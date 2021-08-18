#!/bin/bash
# THIS DOESN'T WORK DON'T USE IT


# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
# with influence from https://forums.alliedmods.net/showthread.php?t=151551
# by sappho.io

## =================================================================
## CONFIGURATION
## -----------------------------------------------------------------
# this isnt just for fun, this lets me easily grep for the rules and delete and recreate them
COMMENT="-m comment --comment="sappho.io""
LOGPREFIX="[srcds-ipt]"
# log up to every 30 seconds at max so we dont hog io
LOGLIMIT="-m limit --limit 2/min"

LOGLIMIT_FAST="-m limit --limit 10/min"

# port range to protect
PORTMIN=27000
PORTMAX=28015


## =================================================================
## INITIALISATION
## -----------------------------------------------------------------

## Docker detection
## --
usedocker=false

if dpkg -l docker\* &> /dev/null; then
    usedocker=true
fi


defaultin=$(route | grep '^default' | grep -o '[^ ]*$')

ipt=""

ports="-m multiport --dports ${PORTMIN}:${PORTMAX} "

if [[ ${usedocker} == true ]]; then
    echo "Detected docker."
    ipt="iptables -I DOCKER-USER 1"
else
    echo "No docker."
    ipt="iptables -I INPUT 1"
fi

echo ""
#recent_real="/proc/net/xt_recent"
#recent_tmp="/tmp/xt_recent"

## Delete any existing rules we already wrote
## --
rm /tmp/ipt
rm /tmp/ipt_scrub

# copy our recent ip addrs
#mkdir ${recent_tmp} -p
#
#for file in ${recent_real}/*;
#    do
#        basefile=$(basename ${file})
#        cp ${file} ${recent_tmp}/${basefile}
#        echo "cp ${file} ${recent_tmp}/${basefile}"
#    done
#
## Save & restore
## --
iptables-save -c > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore -c < /tmp/ipt_scrub

## =================================================================
## RULES
## 0. WHITELIST players that connect and UNWHITELIST them when they leave
## 1. ALLOW Trusted hosts
## 2. ALLOW Legit UDP game packets [USES CONNTRACK]
## 3. SRC Conformity (Strict Length Checking = too big)
## 4. SRC Conformity (Strict Length Checking = too small)
## 5. UDP spam (100 req/s limit)
## 6. A2S flooding
##
## -----------------------------------------------------------------

#iptables -I PREROUTING 1 -t mangle -p udp ${ports} -i ${defaultin} ${COMMENT} \
#    -m recent --name signedon ! --rcheck --seconds 25200 --reap --hitcount 1 \
#    -j DROP

#iptables -I PREROUTING 1 -t mangle -p udp ${ports} -i ${defaultin} ${COMMENT} \
#    -m recent --name signedon ! --rcheck --seconds 25200 --reap --hitcount 1 -j LOG \
#    ${LOGLIMIT_FAST} --log-ip-options --log-level error \
#    --log-prefix "PACKET NOT WHITELISTED: "

#iptables -I PREROUTING 1 -t mangle -p udp ${ports} -i ${defaultin} ${COMMENT} \
#    -m recent --name signedon --rcheck --hitcount 10 -j LOG \
#    ${LOGLIMIT_FAST} --log-ip-options --log-level error \
#    --log-prefix "10 SIGNONS: "

# this hex string is sent in every "i am connecting to the server" packet that comes from clients
# probably
# -steph

#iptables -I PREROUTING 1 -t raw -p udp ${ports} -i ${defaultin} ${COMMENT} \
#    -m string --algo bm --hex-string '|9b5bd9181d88581e48dd5c999c0bc0|' \
#    -m recent --name signedon --remove \
#    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error \
#    --log-prefix "SIGNOFF: "
#    -m length --length 45

# similarly, this string is sent in every "goodbye see ya later" packet that comes from clients
# probably.
# -steph

#iptables -I PREROUTING 1 -t raw -p udp ${ports} -i ${defaultin} ${COMMENT} \
#    -m string --algo bm --hex-string '|3030303030303030303000|' \
#    -m recent --name signedon --set \
#    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error \
#    --log-prefix "SIGNON: "
    #-m length --length 28


## 6: A2S flooding
## We used to check packetstate = NEW,
## but there's no reason to as we already allow legit packets with our
## later ALLOW ESTABLISHED rule.
RULE_FILTER="-m hashlimit --hashlimit-name a2s --hashlimit-mode srcip --hashlimit-above 1/sec --hashlimit-burst 3"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -m string --algo bm --hex-string '|ffffffff54|' \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -m string --algo bm --hex-string '|ffffffff54|' \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} a2s flood: "

## 5: UDP spam (50 req/s limit)
## We should never be seeing 50 packets a second from the same ip not already established or related
RULE_FILTER="-m hashlimit --hashlimit-name speedlimit --hashlimit-mode srcip --hashlimit-above 10/sec"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} >10 req/s: "


## 4: PACKET TOO smol: There should never be any packets packets below 32 bytes.
RULE_FILTER="-m length --length 0:32"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} len < 32: "

## 3: PACKET TOO BIG: There should never be any packets above the following length.
## (net_maxroutable) + (net_splitrate) * (net_maxfragments)
##  1260             +  1              *  1260
##  = 2521 bytes
RULE_FILTER="-m length --length 2521:65535"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} len > 2521: "


## 2: UDP game packets
## Allow "Established" packets so that we dont stomp on legit gamers
## This rule goes last so it gets inserted first
RULE_FILTER="-m state --state ESTABLISHED,RELATED"

${ipt} -p udp ${COMMENT} ${RULE_FILTER} \
    -j ACCEPT

# this doesn't fucking work
# -steph
#${ipt} -p udp ${COMMENT} -i ${defaultin} \
#    -m recent --name signedon --rcheck --seconds 25200 --reap --hitcount 1 \
#    -j ACCEPT

#${ipt} -p udp ${COMMENT} -i ${defaultin} \
#    -m recent --name signedon --rcheck --seconds 25200 --reap --hitcount 1 \
#    -j LOG

## 1: Reject invalid packets
##
##
RULE_FILTER="-m state --state INVALID"

${ipt} -p udp ${COMMENT} ${RULE_FILTER} \
    -j REJECT

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} INVALID PACKET: "

## 0: Trusted hosts
## Uses /etc/hosts.trusted to use a list of hosts to allow unrestricted communication.
if [[ -f /etc/hosts.trusted ]]; then
    for host in $(cat /etc/hosts.trusted); do
        ${ipt} -p udp ${COMMENT} -s "$host" -j ACCEPT
    done
    echo "allowing trusted hosts"
fi

## =================================================================
## CLEAN-UP
## -----------------------------------------------------------------

## Persist them - needs iptables-persistant!
## --
iptables-save > /etc/iptables/rules.v4


## Dump our generated rules
## --
cat /etc/iptables/rules.v4 | grep sapph

#echo ""
#echo "Re-populating xt_recent ip lists..."
#echo ""
#for file in ${recent_tmp}/*;
#    do
#        basefile=$(basename ${file})
#        cat $file | while read line; do
#            echo $line | cut -d " " -f 1 | sed 's/src=/+/' > ${recent_real}/${basefile}
#            echo $line | cut -d " " -f 1 | sed 's/src=/+/'
#        done
#
#    done


## Final feedback
## --
echo ""
if [[ ${usedocker} == true ]]; then
    echo "Hardened SRCDS (in docker)."
else
    echo "Hardened SRCDS."
fi
