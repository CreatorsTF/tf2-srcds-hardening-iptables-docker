#!/bin/bash
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

## Delete any existing rules we already wrote
## --
rm /tmp/ipt
rm /tmp/ipt_scrub

## Save & restore
## --
iptables-save -c > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore -c < /tmp/ipt_scrub

## =================================================================
## RULES (in order)
## 1. ALLOW - Trusted hosts
## 2. DROP  - "INVALID" UDP packets
## 3. ALLOW - "ESTABLISHED, RELATED" legit UDP game packets [USES CONNTRACK]
## 4. DROP  - SRC Conformity (Strict Length Checking = too big)
## 5. DROP  - SRC Conformity (Strict Length Checking = too small)
## 6. DROP  - UDP spam (>25 req/s)
## 7. DROP  - A2S flooding (>1/s burst 3)
##
## -----------------------------------------------------------------

## 7: A2S flooding
## We used to check packetstate = NEW,
## but there's no reason to as we already allow legit packets with our
## later ALLOW ESTABLISHED rule.
RULE_FILTER="-m hashlimit --hashlimit-name a2s --hashlimit-mode srcip,dstport --hashlimit-above 1/sec --hashlimit-burst 3"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -m string --algo bm --hex-string '|ffffffff54|' \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -m string --algo bm --hex-string '|ffffffff54|' \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} a2s flood: "

## 6: UDP spam (25 req/s limit)
## We should never be seeing 25 packets a second from the same ip not already established or related
RULE_FILTER="-m hashlimit --hashlimit-name speedlimit --hashlimit-mode srcip --hashlimit-above 25/sec"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} >25 req/s: "


## 5: PACKET TOO smol: There should never be any packets packets below 32 bytes.
RULE_FILTER="-m length --length 0:32"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} len < 32: "

## 4: PACKET TOO BIG: There should never be any packets above the following length.
## (net_maxroutable) + (net_splitrate) * (net_maxfragments)
##  1260             +  1              *  1260
##  = 2521 bytes
RULE_FILTER="-m length --length 2521:65535"

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j DROP

${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} len > 2521: "


## 3: UDP game packets
## Allow "Established" packets so that we dont stomp on legit gamers
## This rule goes last so it gets inserted first
RULE_FILTER="-m state --state ESTABLISHED,RELATED"

${ipt} -p udp ${COMMENT} ${RULE_FILTER} \
    -j ACCEPT

## 2: Reject invalid packets
##
##
RULE_FILTER="-m state --state INVALID"

iptables -I PREROUTING 1 -t mangle -p all ${COMMENT} ${RULE_FILTER} \
    -j DROP

iptables -I PREROUTING 1 -t mangle -p all ${COMMENT} ${RULE_FILTER} \
    -j LOG ${LOGLIMIT} --log-ip-options \
    --log-prefix "${LOGPREFIX} INVALID PACKET: "

## 1: Trusted hosts
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

## Final feedback
## --
echo ""
if [[ ${usedocker} == true ]]; then
    echo "Hardened SRCDS (in docker)."
else
    echo "Hardened SRCDS."
fi
