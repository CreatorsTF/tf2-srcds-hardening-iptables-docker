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
LOGPREFIX="[SRCDS IPT]"
# log up to every 30 seconds at max so we dont hog io
LOGLIMIT="-m limit --limit 2/min"
# port range to protect
PORTMIN=27000
PORTMAX=28015


## =================================================================
## INITIALISATION
## -----------------------------------------------------------------

## Docker detection
## --
usedocker=false

# a guess
if ps aux | grep docker-proxy | grep 27015 &> /dev/null; then
    usedocker=true
fi



## Ports & chain setup
## --
ports=""
chain=""
if [[ ${usedocker} == true ]]; then
    ports="-m conntrack --ctdir ORIGINAL --ctorigdstport ${PORTMIN}:${PORTMAX} "
    chain="DOCKER-USER"
    echo "Detected docker."
else
    ports="-m multiport --dports ${PORTMIN}:${PORTMAX} "
    chain="INPUT"
fi

echo ""


## Delete any existing rules we already wrote
## --
rm /tmp/ipt
rm /tmp/ipt_scrub

## Save & restore
## --
iptables-save > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore < /tmp/ipt_scrub

## =================================================================
## RULES
##
## 1. Trusted hosts
## 2. UDP game packets
## 3. A2S flooding
## 4. UDP spam (300 req/s limit)
## 5. SRC Conformity (Strict Length Checking)
##
## -----------------------------------------------------------------

## 5. SRC Conformity (Strict Length Checking)
## --

# PACKETS TOO SMALL: There should never be any UDP packets below 32 bytes.

## drop em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} -m length --length 0:32 \
-j DROP
## log em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} -m length --length 0:32 \
-j LOG ${LOGLIMIT} --log-ip-options --log-prefix "${LOGPREFIX} < XtraSmallJunk > "

# PACKET TOO BIG: There should never be any packets above the following length.

# (net_maxroutable) + (net_splitrate) * (net_maxfragments)
#  1260             +  1              *  1260             
#  = 2521 bytes

## drop em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} -m length --length 2521:65535 \
-j DROP
## log em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} -m length --length 2521:65535 \
-j LOG ${LOGLIMIT} --log-ip-options --log-prefix "${LOGPREFIX} < XtraLargeJunk > "


## 4. UDP spam (300 req/s limit)
## --
## (desc.) We should never be seeing 300 packets a second from the same ip lol

RULE_FILTER="-m hashlimit --hashlimit-name speedlimit --hashlimit-mode srcip --hashlimit-above 300/sec"

## drop em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
	-j DROP
## log em ##
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
        -j LOG ${LOGLIMIT} --log-ip-options --log-prefix "${LOGPREFIX} R: >300 req/s:"

## 3. A2S flooding
## --
## Thank you arie for the recommendation. 
##
## (desc.) Used to check packetstate = NEW,
##   but there's no reason to as we already allow legit packets with our 
##   later ALLOW ESTABLISHED rule.

# Johnny: Docker-enabled uses `dstip` cause all non-allocated ports are 
#           routed to one host. This makes it easier to filter and reduces
#           our hashes.
RULE_FILTER="-m hashlimit --hashlimit-name a2sflood --hashlimit-mode srcip,dstport --hashlimit-above 2/sec --hashlimit-burst 3"
if [[ ${usedocker} == true ]]; then
    RULE_FILTER="-m hashlimit --hashlimit-name a2sflood --hashlimit-mode srcip,dstip --hashlimit-above 2/sec --hashlimit-burst 3"
fi

# drop em #
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
	-j DROP

# log em #
iptables -I ${chain} 1 -p udp ${COMMENT} ${ports} ${RULE_FILTER} \
        -j LOG ${LOGLIMIT} --log-ip-options --log-prefix "${LOGPREFIX} A2S FLOOD:"

## 2. UDP game packets
## --
## Allow "Established" packets so that we dont stomp on legit gamers
## This rule goes last so it gets inserted first

# love em #
iptables -I ${chain} 1 -p udp ${COMMENT} -m state --state ESTABLISH \
        -j ACCEPT


## 1. Trusted hosts
## --
## Uses /etc/hosts.trusted to use a list of hosts to allow unrestricted communication.

if [[ -f /etc/hosts.trusted ]]; then
    for host in $(cat /etc/hosts.trusted); do
    	iptables -I ${chain} 1 -p udp ${COMMENT} -s "$host" -j ACCEPT
    done
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
