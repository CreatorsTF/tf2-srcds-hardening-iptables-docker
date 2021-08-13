#!/bin/bash
# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
# with influence from https://forums.alliedmods.net/showthread.php?t=151551
# by sappho.io


usedocker=false


# a guess
if ps aux | grep docker-proxy | grep 27015 &> /dev/null; then
    usedocker=true
fi


# this isnt just for fun, this lets me easily grep for the rules and delete and recreate them
comment="-m comment --comment="sappho.io""
logprefix="[srcds ipt]"
# log up to every 30 seconds at max so we dont hog io
loglimit="-m limit --limit 2/min"
portmin=27000
portmax=28015
ports=""
chain=""


if [[ ${usedocker} == true ]]; then
    ports="-m conntrack --ctdir ORIGINAL --ctorigdstport ${portmin}:${portmax} "
    chain="DOCKER-USER"
    echo "Detected docker."
else
    ports="-m multiport --dports ${portmin}:${portmax} "
    chain="INPUT"
fi


echo ""


## Delete any existing rules we already wrote
##
##
rm /tmp/ipt
rm /tmp/ipt_scrub

iptables-save > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore < /tmp/ipt_scrub

## PACKETS THAT ARE TOO SMALL
##
## There should never be any UDP packets below 32 bytes.
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 0:32 -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 0:32 -j LOG \
${loglimit} --log-ip-options --log-prefix "${logprefix} < XtraSmallJunk > "

## PACKETS THAT ARE TOO BIG
##
## There should never be any packets above (net_maxroutable) + (net_splitrate) * (net_maxfragments)
##                                          1260             +  1              *  1260
## = 2521
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 2521:65535 -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 2521:65535 -j LOG \
${loglimit} --log-ip-options --log-prefix "${logprefix} < XtraLargeJunk > "


## Prevent UDP spam
##
## We should never be seeing 300 packets a second from the same ip lol
##
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name 500flood --hashlimit-mode srcip --hashlimit-above 300/sec -j DROP
# log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name 500flood --hashlimit-mode srcip --hashlimit-above 300/sec -j LOG \
${loglimit} --log-ip-options --log-prefix "${logprefix} < 500 pps > "

## Prevent flooding, typically caused by A2S spam
## Used to check packetstate = NEW, but there's no reason to as we already allow legit packets with our later ALLOW ESTABLISHED rule
## Thank you arie for the recommendation
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name a2sflood --hashlimit-mode srcip --hashlimit-above 1/s --hashlimit-burst 3 -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name a2sflood --hashlimit-mode srcip --hashlimit-above 1/s --hashlimit-burst 3 -j LOG \
${loglimit} --log-ip-options --log-prefix "${logprefix} < A2s Spam > "

## Allow "Established" packets so that we dont stomp on legit gamers
## This rule goes last so it gets inserted first
##
iptables -I ${chain} 1 -p udp ${comment} -m state --state ESTABLISH -j ACCEPT


## Persist them - needs iptables-persistant!
iptables-save > /etc/iptables/rules.v4


## Dump our generated rules
cat /etc/iptables/rules.v4 | grep sapph


echo ""
if [[ ${usedocker} == true ]]; then
    echo "Hardened SRCDS (in docker)."
else
    echo "Hardened SRCDS."
fi
