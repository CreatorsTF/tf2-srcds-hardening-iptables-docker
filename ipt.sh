#!/bin/bash
# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# keep in mind this will only work if your srcds servers are on docker containers
# FUCK YOU VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
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
--log-ip-options --log-prefix "${logprefix} XtraSmallJunk> "

## PACKETS THAT ARE TOO BIG
##
## There should never be any packets above (net_maxroutable) + (net_splitrate) * (net_maxfragments)
##                                          1260             +  1              *  1260
## = 2521
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 2521:65535 -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} -m length --length 2521:65535 -j LOG \
--log-ip-options --log-prefix "${logprefix} XtraLargeJunk> "


## Prevent UDP spam
##
## We should never be seeing 1k packets a second from the same ip lol
##
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name 1kflood --hashlimit-mode srcip,dstport --hashlimit-above 1000/sec -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m hashlimit --hashlimit-name 1kflood --hashlimit-mode srcip,dstport --hashlimit-above 1000/sec -j LOG \
--log-ip-options --log-prefix "${logprefix} 1k pps> "


## Prevent "new" state spam aka a2s spam
##
## drop em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m state --state NEW \
-m hashlimit --hashlimit-name newflood --hashlimit-mode srcip --hashlimit-above 1/s --hashlimit-burst 2 -j DROP
## log em
iptables -I ${chain} 1 -p udp ${comment} ${ports} \
-m state --state NEW \
-m hashlimit --hashlimit-name newflood --hashlimit-mode srcip --hashlimit-above 1/s --hashlimit-burst 2 -j LOG \
--log-ip-options --log-prefix "${logprefix} A2S Spam> "


## Allow "Established" packets so that we dont stomp on legit gamers
##
##
iptables -I ${chain} 1 -p udp ${comment} -m state --state ESTABLISH -j ACCEPT


## Persist them - needs iptables-persistant
iptables-save > /etc/iptables/rules.v4

cat /etc/iptables/rules.v4 | grep sapph

if [[ ${usedocker} == true ]]; then
    echo "Hardened SRCDS (in docker)."
else
    echo "Hardened SRCDS."
fi
