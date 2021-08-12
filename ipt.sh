#!/bin/bash
# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# keep in mind this will only work if your srcds servers are on docker containers
# FUCK YOU VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
# with influence from https://forums.alliedmods.net/showthread.php?t=151551
# by sappho.io

comment="-m comment --comment="sappho.io""
logprefix="[srcds ipt]"
portmin=27000
portmax=30000
conntrack="-m conntrack --ctdir ORIGINAL --ctorigdstport ${portmin}:${portmax} "
dockeruser="DOCKER-USER"

## Delete any existing rules we already wrote
##
##
rm /tmp/ipt
rm /tmp/ipt_scrub

iptables-save > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore < /tmp/ipt_scrub


## Persist them - needs iptables-persistant
iptables-save > /etc/iptables/rules.v4

## PACKETS THAT ARE TOO SMALL
##
## There should never be any UDP packets below 32 bytes.
## drop em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} -m length --length 0:32 -j DROP
## log em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} -m length --length 0:32 -j LOG \
--log-ip-options --log-prefix "${logprefix} XtraSmallJunk "

## PACKETS THAT ARE TOO BIG
##
## There should never be any packets above (net_maxroutable) + (net_splitrate) * (net_maxfragments)
##                                          1260             +  1              *  1260
## = 2521
## drop em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} -m length --length 2521:65535 -j DROP
## log em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} -m length --length 2521:65535 -j LOG \
--log-ip-options --log-prefix "${logprefix} XtraLargeJunk "


## Prevent UDP spam
##
## We should never be seeing 1k packets a second from the same ip lol
##
## drop em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} \
-m hashlimit --hashlimit-name 1kflood --hashlimit-mode srcip,dstport --hashlimit-above 1000/sec -j DROP
## log em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} \
-m hashlimit --hashlimit-name 1kflood --hashlimit-mode srcip,dstport --hashlimit-above 1000/sec -j LOG \
--log-ip-options --log-prefix "${logprefix} 1k pps "


## Prevent "new" state spam aka a2s spam
##
## drop em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} \
-m state --state NEW \
-m hashlimit --hashlimit-name newflood --hashlimit-mode srcip --hashlimit-above 3/s --hashlimit-burst 5 -j DROP
## log em
iptables -I ${dockeruser} 1 -p udp ${comment} ${conntrack} \
-m state --state NEW \
-m hashlimit --hashlimit-name newflood --hashlimit-mode srcip --hashlimit-above 2/s --hashlimit-burst 4 -j LOG \
--log-ip-options --log-prefix "${logprefix} NewStateSpam "


## Allow "Established" packets so that we dont stomp on legit gamers
##
##
iptables -I ${dockeruser} 1 -p udp ${comment} -m state --state ESTABLISH -j ACCEPT

echo "Hardened SRCDS".
