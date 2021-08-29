#!/bin/bash
# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
# with influence from https://forums.alliedmods.net/showthread.php?t=151551
# by sappho.io
# REQUIRES: a recent-ish version of iptables, iptables-persistent, ipset


#########################################################################
# CONFIG
#########################################################################


# this isnt just for fun, this lets me easily grep for the rules and delete and recreate them
COMMENT="-m comment --comment="sappho.io""
LOGPREFIX="[srcds-ipt]"
# log up to every 30 seconds at max so we dont hog io
LOGLIMIT="-m limit --limit 1/min"

LOGLIMIT_FAST="-m limit --limit 100/min"

# port range to protect
PORTMIN=27000
PORTMAX=29000


#########################################################################
# INIT
#########################################################################


# Docker detection
usedocker=false

if (pidof dockerd && netstat -aupl | grep docker-proxy) &> /dev/null; then
    usedocker=true
fi

# default interface detection
defaultin=$(route | grep '^default' | grep -o '[^ ]*$')

# ports setup
ports="-m multiport --dports ${PORTMIN}:${PORTMAX} "

# iptables command setup
ipt=""

if [[ ${usedocker} == true ]]; then
    echo "Detected docker."
    ipt="iptables -I DOCKER-USER 1"
else
    echo "No docker."
    ipt="iptables -I INPUT 1"
fi

# feedback
echo ""

# for raw prerouting
ipt_pre_raw="iptables -I PREROUTING 1 -t raw "

# for raw mangling
ipt_pre_mangle="iptables -I PREROUTING 1 -t mangle "

# Delete any existing rules we already wrote
rm /tmp/ipt
rm /tmp/ipt_scrub

# Save & restore - requires iptables-persistent!
iptables-save -c > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore -c < /tmp/ipt_scrub


# create our ipset rules - requires ipset!
ipset create permatrusted hash:ip    timeout 10800 || true
ipset create signedon     hash:ip    timeout 10800 || true


#########################################################################
# PREROUTING RAW
#########################################################################


# 7: PACKET TOO SMOL
# There should never be any packets packets below 32 bytes
RULE_FILTER="-m length --length 0:32"

${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
    -j DROP

${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
    -j LOG ${LOGLIMIT} --log-ip-options                                     \
    --log-prefix "${LOGPREFIX} len < 32: "


# 6: PACKET TOO BIG
# There should never be any packets above this length:
# (net_maxroutable) + (net_splitrate  * net_maxfragments)
#  1260             + (1              *  1260)
#  = 2520 (+1) bytes
RULE_FILTER="-m length --length 2521:65535"

${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
    -j DROP

${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
    -j LOG ${LOGLIMIT} --log-ip-options                                     \
    --log-prefix "${LOGPREFIX} len > 2521: "

RULE_FILTER="-m string --algo bm --hex-string"

# 5: Log client signons
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|3030303030303030303000|'                               \
    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
    --log-prefix "${LOGPREFIX} signon: "

# 4: Grab client signon packets to whitelist
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|3030303030303030303000|'                               \
    -j SET --add-set signedon src

# 3: Log client signoffs
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
    --log-prefix "${LOGPREFIX} signoff: "

# 2: Grab client signoff packets to unwhitelist clients
# They time out after 3 hrs anyway regardless so
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
    -j SET --del-set signedon src


# 1: ALWAYS allow trusted hosts
# Uses /etc/hosts.trusted to use a list of hosts to allow unrestricted communication.
    if [[ -f /etc/hosts.trusted ]]; then
        for host in $(cat /etc/hosts.trusted); do

${ipt_pre_raw} -p udp ${COMMENT} -s "$host"                                 \
    -j SET --add-set permatrusted src --exist

        done
        echo "allowing trusted hosts"
    fi


#########################################################################
# PREROUTING MANGLE
#########################################################################


# 1: Drop invalid packets
RULE_FILTER="-m state --state INVALID"

${ipt_pre_mangle} -p all ${COMMENT} ${RULE_FILTER}                          \
    -j DROP

${ipt_pre_mangle} -p all ${COMMENT} ${RULE_FILTER}                          \
    -j LOG ${LOGLIMIT} --log-ip-options                                     \
    --log-prefix "${LOGPREFIX} INVALID PACKET: "


#########################################################################
# INPUT / DOCKER-USER
#########################################################################


RULE_FILTER="-m hashlimit --hashlimit-name speedlimit --hashlimit-mode srcip,dstport --hashlimit-above 2/sec --hashlimit-burst 4"

# 3: UDP Spam
# Should never see so much traffic from the same IP to the same port
# ignore signed on and trusted users
${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER}                            \
    -m set --match-set signedon     src --return-nomatch                    \
    -m set --match-set permatrusted src --return-nomatch                    \
    -j DROP

# 2: Log udp spam - ignore signed on and trusted users
${ipt} -p udp ${COMMENT} ${ports} ${RULE_FILTER}                            \
    -m set --match-set signedon     src --return-nomatch                    \
    -m set --match-set permatrusted src --return-nomatch                    \
    -j LOG ${LOGLIMIT} --log-ip-options                                     \
    --log-prefix "${LOGPREFIX} udpspam: "


# 1: Allow signed on gamers to play
${ipt} -p udp ${COMMENT}                                                    \
    -m set --match-set signedon src                                         \
    -j ACCEPT

# 0: Debug logging
#${ipt} -p udp ${COMMENT}                                                   \
#    -m set --match-set signedon src                                        \
#    -j LOG ${LOGLIMIT_FAST} --log-ip-options                               \
#    --log-prefix "${LOGPREFIX} whitelist: "


#########################################################################
# CLEANUP
#########################################################################


# Persist these - needs iptables-persistant!
iptables-save > /etc/iptables/rules.v4


# Dump our generated rules
cat /etc/iptables/rules.v4 | grep sapph

# Final feedback
echo ""
if [[ ${usedocker} == true ]]; then
    echo "Hardened SRCDS (in docker)."
else
    echo "Hardened SRCDS."
fi
