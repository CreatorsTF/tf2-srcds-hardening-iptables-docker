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
# i know this commenting is weird, bash sucks ass
COMMENT="-m comment --comment="srcds-hardening-by-sappho.io""
LOGPREFIX="[srcds-ipt]"
# log up to every 60 seconds at max so we dont hog io
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
# iptables command setup
ipt=""


if (netstat -aupl | grep docker-proxy) &> /dev/null; then
    usedocker=true
    echo "Detected docker."
    ipt="iptables -I DOCKER-USER 1"
else
    echo "No docker."
    ipt="iptables -I INPUT 1"
fi

# default interface detection
defaultin=$(route | grep '^default' | grep -o '[^ ]*$')

# ports setup
ports="-m multiport --dports ${PORTMIN}:${PORTMAX} "

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
ipset create  signed_on   hash:ip,port timeout 240 || true


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

# 5: Log client signons - string is at the end of the packet
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|3030303030303030303000|'                               \
    -m length --length 48 --from 26 --to 48                                  \
    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
    --log-prefix "${LOGPREFIX} signon: "

# 4: Grab client signon packets to whitelist
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|3030303030303030303000|'                               \
    -m length --length 48 --from 26 --to 48                                  \
    -j SET --add-set signed_on src,dst --timeout 120

# 3: Log client signoffs - string is at the end of the packet
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
    -m length --length 65 --from 35 --to 65                                 \
    -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
    --log-prefix "${LOGPREFIX} signoff: "

# 2: Grab client signoff packets to unwhitelist clients
# They will timeout after ~65 seconds if no data is received anyway.
${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
    ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
    -m length --length 65 --from 35 --to 65                                 \
    -j SET --del-set signed_on src,dst



# 1: ALWAYS allow trusted hosts
# Uses /etc/hosts.trusted to use a list of hosts to allow unrestricted communication.
    if [[ -f /etc/hosts.trusted ]]; then
        for host in $(cat /etc/hosts.trusted); do

${ipt_pre_raw} -p udp ${COMMENT} -s "$host"                                 \
    -j SET --add-set permatrusted src --exist

        done
        echo "allowing trusted hosts"
    fi


# 0: Disable conntracking on our srcds ports

if [[ ${usedocker} == true ]]; then
    # if we're using docker we need to disable conntrack wholesale
    # docker needs the whole thing gone, else it will get very confused and not route things properly
    modprobe nf_conntrack nf_conntrack_helper=0
    # make it persistent across boots
    echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no_conntrack_helper.conf
else
    # otherwise we can just do the specific ports
    ${ipt_pre_raw} -p udp ${ports} ${COMMENT}                               \
        -j NOTRACK
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
# Ignore signed on and trusted users
NOMATCH_TRUSTED=" -m set ! --match-set permatrusted  src    "
NOMATCH_SIGNEDON="-m set ! --match-set signed_on     src,dst"

# 4: UDP Spam
# Should never see so much traffic from the same IP to the same port
${ipt} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}            \
    ${NOMATCH_TRUSTED} ${NOMATCH_SIGNEDON}                                  \
    -j DROP

# 3: Log udp spam
${ipt} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}            \
    ${NOMATCH_TRUSTED} ${NOMATCH_SIGNEDON}                                  \
    -j LOG ${LOGLIMIT} --log-ip-options                                     \
    --log-prefix "${LOGPREFIX} udpspam: "


# 2: Allow signed on gamers to play - only whitelists ip to destip / dport :D
${ipt} -p udp -i ${defaultin} ${COMMENT}                                    \
    -m set --match-set signed_on src,dst                                    \
    -j ACCEPT

# 1: Reset timeout whenever we get some data from this client
${ipt} -p udp ${COMMENT}                                                    \
    -m set --match-set signed_on src,dst                                    \
    -j SET --add-set   signed_on src,dst --timeout 65 --exist


# 0: Debug logging
#${ipt} -p udp ${COMMENT}                                                    \
#    -m set --match-set signed_on src,dst                                    \
#    -j LOG ${LOGLIMIT_FAST} --log-ip-options                                \
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
