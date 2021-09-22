#!/bin/bash
# sourceds hardening with iptables and docker
# this *should* hopefully prevent most petty/smallish a2s attacks
# VALVE I *SHOULD NOT* HAVE HAD TO WRITE THIS
# with influence from https://forums.alliedmods.net/showthread.php?t=151551
# by sappho.io
# REQUIRES: a recent-ish version of iptables, iptables-persistent, ipset


# colors!
red=$(      tput setaf 1)
green=$(    tput setaf 2)
yellow=$(   tput setaf 3)
blue=$(     tput setaf 4)
magenta=$(  tput setaf 5)
cyan=$(     tput setaf 6)
white=$(    tput setaf 7)
reset=$(    tput sgr0   )

################################################################################
# CONFIG
################################################################################

# for crontabbing
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# this isnt just for fun, this lets us easily grep for the rules and delete and recreate them

COMMENT="-m comment --comment=srcds-hardening-by-sappho.io"
LOGPREFIX="<|srcds-ipt|>"
# log up to every 30 seconds at max so we dont hog io
LOGLIMIT="-m limit --limit 2/min"

LOGLIMIT_FAST="-m limit --limit 250/min"

# port range to protect
PORTMIN=27000
PORTMAX=29000


################################################################################
# INIT
################################################################################


# Docker detection
usedocker=false

if (netstat -aupl | grep docker-proxy) &> /dev/null; then
    usedocker=true
    echo "Detected docker."
else
    echo "No docker."
fi

# feedback for script
echo ""

# default interface detection
defaultin=$(route | grep '^default' | grep -o '[^ ]*$')

# ports setup
ports="-m multiport --dports ${PORTMIN}:${PORTMAX} "

# for raw prerouting
ipt_pre_raw="iptables -I PREROUTING 1 -t raw "

# for raw mangling
ipt_pre_mangle="iptables -I PREROUTING 1 -t mangle "

# blank any rules we already wrote
> /tmp/ipt
> /tmp/ipt_scrub

# Save & restore - requires iptables-persistent!
iptables-save -c > /tmp/ipt
grep -v -h "sappho.io" /tmp/ipt > /tmp/ipt_scrub
iptables-restore -c < /tmp/ipt_scrub

# for human readable output, printed at the end

rawhuman="/tmp/ipt_raw_human"
manglehuman="/tmp/ipt_mangle_human"

# blank any previous output
> ${rawhuman}
> ${manglehuman}

# create our ipset rules - requires ipset!
ipset create permatrusted hash:ip      timeout 0   -! || true
ipset create  signed_on   hash:ip,port timeout 240 -! || true

################################################################################
# FUNCS
################################################################################

small_len()
{
    # PACKET TOO SMOL
    # There should never be any packets packets below 32 bytes
    RULE_FILTER="-m length --length 0:32"

    echo "DROP small lens" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        -j DROP

    echo "LOG small lens" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        -j LOG ${LOGLIMIT} --log-ip-options                                     \
        --log-prefix "${LOGPREFIX} len < 32: "
}


big_len()
{
    # PACKET TOO BIG
    # There should never be any packets above this length:
    # (net_maxroutable) + (net_splitrate  * net_maxfragments)
    #  1260             + (1              *  1260)
    #  = 2520 (+1) bytes
    RULE_FILTER="-m length --length 2521:65535"

    echo "DROP big lens" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        -j DROP

    echo "LOG big lens" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        -j LOG ${LOGLIMIT} --log-ip-options                                     \
        --log-prefix "${LOGPREFIX} len > 2521: "
}


udpspam()
{
    # We should never see so much traffic from the same IP to the same port. If we are it's probably naughty.
    RULE_FILTER="-m hashlimit --hashlimit-name speedlimit --hashlimit-mode srcip,dstport --hashlimit-above 8/sec --hashlimit-burst 16"

    # Ignore signed on and trusted users for these rules
    NOMATCH_TRUSTED=" -m set ! --match-set permatrusted  src    "
    NOMATCH_SIGNEDON="-m set ! --match-set signed_on     src,dst"

    echo "DROP UDP spam" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        ${NOMATCH_TRUSTED} ${NOMATCH_SIGNEDON}                                  \
        -j DROP

    echo "LOG UDP spam" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports} ${RULE_FILTER}    \
        ${NOMATCH_TRUSTED} ${NOMATCH_SIGNEDON}                                  \
        -j LOG ${LOGLIMIT} --log-ip-options                                     \
        --log-prefix "${LOGPREFIX} udp spam: "
}


whitelist_signedon()
{
    # Allow signed on gamers to play - only whitelists ip to destip / dport !
    echo "ACCEPT from signed on client from srcip to dpt" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT}                            \
        -m set --match-set signed_on src,dst                                    \
        -j ACCEPT
}


reset_timeout_recv_data()
{
    # Reset timeout whenever we get some data from this client
    echo "SET on recieve data from client" >> ${rawhuman}
    ${ipt_pre_raw} -p udp ${COMMENT}                                            \
        -m set --match-set signed_on src,dst                                    \
        -j SET --add-set   signed_on src,dst --timeout 65 --exist
}


set_signedon()
{
    RULE_FILTER="-m string --algo bm --hex-string"

    # Grab client signon packets to add them to our ipset whitelist
    # 3030 string is at the end of the packet
    echo "SET signons" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports}                   \
        ${RULE_FILTER} '|3030303030303030303000|'                               \
        -m length --length 48 --from 26 --to 48                                 \
        -j SET --add-set signed_on src,dst --timeout 120

    echo "LOG signons" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports}                   \
        ${RULE_FILTER} '|3030303030303030303000|'                               \
        -m length --length 48 --from 26 --to 48                                 \
        -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
        --log-prefix "${LOGPREFIX} signon: "
}


set_signedoff()
{
    RULE_FILTER="-m string --algo bm --hex-string"

    # Grab client signoff packets to unwhitelist clients
    # They will timeout after ~65 seconds if no data is received anyway.
    # 9b5b string is at the end of the packet
    echo "SET signoffs" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports}                   \
        ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
        -m length --length 65 --from 35 --to 65                                 \
        -j SET --del-set signed_on src,dst

    echo "LOG signoffs" >> ${rawhuman}
    ${ipt_pre_raw} -p udp -i ${defaultin} ${COMMENT} ${ports}                   \
        ${RULE_FILTER} '|9b5bd9181d88581e48dd5c999c0bc0|'                       \
        -m length --length 65 --from 35 --to 65                                 \
        -j LOG ${LOGLIMIT_FAST} --log-ip-options --log-level error              \
        --log-prefix "${LOGPREFIX} signoff: "
}


debug_whitelisted()
{
    # Debug logging
    echo "debug logging for whitelist" >> ${rawhuman}
    ${ipt_pre_raw} -p udp ${COMMENT}                                            \
        -m set --match-set signed_on src,dst                                    \
        -j LOG ${LOGLIMIT_FAST} --log-ip-options                                \
        --log-prefix "${LOGPREFIX} whitelist: "
}


disable_conntrack()
{
    # Disable conntracking on our srcds ports
    if [[ ${usedocker} == true ]]; then
        # if we're using docker we need to disable conntrack wholesale
        # docker needs the whole thing gone, else it will get very confused and not route things properly
        modprobe nf_conntrack nf_conntrack_helper=0
        # make it persistent across boots
        echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no_conntrack_helper.conf
    else
        # otherwise we can just do the specific ports
        echo "NOTRACK" >> ${rawhuman}
        ${ipt_pre_raw} -p udp ${ports} ${COMMENT}                               \
            -j NOTRACK
    fi
}


drop_invalid()
{
    # Drop invalid packets
    RULE_FILTER="-m state --state INVALID"

    echo "DROP invalid packets" >> ${manglehuman}
    ${ipt_pre_mangle} -p all ${COMMENT} ${RULE_FILTER}                          \
        -j DROP

    echo "LOG dropped invalid packets" >> ${manglehuman}
    ${ipt_pre_mangle} -p all ${COMMENT} ${RULE_FILTER}                          \
        -j LOG ${LOGLIMIT} --log-ip-options                                     \
        --log-prefix "${LOGPREFIX} INVALID PKT: "
}


################################################################################
# PREROUTING RAW - essentially as early as we can get in the netfilter environment
# https://en.wikipedia.org/wiki/Netfilter#/media/File:Netfilter-packet-flow.svg
################################################################################

# THESE ARE IN REVERSE ORDER.
# This is because we insert at the FIRST rule, so we override any other random IPT rules.

udpspam
whitelist_signedon
big_len
small_len
reset_timeout_recv_data
set_signedoff
set_signedon
# debug_whitelisted
disable_conntrack

################################################################################
# PREROUTING MANGLE - comes after raw prerouting
################################################################################

drop_invalid

################################################################################
# TRUSTED HOSTS - Uses /etc/hosts.trusted as a list to whitelist
################################################################################

# flush
ipset flush permatrusted
# readd from trustedhosts
trustedhosts="/etc/hosts.trusted"
if [[ -f "$trustedhosts" ]]; then
    while IFS= read -r line; do
        # ignore comments
        if ! [[ $line =~ "#" ]]; then
            ipset add permatrusted $line
            echo "${green}${line}${reset} added to trusted hosts."
        fi
    done < $trustedhosts
fi
echo ""

################################################################################
# CLEANUP
################################################################################

# Persist these - needs iptables-persistant!
iptables-save > /etc/iptables/rules.v4

# Dump our generated rules
echo "${green}$(cat /etc/iptables/rules.v4 | grep sapph -a -c)${reset} rules added:"

# Human readable!
echo "=== IPTABLES PRE RAW ==="
tac ${rawhuman}
echo "=== IPTABLES PRE MANGLE ==="
tac ${manglehuman}

# Final feedback
echo ""
if [[ ${usedocker} == true ]]; then
    echo "${red}Hardened${reset} SRCDS ${cyan}(in docker!)${reset}."
else
    echo "${red}Hardened${reset} SRCDS."
fi
