#!/bin/sh
# fetch_threat_intel.sh - download public IP-reputation feeds and normalise them
# into /root/threat_intel.txt, which the dualwield agent syncs into the kernel
# blocklist map. Run from cron on the router, e.g. hourly:
#
#   echo '0 * * * * /root/fetch_threat_intel.sh' >> /etc/crontabs/root
#   /etc/init.d/cron restart
#
# Keeping the fetch out of the agent means the agent has no network/TLS dependency
# and never blocks at boot waiting for a feed. The agent re-reads the file on its
# own timer (-blocklist-refresh, default 10m).
#
# Requires: curl (opkg install curl ca-bundle). grep -oE / sort are in busybox.

OUT=/root/threat_intel.txt
TMP="${OUT}.tmp.$$"

# Well-known free feeds (no auth). Add/remove as you like.
FEEDS="
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://cinsscore.com/list/ci-badguys.txt
https://www.spamhaus.org/drop/drop.txt
"

# Never blocklist private / loopback / unspecified ranges even if a feed lists
# them by mistake (the in-kernel allowlist also overrides, this is belt-and-suspenders).
PRIVATE_RE='^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)'

{
    echo "# generated $(date -u +%FT%TZ) by fetch_threat_intel.sh"
    for url in $FEEDS; do
        if ! curl -fsSL --max-time 30 "$url" 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?'
        then
            echo "  feed failed or empty: $url" >&2
        fi
    done
} > "$TMP"

# Drop the private/bogon ranges, dedup, keep the header comment.
{
    grep -E '^#' "$TMP"
    grep -vE '^#' "$TMP" | grep -vE "$PRIVATE_RE" | sort -u
} > "$OUT"

rm -f "$TMP"
echo "wrote $(grep -cvE '^#' "$OUT") entries to $OUT"
