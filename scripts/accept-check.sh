#!/bin/bash
# Read-only acceptance evidence for the own connection with the split
# (mac-proof I9–I12). No sudo; changes nothing: it reads routes, the
# system resolvers and the relay log, and asks names the way a browser
# would (which, for names on the list, is exactly what adds their direct
# route). Addresses are masked in the output.
#
#   scripts/accept-check.sh [direct-name ...]
#
# Default direct names suit a list with geoip:cn and geosite:google.
set -uo pipefail
if [ $# -gt 0 ]; then DIRECT=("$@"); else DIRECT=(www.baidu.com www.google.com); fi
TUNNEL=(www.wikipedia.org)
mask() { sed -E 's/([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/\1.x.x/g'; }
ifc() { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }
PASS=0; FAIL=0
check() { if [ "$2" = yes ]; then echo "PASS $1"; PASS=$((PASS + 1)); else echo "FAIL $1"; FAIL=$((FAIL + 1)); fi; }

echo "== session"
check "own connection running" "$(pgrep -f alwaysconnect-vpnc.sh >/dev/null && echo yes || echo no)"
DEF=$(ifc default)
check "default route into the tunnel ($DEF)" "$([[ $DEF == utun* ]] && echo yes || echo no)"
FIRST=$(scutil --dns | awk '/^resolver #1/{p=1} p && /nameserver\[0\]/{print $3; exit}')
check "system asks the split forwarder first ($FIRST)" "$([ "$FIRST" = 127.0.0.1 ] && echo yes || echo no)"
LAST=$(grep -E "udp channel to gateway ready|closed after" ~/Library/Logs/AlwaysConnect/relay.log 2>/dev/null | tail -1)
check "UDP (DTLS) channel up on the current session" "$(echo "$LAST" | grep -q "udp channel to gateway ready" && echo yes || echo no)"

echo "== listed names go direct"
for name in "${DIRECT[@]}"; do
    ip=$(dig @127.0.0.1 +time=3 +tries=1 +short "$name" A | grep -E '^[0-9.]+$' | head -1)
    i=$(ifc "$ip")
    t=$(curl -s -m 8 -o /dev/null -w '%{http_code} %{time_total}s' "https://$name/" || true)
    check "$name -> $(echo "$ip" | mask) via ${i:-?} ($t)" "$([[ $i == en* ]] && echo yes || echo no)"
done

echo "== other names stay in the tunnel"
for name in "${TUNNEL[@]}"; do
    ip=$(dig @127.0.0.1 +time=3 +tries=1 +short "$name" A | grep -E '^[0-9.]+$' | head -1)
    i=$(ifc "$ip")
    t=$(curl -s -m 8 -o /dev/null -w '%{http_code} %{time_total}s' "https://$name/" || true)
    check "$name -> $(echo "$ip" | mask) via ${i:-?} ($t)" "$([[ $i == utun* ]] && echo yes || echo no)"
done

echo "== local network"
ifconfig | awk '/^[a-z]/{i=($1 ~ /^en[0-9]+:$/) ? $1 : ""} /inet / && i {print "  " i " " $2 " mask " $4}' | mask
GW=$(route -n get -ifscope en0 default 2>/dev/null | awk '/gateway:/{print $2}')
[ -n "$GW" ] && check "local router reachable ($(echo "$GW" | mask) via $(ifc "$GW"))" \
    "$(ping -c 2 -t 3 "$GW" >/dev/null 2>&1 && echo yes || echo no)"

echo "accept-check PASS=$PASS FAIL=$FAIL"
