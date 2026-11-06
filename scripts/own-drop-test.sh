#!/bin/bash
# Real drop test for the own connection (DESIGN.md §二十三, mac-proof I2).
# With the own connection up, it kills openconnect abruptly (SIGKILL: no
# logout, like a lost link; the background service sees a drop), then
# probes every 3 s:
#   web  - HTTPS through the default route (must FAIL while down: a
#          success before the tunnel is back means a leak)
#   dns  - a lookup through the system resolver
#   lan  - the local router (allowed: home LAN / allowlist)
# until the tunnel is back and the web answers through it, or 150 s
# pass. On timeout it restores the direct network itself
# (dev-helper.sh recover), so this never leaves the Mac offline.
# Also prints the pf anchor the background service had loaded.
#
# Usage: sudo scripts/own-drop-test.sh | tee /tmp/ac-own-drop.txt
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIMIT=${LIMIT:-150}
ANCHOR=com.apple/300.AlwaysConnect
mask() { sed -E 's/([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/\1.x.x/g'; }
oc() { pgrep -f "alwaysconnect-vpnc.sh" | head -1; }
tun() { netstat -rn -f inet | awk '$1=="default"{print $4; exit}'; }
web() { curl -s -m 4 -o /dev/null -w '%{http_code}' https://www.apple.com 2>/dev/null || true; }
dns() { [ -n "$(dig +time=2 +tries=1 +short apple.com 2>/dev/null | head -1)" ] && echo ok || echo fail; }
ROUTER=$(ipconfig getoption en0 router 2>/dev/null || true)
lan() {
    [ -n "$ROUTER" ] || { echo none; return; }
    for port in 53 80 443; do
        nc -z -G 2 "$ROUTER" "$port" >/dev/null 2>&1 && { echo ok; return; }
    done
    ping -c 1 -t 2 "$ROUTER" >/dev/null 2>&1 && echo ok || echo fail
}
ok() { [ "$1" = 200 ] || [ "$1" = 301 ] || [ "$1" = 302 ]; }

FIRST=$(oc)
[ -n "$FIRST" ] && case "$(tun)" in utun*) true;; *) false;; esac ||
    { echo "connect with the own connection in AlwaysConnect first" >&2; exit 2; }
echo "== pf anchor while connected"; pfctl -a "$ANCHOR" -sr 2>/dev/null | mask
START=$(date +%s)
t() { echo $(( $(date +%s) - START )); }
echo "t=0 baseline: default=$(tun) web=$(web) dns=$(dns) lan=$(lan)"
kill -9 "$FIRST"
echo "t=$(t) killed openconnect (abrupt loss); the session should come back by itself"

leaks=0; blocked=0; dns_ok=0; lan_ok=0; down=0; back=""
while [ "$(t)" -lt "$LIMIT" ]; do
    p=$(oc); d=$(tun); w=$(web); n=$(dns); l=$(lan)
    up=no
    [ -n "$p" ] && [ "$p" != "$FIRST" ] && case "$d" in utun*) up=yes;; esac
    echo "t=$(t) openconnect=${p:-none} default=${d:-none} web=$w dns=$n lan=$l"
    if [ "$up" = yes ] && ok "$w"; then back=$(t); break; fi
    down=$((down + 1))
    if ok "$w"; then leaks=$((leaks + 1)); else blocked=$((blocked + 1)); fi
    [ "$n" = ok ] && dns_ok=$((dns_ok + 1))
    [ "$l" = ok ] && lan_ok=$((lan_ok + 1))
    [ "$down" = 2 ] && { echo "== pf anchor while down"; pfctl -a "$ANCHOR" -sr 2>/dev/null | mask; }
    sleep 3
done

if [ -z "$back" ]; then
    echo "t=$(t) not back within ${LIMIT}s; restoring the direct network"
    pkill -f "alwaysconnect-vpnc.sh" 2>/dev/null || true
    "$ROOT/scripts/dev-helper.sh" recover
fi

echo "== result"
echo "probes while down: $down  leaked: $leaks  blocked: $blocked  dns ok: $dns_ok  lan ok: $lan_ok"
[ -n "$back" ] && echo "back after ${back}s (new openconnect, tunnel default route, web answering)" || echo "did not come back"
[ "$leaks" -eq 0 ] && echo "NO LEAK: no web request got out while the tunnel was down" ||
    echo "LEAK: $leaks web request(s) got out while the tunnel was down"
