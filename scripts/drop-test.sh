#!/bin/bash
# Real drop test for the Cisco engine (DESIGN.md §21.17, mac-proof H2).
# Measures instead of trusting the panel: with the VPN up and
# AlwaysConnect running, it drops Cisco's session (`vpn disconnect`,
# which the App treats as a lost session), then probes every 3 s:
#   web  - HTTPS through the default route (must FAIL while down: a
#          success means traffic left over the local network = leak)
#   dns  - a lookup through the system resolver (allowed on purpose)
#   lan  - the local router (allowed: home LAN / allowlist)
# until Cisco is connected again (approve the phone push) or 150 s
# pass. On timeout it quits AlwaysConnect gracefully, which disconnects
# and restores the direct network, so this never leaves the Mac offline.
#
# Usage: scripts/drop-test.sh        (VPN connected, App running)
set -uo pipefail

VPN=/opt/cisco/secureclient/bin/vpn
LIMIT=${LIMIT:-150}
state() { "$VPN" state 2>/dev/null | grep -o 'state: [A-Za-z]*' | tail -1 | cut -d' ' -f2; }
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

[ "$(state)" = Connected ] || { echo "connect the VPN in AlwaysConnect first" >&2; exit 2; }
pgrep -f "AlwaysConnect.app/Contents/MacOS" >/dev/null || { echo "AlwaysConnect is not running" >&2; exit 2; }

START=$(date +%s)
t() { echo $(( $(date +%s) - START )); }
echo "t=0 baseline: cisco=$(state) web=$(web) dns=$(dns) lan=$(lan)"
"$VPN" disconnect >/dev/null 2>&1
echo "t=$(t) dropped Cisco's session; approve the phone push when it arrives"

leaks=0; blocked=0; dns_ok=0; lan_ok=0; down=0; back=""
while [ "$(t)" -lt "$LIMIT" ]; do
    s=$(state); w=$(web); d=$(dns); l=$(lan)
    echo "t=$(t) cisco=$s web=$w dns=$d lan=$l"
    if [ "$s" != Connected ]; then
        down=$((down + 1))
        if [ "$w" = 200 ] || [ "$w" = 301 ] || [ "$w" = 302 ]; then leaks=$((leaks + 1)); else blocked=$((blocked + 1)); fi
        [ "$d" = ok ] && dns_ok=$((dns_ok + 1))
        [ "$l" = ok ] && lan_ok=$((lan_ok + 1))
    elif [ "$w" = 200 ] || [ "$w" = 301 ] || [ "$w" = 302 ]; then
        back=$(t); break
    fi
    sleep 3
done

if [ -z "$back" ]; then
    echo "t=$(t) not reconnected within ${LIMIT}s; quitting AlwaysConnect to restore the direct network"
    osascript -e 'tell application id "com.alwaysconnect.app" to quit' >/dev/null 2>&1 || true
    sleep 5
fi

echo "== result"
echo "probes while down: $down  leaked: $leaks  blocked: $blocked  dns ok: $dns_ok  lan ok: $lan_ok"
[ -n "$back" ] && echo "reconnected after ${back}s" || echo "did not reconnect"
[ "$leaks" -eq 0 ] && echo "NO LEAK: no web request got out while the VPN was down" || echo "LEAK: $leaks web request(s) got out while the VPN was down"
