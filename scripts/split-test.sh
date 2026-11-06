#!/bin/bash
# Real check of the domain split (DESIGN.md §26.4–§26.7, plan v2 B5) and
# of batch A's "nothing left behind". Run with sudo while the own
# connection is up and a site you pass as SPLIT_SITE is on the split
# list (设置 → 分流 → 不走 VPN 的名单).
#
#   sudo SPLIT_SITE=www.example.com scripts/split-test.sh   connected checks + a drop
#   sudo scripts/split-test.sh --after-disconnect  after clicking 断开: no residue
#
# Safety (AGENTS.md): a watchdog probes a listed site every 3 s; if it
# fails for 45 s straight the direct network is restored with the reset
# tool and the test stops. Nothing here can leave the Mac offline.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
[ -n "${SPLIT_SITE:-}" ] || [ "${1:-}" = --after-disconnect ] || { echo "set SPLIT_SITE to a site on your split list" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUPPORT="/Library/Application Support/AlwaysConnect"
ANCHOR=com.apple/300.AlwaysConnect
DIRECT=${SPLIT_SITE:-}
OTHER=www.apple.com
FAILS=0
mask() { sed -E 's/([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/\1.x.x/g'; }
check() { if [ "$2" = yes ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }
ok() { case "$1" in 200|204|301|302) return 0;; *) return 1;; esac; }
web() { curl -s -m 5 -o /dev/null -w '%{http_code}' "https://$1/" 2>/dev/null || true; }
oc() { pgrep -f "alwaysconnect-vpnc.sh" | head -1; }
ifc() { route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'; }
PHYS=$(netstat -rn -f inet | awk '$1=="default" && $NF ~ /^en/{print $NF; exit}')

reset_now() {
    echo "== restoring the direct network"
    if [ -x /Applications/AlwaysConnect.app/Contents/Resources/reset-network.sh ]; then
        /Applications/AlwaysConnect.app/Contents/Resources/reset-network.sh
    else
        "$ROOT/scripts/reset-network.sh"
    fi
}

if [ "${1:-}" = "--after-disconnect" ]; then
    echo "== after 断开: nothing of the session may be left"
    check "no openconnect of ours" "$([ -z "$(oc)" ] && echo yes || echo no)"
    check "forwarder no longer listens on 127.0.0.1:53" "$(lsof -nP -iUDP@127.0.0.1:53 2>/dev/null | grep -q . && echo no || echo yes)"
    check "route journal undone" "$([ -e "$SUPPORT/route-state" ] && echo no || echo yes)"
    check "direct-route journal undone" "$([ -e "$SUPPORT/direct-routes" ] && echo no || echo yes)"
    KEYS=$(printf 'list State:/Network/Service/utun[0-9]*/.*\nquit\n' | scutil | grep -c subKey || true)
    check "no tunnel DNS entries left ($KEYS)" "$([ "$KEYS" = 0 ] && echo yes || echo no)"
    check "default route on the physical interface" "$(case "$(ifc default)" in en*) echo yes;; *) echo no;; esac)"
    RULES=$(pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -c . || true)
    check "pf anchor empty ($RULES rules)" "$([ "$RULES" = 0 ] && echo yes || echo no)"
    check "web works" "$(ok "$(web $OTHER)" && echo yes || echo no)"
    echo "split after-disconnect FAILS=$FAILS"
    exit 0
fi

[ -n "$(oc)" ] && case "$(ifc default)" in utun*) true;; *) false;; esac ||
    { echo "connect with the own connection first (with SPLIT_SITE on the split list)" >&2; exit 2; }

# Watchdog: a listed site must stay reachable, tunnel or not.
( bad=0
  while kill -0 $$ 2>/dev/null; do
      if ok "$(web $DIRECT)"; then bad=0; else bad=$((bad + 1)); fi
      if [ $bad -ge 15 ]; then echo "!! watchdog: no web for 45 s"; reset_now; kill $$; exit; fi
      sleep 3
  done ) &
WD=$!
trap 'kill $WD 2>/dev/null' EXIT

echo "== 1 connected"
check "forwarder listens on 127.0.0.1:53" "$(lsof -nP -iUDP@127.0.0.1:53 2>/dev/null | grep -q . && echo yes || echo no)"
FIRST=$(scutil --dns | awk '/^resolver #1/{p=1} p && /nameserver\[0\]/{print $3; exit}')
check "system DNS asks the forwarder first ($FIRST)" "$([ "$FIRST" = 127.0.0.1 ] && echo yes || echo no)"
IPS=$(dig @127.0.0.1 +time=3 +tries=1 +short "$DIRECT" A | grep -E '^[0-9.]+$' | head -3)
check "listed site resolves through the forwarder" "$([ -n "$IPS" ] && echo yes || echo no)"
AAAA=$(dig @127.0.0.1 +time=3 +tries=1 +short "$DIRECT" AAAA | grep -c : || true)
check "listed site gets no IPv6 answer" "$([ "$AAAA" = 0 ] && echo yes || echo no)"
for ip in $IPS; do
    I=$(ifc "$ip")
    check "listed address $(echo "$ip" | mask) routed via $I" "$([ "$I" = "$PHYS" ] && echo yes || echo no)"
    check "listed address $(echo "$ip" | mask) in the direct table" \
        "$(pfctl -a "$ANCHOR" -t ac_direct -T show 2>/dev/null | grep -qx " *$ip" && echo yes || echo no)"
done
OIP=$(dig @127.0.0.1 +time=3 +tries=1 +short "$OTHER" A | grep -E '^[0-9.]+$' | head -1)
check "other site routed into the tunnel ($(ifc "$OIP"))" "$(case "$(ifc "$OIP")" in utun*) echo yes;; *) echo no;; esac)"
check "listed site loads" "$(ok "$(web $DIRECT)" && echo yes || echo no)"
check "other site loads" "$(ok "$(web $OTHER)" && echo yes || echo no)"

echo "== 2 drop (openconnect killed; the session comes back by itself)"
O=$(oc); kill -9 "$O"
leaks=0; direct_ok=0; down=0; back=no
for _ in $(seq 1 40); do
    sleep 3
    p=$(oc); d=$(web $DIRECT); o=$(web $OTHER)
    echo "  openconnect=${p:-none} listed=$d other=$o default=$(ifc default)"
    if [ -n "$p" ] && [ "$p" != "$O" ] && ok "$o"; then back=yes; break; fi
    down=$((down + 1))
    ok "$o" && leaks=$((leaks + 1))
    ok "$d" && direct_ok=$((direct_ok + 1))
done
check "nothing else got out while the tunnel was down ($down probes)" "$([ $leaks = 0 ] && echo yes || echo no)"
check "the listed site kept working during the drop ($direct_ok/$down)" "$([ $down = 0 ] || [ $direct_ok -gt 0 ] && echo yes || echo no)"
check "session came back by itself" "$back"
[ $back = yes ] || reset_now
echo "split FAILS=$FAILS  (next: click 断开 in the panel, then: sudo scripts/split-test.sh --after-disconnect)"
