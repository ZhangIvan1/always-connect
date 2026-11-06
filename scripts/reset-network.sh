#!/bin/bash
# AlwaysConnect emergency network reset (DESIGN.md §24.6).
#
# Puts the Mac back on its plain local network whatever state
# AlwaysConnect left it in, without the App, the background service or
# the internet. Self-contained on purpose: a copy of this file on the
# Desktop must keep working even if the repository moves.
#
#   1 stop everything of ours: the App, the background service, our
#     openconnect (the one using our vpnc-script) and, from older builds,
#     a routing core (mihomo with our config). Other apps (Cisco, Clash,
#     ...) untouched.
#   2 forget the held state so nothing re-blocks on its own
#   3 routes: drop our core's 0/1 and 128/1, restore the default route
#     through the physical interface if it is missing
#   4 DNS: remove stale tunnel DNS/IPv4 entries (State:/Network/Service/
#     utunN/..., written by our vpnc-script) whose utun no longer exists:
#     they keep a dead tunnel "primary" and DNS pointed into it. A live
#     utun's entries (another VPN's) are kept. Then flush the DNS cache
#   5 pf: empty our anchor, release our pf enable reference
#   6 verify; only if the web still fails, disable pf as a last resort
#
# Usage:
#   sudo scripts/reset-network.sh            (or double-click the Desktop copy)
#   scripts/reset-network.sh --dry-run       show what it would do, change nothing
#   reset-network.sh --from-app              the App's "恢复网络" button: the App
#                                            has already disconnected and stays open
#   reset-network.sh --keep-unloaded         leave the background service unloaded
#                                            afterwards (the uninstaller, DESIGN.md §31)
set -u
DRY=0
FROM_APP=0
KEEP_UNLOADED=0
for a in "$@"; do
    case "$a" in --dry-run) DRY=1;; --from-app) FROM_APP=1;; --keep-unloaded) KEEP_UNLOADED=1;; esac
done
if [ $DRY = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "需要管理员权限，请输入这台电脑的开机密码："
    exec sudo /bin/bash "$0" "$@"
fi

LABEL=com.alwaysconnect.app.helper
SUPPORT="/Library/Application Support/AlwaysConnect"
ANCHOR=com.apple/300.AlwaysConnect
say() { echo "• $*"; }
run() {
    if [ $DRY = 1 ]; then echo "  [dry-run] $*"; else "$@" >/dev/null 2>&1; fi
}
web() { curl -s -m 6 -o /dev/null -w '%{http_code}' https://www.apple.com 2>/dev/null || true; }
webok() { case "$(web)" in 200|301|302) return 0;; *) return 1;; esac; }

echo "== AlwaysConnect 恢复网络 $( [ $DRY = 1 ] && echo '(dry-run)')"

# 1 our processes, matched narrowly: by the App's executable name and by
# command lines that START with our programs, never by a name merely
# mentioned in some other command (a terminal running `launchctl print
# system/<our label>` was killed by the old patterns, DESIGN.md §31.5).
# Run by hand: the background service is unloaded
# FIRST — killed after the App, it saw the App vanish while holding and
# reopened it at once, and the reopened App connected again behind the
# reset (DESIGN.md §30.3). It is loaded again (idle) at the end.
PLIST=/Library/LaunchDaemons/$LABEL.plist
UNLOADED=0
if [ $FROM_APP = 0 ] && launchctl print "system/$LABEL" >/dev/null 2>&1; then
    say "unload the background service"
    run launchctl bootout "system/$LABEL"
    UNLOADED=1
fi
if [ $FROM_APP = 0 ]; then
    for p in $(pgrep -x AlwaysConnect); do
        say "stop AlwaysConnect App (pid $p)"; run kill -9 "$p"
    done
fi
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    say "stop the background service"
    run launchctl kill SIGTERM "system/$LABEL"
    [ $DRY = 1 ] || sleep 2
fi
for p in $(pgrep -f "^/Library/PrivilegedHelperTools/$LABEL( |$)"); do
    say "background service still running (pid $p): kill"; run kill -9 "$p"
done
for p in $(pgrep -f "^[^ ]*/openconnect .*alwaysconnect-vpnc\.sh"); do
    say "stop our openconnect (pid $p)"; run kill -9 "$p"
done
for p in $(pgrep -f "^[^ ]*mihomo .*AlwaysConnect/core"); do
    say "stop our routing core (pid $p)"; run kill -9 "$p"
done
[ $DRY = 1 ] || sleep 1

# 2 held state (and our pf enable reference, released in step 5).
# The route journal is undone by the script that wrote it first
# (DESIGN.md §26.3): gateway host route, default route, tunnel DNS.
TOKEN=$(plutil -extract token raw -o - "$SUPPORT/guard.json" 2>/dev/null || true)
if [ -f "$SUPPORT/route-state" ] && [ -x "$SUPPORT/alwaysconnect-vpnc.sh" ]; then
    say "undo the route journal"
    run env ALWAYSCONNECT_ROUTE_STATE_PATH="$SUPPORT/route-state" "$SUPPORT/alwaysconnect-vpnc.sh" restore
fi
# The domain split's host routes, from their own journal (§26.5).
if [ -f "$SUPPORT/direct-routes" ]; then
    n=0
    while read -r ip gw; do
        [ "$ip" = boot ] && continue
        case "$ip" in
            */*) run route -n delete -net "$ip";;
            *) run route -n delete -host "$ip";;
        esac
        n=$((n + 1))
    done < "$SUPPORT/direct-routes"
    say "removed $n direct route(s)"
    # A network of ours that the Mac has since moved onto kept the
    # system from adding that LAN's own route: put it back (harmless
    # when it exists, DESIGN.md §30.2).
    for i in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^en'); do
        NET=$(ifconfig "$i" 2>/dev/null | awk '/inet / && $2 !~ /^169\.254\./ {
            split($2, a, "."); h = tolower($4); sub(/^0x/, "", h); bits = 0
            for (k = 1; k <= length(h); k++) { d = index("0123456789abcdef", substr(h, k, 1)) - 1
                for (b = 3; b >= 0; b--) if (int(d / 2^b) % 2) bits++ }
            ip = ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
            net = ip - ip % 2^(32 - bits)
            printf "%d.%d.%d.%d/%d\n", int(net / 16777216) % 256, int(net / 65536) % 256, int(net / 256) % 256, net % 256, bits
            exit }')
        [ -n "$NET" ] && run route -n add -net "$NET" -interface "$i"
    done
fi
for f in guard.json pf-state.json route-state manual-disconnect direct-routes; do
    [ -e "$SUPPORT/$f" ] && { say "forget held state $f"; run rm -f "$SUPPORT/$f"; }
done

# 3 routes
for net in 0/1 128.0/1; do
    IF=$(netstat -rn -f inet | awk -v n="$net" '$1==n{print $NF; exit}')
    case "$IF" in
        utun23[0-9]|utun24[0-9])
            say "remove core route $net via $IF"
            run route -n delete -net "$([ "$net" = 0/1 ] && echo 0.0.0.0/1 || echo 128.0.0.0/1)" -interface "$IF";;
    esac
done

# 4 DNS / primary service entries our vpnc-script wrote, keyed by utun name
KEYS=$(printf 'list State:/Network/Service/utun[0-9]*/.*\nquit\n' | scutil 2>/dev/null \
    | sed -n 's/.*= \(State:\/Network\/Service\/utun[0-9]*\/[A-Za-z0-9]*\)$/\1/p')
for k in $KEYS; do
    TUN=$(echo "$k" | cut -d/ -f4)
    # A live utun belongs to a running VPN (ours is stopped by now):
    # only entries for tunnels that no longer exist are removed.
    if ifconfig "$TUN" 2>/dev/null | grep -q "inet "; then
        say "keep $k ($TUN is up: another VPN's)"; continue
    fi
    say "remove stale tunnel entry $k"
    if [ $DRY = 1 ]; then echo "  [dry-run] scutil remove $k"
    else printf 'open\nremove %s\nclose\n' "$k" | scutil >/dev/null 2>&1; fi
done
[ $DRY = 1 ] || sleep 2

DEF_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
set_default_route() {
    for i in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^en'); do
        GW=$(ipconfig getoption "$i" router 2>/dev/null || true)
        [ -n "$GW" ] || continue
        say "default route was ${DEF_IF:-missing}: set it via $i ($GW)"
        run route -n delete default
        run route -n add default "$GW"
        break
    done
}
case "$DEF_IF" in
    en[0-9]*|bridge*) say "default route via $DEF_IF (local network)";;
    utun[0-9]*)
        # Ours is stopped by now, so a tunnel still up belongs to another
        # VPN (Cisco Secure Client run by hand): its route stays (§31.3).
        if ifconfig "$DEF_IF" 2>/dev/null | grep -q "inet "; then
            say "default route via $DEF_IF (another VPN's, kept)"
        else
            set_default_route
        fi;;
    *) set_default_route;;
esac

say "flush DNS cache"
run dscacheutil -flushcache
run killall -HUP mDNSResponder

# 5 pf: our anchor and our enable reference only
say "empty our pf anchor"
run pfctl -a "$ANCHOR" -F all
[ -n "$TOKEN" ] && { say "release our pf enable reference"; run pfctl -X "$TOKEN"; }

# The background service back in place, idle: nothing is held any more,
# so it starts only when the App asks and exits again without it.
if [ $UNLOADED = 1 ] && [ $KEEP_UNLOADED = 0 ] && [ -f "$PLIST" ]; then
    say "load the background service again (idle)"
    run launchctl bootstrap system "$PLIST"
fi

# 6 verify
[ $DRY = 1 ] && { echo "== dry-run done, nothing changed"; exit 0; }
sleep 2
if webok; then
    echo "== 网络已恢复：默认路由 $(route -n get default 2>/dev/null | awk '/interface:/{print $2}')，网页可以打开。"
    exit 0
fi
say "web still failing: disable pf as a last resort"
pfctl -d >/dev/null 2>&1 || true
sleep 2
if webok; then
    echo "== 网络已恢复（关闭了系统防火墙 pf；重启电脑后会恢复原状）。"
    exit 0
fi
echo "== 我们的设置已全部清掉，但网页仍打不开：请检查 Wi-Fi/网线，或重启电脑。"
echo "   当前默认路由：$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
exit 1
