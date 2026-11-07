#!/bin/bash
# Development install of the privileged Helper, for builds WITHOUT a
# developer team (DESIGN.md §20.11). SMAppService only registers
# daemons from a properly signed App; an ad-hoc build cannot use it,
# so this installs the same daemon the classic way: a root-owned copy
# of the Helper in /Library/PrivilegedHelperTools and a LaunchDaemon
# plist declaring the same Mach service the App connects to.
#
# The installed Helper accepts only the App signed with its own
# certificate (DESIGN.md §36.3); an ad-hoc build accepts no App, so
# sign local builds with scripts/dev-signing-identity.sh. Never use
# alongside an SMAppService-installed Helper (same label).
#
# Usage (as root):
#   sudo scripts/dev-helper.sh install [helper]
#                                         copy the Helper (default: the
#                                         .local-build App's), load daemon.
#                                         The App runs this itself from its
#                                         bundle, behind the macOS admin
#                                         password dialog (DESIGN.md §21.8)
#   sudo scripts/dev-helper.sh uninstall  restore network, unload, remove files
#   sudo scripts/dev-helper.sh recover    restore the local network only:
#                                         routes/DNS from route-state, empty the
#                                         pf anchor, clear held state
#   scripts/dev-helper.sh status          daemon state + held-network files
#   scripts/dev-helper.sh log             follow the daemon log
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LABEL=com.alwaysconnect.app.helper
BIN=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist
OCDIR=/Library/PrivilegedHelperTools/AlwaysConnect-openconnect
LOGDIR=/Library/Logs/AlwaysConnect
SUPPORT="/Library/Application Support/AlwaysConnect"
ANCHOR=com.apple/300.AlwaysConnect

need_root() {
    [ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
}

recover() {
    # Same order as a manual disconnect: routes/DNS, then pf.
    local script="$SUPPORT/alwaysconnect-vpnc.sh"
    if [ -x "$script" ]; then
        ALWAYSCONNECT_ROUTE_STATE_PATH="$SUPPORT/route-state" "$script" restore >/dev/null || true
    fi
    pfctl -a "$ANCHOR" -F rules 2>/dev/null || true
    # The network gate's pf enable reference (DESIGN.md §25.2), so pf is
    # not left enabled on our account.
    local token
    token=$(plutil -extract token raw -o - "$SUPPORT/guard.json" 2>/dev/null || true)
    [ -n "$token" ] && pfctl -X "$token" >/dev/null 2>&1 || true
    rm -f "$SUPPORT/guard.json" "$SUPPORT/pf-state.json" "$SUPPORT/route-state" \
        "$SUPPORT/manual-disconnect"
    # A live but slow service still believes it holds that reference;
    # restart it so its state matches (a stopped one just stays idle).
    if launchctl print "system/$LABEL" >/dev/null 2>&1; then
        launchctl kickstart -k "system/$LABEL" >/dev/null 2>&1 || true
    fi
    echo "local network restored (pf anchor emptied, our pf enable reference released)"
}

case "${1:-}" in
install)
    need_root
    src=${2:-"$ROOT/.local-build/AlwaysConnect.app/Contents/Library/LaunchDaemons/AlwaysConnectHelper"}
    [ -x "$src" ] || { echo "build first: scripts/build-local.sh" >&2; exit 1; }
    launchctl bootout system/$LABEL 2>/dev/null || true
    # An older daemon did not take its openconnect down on SIGTERM. HUP:
    # leave without logging the session off, so the App's reconnect can
    # reuse the cookie (DESIGN.md §26.17).
    pkill -HUP -f "^[^ ]*/openconnect .*alwaysconnect-vpnc\.sh" 2>/dev/null || true
    mkdir -p /Library/PrivilegedHelperTools "$LOGDIR"
    chmod 700 "$LOGDIR"
    install -o root -g wheel -m 755 "$src" "$BIN"
    # The App's own openconnect (DESIGN.md §27.3), next to the daemon in a
    # root-only place. App-driven installation uses a verified root-owned
    # snapshot (PrivilegedBundle); manual sudo is a deliberate developer action.
    oc="$(cd "$(dirname "$src")/../.." && pwd)/Resources/openconnect"
    if [ -x "$oc/bin/openconnect" ]; then
        rm -rf "$OCDIR"
        cp -R "$oc" "$OCDIR"
        chown -R root:wheel "$OCDIR"
        chmod -R go-w "$OCDIR"
        echo "openconnect: $(head -2 "$OCDIR/VERSIONS" | tail -1)"
    fi
    # The engine's redacted openconnect output in helper.log is opt-in
    # (DESIGN.md §36.3): it still names the server and the user. Run
    # `sudo ALWAYSCONNECT_DEBUG_CHILD_OUTPUT=1 scripts/dev-helper.sh install`
    # to record a gateway's output shapes; the App's own install leaves it off.
    DEBUG_ENV=""
    if [ "${ALWAYSCONNECT_DEBUG_CHILD_OUTPUT:-}" = 1 ]; then
        DEBUG_ENV='  <key>EnvironmentVariables</key>
  <dict>
    <key>ALWAYSCONNECT_DEBUG_CHILD_OUTPUT</key>
    <string>1</string>
  </dict>
'
    fi
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN</string>
    <string>daemon</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>$LABEL</key>
    <true/>
  </dict>
$DEBUG_ENV  <key>StandardErrorPath</key>
  <string>$LOGDIR/helper.log</string>
  <key>KeepAlive</key>
  <dict>
    <key>Crashed</key>
    <true/>
  </dict>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    plutil -lint -s "$PLIST"
    launchctl bootstrap system "$PLIST"
    # Start it now (no RunAtLoad, DESIGN.md §25.6): a hold the replaced
    # daemon left is adopted and, with no App attached, released after
    # the grace period instead of waiting for the next App launch.
    launchctl kickstart "system/$LABEL" 2>/dev/null || true
    echo "installed; log: sudo tail -f $LOGDIR/helper.log"
    ;;
uninstall)
    need_root
    recover
    launchctl bootout system/$LABEL 2>/dev/null || true
    rm -f "$PLIST" "$BIN"
    rm -rf "$OCDIR"
    echo "uninstalled (log kept in $LOGDIR)"
    ;;
recover)
    need_root
    recover
    ;;
status)
    launchctl print system/$LABEL 2>/dev/null | grep -E "^\s*(state|pid|last exit code) =" || echo "daemon not loaded"
    for f in guard.json pf-state.json route-state; do
        [ -e "$SUPPORT/$f" ] && echo "held: $SUPPORT/$f present" || true
    done
    ;;
log)
    exec sudo tail -f "$LOGDIR/helper.log"
    ;;
*)
    sed -n '2,25p' "$0"
    exit 2
    ;;
esac
