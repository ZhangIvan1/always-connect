#!/bin/bash
# Script-level assertions for scripts/uninstall.sh (DESIGN.md §31): runs
# it against a fake file system (ALWAYSCONNECT_UNINSTALL_ROOT) with every
# Mac-changing command logged instead of run. Proves the logic (what goes,
# what stays, the from-App detach and wait), not the effect on a real Mac.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
UNINSTALL="$ROOT/scripts/uninstall.sh"
FAILS=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
gone() { [ ! -e "$1" ] && pass "removed: ${1#$R}" || fail "still there: ${1#$R}"; }
kept() { [ -e "$1" ] && pass "kept: ${1#$R}" || fail "removed but must stay: ${1#$R}"; }
logged() { grep -qF -- "$1" "$R/commands.log" 2>/dev/null && pass "ran: $1" || fail "did not run: $1"; }
not_logged() { grep -qF -- "$1" "$R/commands.log" 2>/dev/null && fail "must not run: $1" || pass "not run: $1"; }

app_bundle() {  # path bundle-id
    mkdir -p "$1/Contents/MacOS"
    cat > "$1/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>$2</string></dict></plist>
EOF
    touch "$1/Contents/MacOS/AlwaysConnect"
}

setup() {
    R=$(mktemp -d /tmp/ac-uninstall-test.XXXXXX)
    H="$R/Users/someone"
    S="$R/Library/Application Support/AlwaysConnect"
    mkdir -p "$R/Library/LaunchDaemons" "$R/Library/PrivilegedHelperTools/AlwaysConnect-openconnect/bin" \
        "$S/relay" "$R/Library/Logs/AlwaysConnect" \
        "$H/Library/Logs/AlwaysConnect" "$H/Library/Application Support/AlwaysConnect" \
        "$H/Library/Caches/com.alwaysconnect.app" "$H/Library/Preferences" "$H/Desktop" \
        "$H/Library/Saved Application State/com.alwaysconnect.app.savedState" \
        "$R/opt/cisco/secureclient/bin" "$R/Applications/Cisco"
    touch "$R/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist" \
        "$R/Library/LaunchDaemons/com.cisco.secureclient.vpnagentd.plist" \
        "$R/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper" \
        "$R/Library/PrivilegedHelperTools/AlwaysConnect-openconnect/bin/openconnect" \
        "$S/guard.json" "$S/route-state" "$S/session.json" "$S/relay/client.key" \
        "$R/Library/Logs/AlwaysConnect/helper.log" \
        "$H/Library/Logs/AlwaysConnect/relay.log" "$H/Library/Logs/AlwaysConnect/update.log" \
        "$H/Library/Application Support/AlwaysConnect/alwaysconnect-vpnc.sh" \
        "$H/Library/Preferences/com.alwaysconnect.app.plist" \
        "$H/Library/Preferences/group.com.alwaysconnect.app.plist" \
        "$H/Library/Preferences/group.com.alwaysconnect.render.plist" \
        "$H/Library/Preferences/com.cisco.secureclient.gui.plist" \
        "$R/opt/cisco/secureclient/bin/vpn"
    printf '#!/bin/bash\n# AlwaysConnect emergency network reset (DESIGN.md §24.6).\n' \
        > "$H/Desktop/AlwaysConnect 恢复网络.command"
    app_bundle "$R/Applications/AlwaysConnect.app" com.alwaysconnect.app
    app_bundle "$R/Applications/Cisco/Cisco Secure Client.app" com.cisco.secureclient.gui
    export ALWAYSCONNECT_UNINSTALL_ROOT="$R" ALWAYSCONNECT_UNINSTALL_HOME="$H"
}

system_and_user_files_gone() {
    gone "$R/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist"
    gone "$R/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper"
    gone "$R/Library/PrivilegedHelperTools/AlwaysConnect-openconnect"
    gone "$R/Library/Application Support/AlwaysConnect"
    gone "$R/Library/Logs/AlwaysConnect"
    gone "$H/Library/Logs/AlwaysConnect"
    gone "$H/Library/Application Support/AlwaysConnect"
    gone "$H/Library/Caches/com.alwaysconnect.app"
    gone "$H/Library/Saved Application State/com.alwaysconnect.app.savedState"
    gone "$H/Library/Preferences/group.com.alwaysconnect.render.plist"
    gone "$H/Desktop/AlwaysConnect 恢复网络.command"
    gone "$R/Applications/AlwaysConnect.app"
    logged "reset-network --keep-unloaded"
    logged "launchctl bootout system/com.alwaysconnect.app.helper"
}

cisco_untouched() {
    kept "$R/Library/LaunchDaemons/com.cisco.secureclient.vpnagentd.plist"
    kept "$R/opt/cisco/secureclient/bin/vpn"
    kept "$R/Applications/Cisco/Cisco Secure Client.app"
    kept "$H/Library/Preferences/com.cisco.secureclient.gui.plist"
}

no_stage_left() {
    ls -d "$R"/tmp/alwaysconnect-uninstall.* >/dev/null 2>&1 \
        && fail "staged copy left behind" || pass "staged copy removed"
}

echo "== 1 from a terminal: everything goes"
setup
OUT=$(bash "$UNINSTALL" 2>&1)
echo "$OUT" | grep -q "^== AlwaysConnect 已卸载" && pass "verdict line" || fail "verdict line: $OUT"
system_and_user_files_gone
gone "$H/Library/Preferences/com.alwaysconnect.app.plist"
gone "$H/Library/Preferences/group.com.alwaysconnect.app.plist"
logged "as-user defaults delete com.alwaysconnect.app"
logged "as-user defaults delete group.com.alwaysconnect.app"
logged "as-user security delete-generic-password -s com.alwaysconnect.app"
logged "as-user tccutil reset All com.alwaysconnect.app"
cisco_untouched
no_stage_left
rm -rf "$R"

echo "== 2 keep settings and password"
setup
bash "$UNINSTALL" --keep-settings --keep-password >/dev/null 2>&1
system_and_user_files_gone
kept "$H/Library/Preferences/com.alwaysconnect.app.plist"
kept "$H/Library/Preferences/group.com.alwaysconnect.app.plist"
not_logged "defaults delete"
not_logged "security delete-generic-password"
cisco_untouched
rm -rf "$R"

echo "== 3 from the App: returns at once, finishes after the App quits"
setup
app_bundle "$R/build/AlwaysConnect.app" com.alwaysconnect.app
sleep 30 & FAKE_APP=$!
START=$(date +%s)
OUT=$(bash "$UNINSTALL" --from-app --user someone --app-pid $FAKE_APP --app "$R/build/AlwaysConnect.app" 2>&1)
[ $(( $(date +%s) - START )) -lt 5 ] && pass "returned at once" || fail "blocked on the App"
echo "$OUT" | grep -q "^== 卸载已开始" && pass "start line" || fail "start line: $OUT"
sleep 2
kept "$R/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist"
[ -e "$R/commands.log" ] && fail "acted before the App quit" || pass "waits for the App"
kill $FAKE_APP 2>/dev/null; wait $FAKE_APP 2>/dev/null
for _ in $(seq 1 10); do [ -e "$R/Applications/AlwaysConnect.app" ] || break; sleep 1; done
sleep 1
system_and_user_files_gone
gone "$R/build/AlwaysConnect.app"
gone "$H/Library/Preferences/com.alwaysconnect.app.plist"
not_logged "security delete-generic-password"   # the App did the keychain itself
cisco_untouched
no_stage_left
rm -rf "$R"

echo "== 4 not ours: a foreign bundle and a foreign Desktop file stay"
setup
rm -rf "$R/Applications/AlwaysConnect.app"
app_bundle "$R/Applications/AlwaysConnect.app" com.example.other
echo "my own notes" > "$H/Desktop/AlwaysConnect 恢复网络.command"
bash "$UNINSTALL" >/dev/null 2>&1
kept "$R/Applications/AlwaysConnect.app"
kept "$H/Desktop/AlwaysConnect 恢复网络.command"
gone "$R/Library/Application Support/AlwaysConnect"
rm -rf "$R"

echo "== 5 dry-run changes nothing"
setup
bash "$UNINSTALL" --dry-run >/dev/null 2>&1
kept "$R/Library/Application Support/AlwaysConnect"
kept "$R/Applications/AlwaysConnect.app"
kept "$H/Library/Preferences/com.alwaysconnect.app.plist"
rm -rf "$R"

echo
[ $FAILS = 0 ] && { echo "uninstall-test: all passed"; exit 0; }
echo "uninstall-test: $FAILS failure(s)"; exit 1
