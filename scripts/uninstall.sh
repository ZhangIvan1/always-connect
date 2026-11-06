#!/bin/bash
# AlwaysConnect clean uninstall (DESIGN.md §三十一).
#
# Takes AlwaysConnect off this Mac and leaves nothing behind: the network
# back on direct, then every file the App, the background service and
# their scripts ever wrote. Cisco Secure Client is never touched.
#
#   1 wait for the App to quit (its normal quit ends the VPN and releases
#     the network); from a terminal, ask it to quit first
#   2 network back to direct: reset-network.sh (routes, DNS, pf anchor,
#     our pf enable reference, held state), the background service
#     unloaded and kept unloaded
#   3 system files: the LaunchDaemon, the background service, the bundled
#     openconnect copy, /Library/Application Support/AlwaysConnect
#     (held state, session cookie, relay key, journals), its logs
#   4 the user's files: logs, caches, the Desktop reset copy; settings
#     (both preference domains) unless --keep-settings; the keychain
#     password unless --keep-password (from the App, the App has already
#     dealt with the keychain itself)
#   5 the App itself: the running bundle and /Applications/AlwaysConnect.app,
#     each only when its bundle identifier is ours
#
# Runs from a root-only copy in /private/tmp, so removing the App bundle
# (where this file lives) cannot cut it short; the copy removes itself.
#
# Usage:
#   sudo bash /Applications/AlwaysConnect.app/Contents/Resources/uninstall.sh
#                 [--keep-settings] [--keep-password]
#   uninstall.sh --dry-run          list what would go, change nothing
#   uninstall.sh --from-app --user NAME --app-pid PID --app PATH [--keep-settings]
#                 the App's "卸载" button (behind the administrator password
#                 dialog): returns at once, finishes after the App has quit
set -u

LABEL=com.alwaysconnect.app.helper
BUNDLE_ID=com.alwaysconnect.app
KEYCHAIN_SERVICE=com.alwaysconnect.app
ANCHOR=com.apple/300.AlwaysConnect

ORIG=("$@")
FROM_APP=0 FINISH=0 DRY=0 KEEP_SETTINGS=0 KEEP_PASSWORD=0
TARGET_USER="" APP_PID="" APP_PATH="" STAGE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from-app) FROM_APP=1;;
        --finish) FINISH=1;;
        --dry-run) DRY=1;;
        --keep-settings) KEEP_SETTINGS=1;;
        --keep-password) KEEP_PASSWORD=1;;
        --user) TARGET_USER=${2:-}; shift;;
        --app-pid) APP_PID=${2:-}; shift;;
        --app) APP_PATH=${2:-}; shift;;
        --stage) STAGE=${2:-}; shift;;
        -h|--help) sed -n '2,36p' "$0"; exit 0;;
        *) echo "unknown option: $1" >&2; exit 2;;
    esac
    shift
done

# Test seam (scripts/uninstall-test.sh): every system path under $R, the
# user's home from ALWAYSCONNECT_UNINSTALL_HOME, and commands that would
# touch the real Mac (launchctl, pfctl, defaults, security, the network
# reset) written to $R/commands.log instead of run.
R=${ALWAYSCONNECT_UNINSTALL_ROOT:-}
TESTING=0
[ -n "$R" ] && TESTING=1

if [ $TESTING = 0 ] && [ $DRY = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "需要管理员权限，请输入这台电脑的开机密码："
    exec sudo /bin/bash "$0" "${ORIG[@]}"
fi

say() { echo "• $*"; }
# A command that changes the Mac outside our own files.
sys() {
    if [ $TESTING = 1 ]; then echo "$*" >> "$R/commands.log"; return 0; fi
    if [ $DRY = 1 ]; then echo "  [dry-run] $*"; return 0; fi
    "$@" >/dev/null 2>&1
}

# The person whose files and keychain are cleaned: the App passes its
# user; from a terminal it is whoever ran sudo, else the console user.
[ -n "$TARGET_USER" ] || TARGET_USER=${SUDO_USER:-}
[ -n "$TARGET_USER" ] || TARGET_USER=$(stat -f %Su /dev/console 2>/dev/null || true)
[ "$TARGET_USER" = root ] && TARGET_USER=""
TARGET_UID="" USER_HOME=""
if [ $TESTING = 1 ]; then
    USER_HOME=${ALWAYSCONNECT_UNINSTALL_HOME:-}
elif [ -n "$TARGET_USER" ]; then
    TARGET_UID=$(id -u "$TARGET_USER" 2>/dev/null || true)
    USER_HOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi

as_user() {
    if [ $TESTING = 1 ]; then echo "as-user $*" >> "$R/commands.log"; return 0; fi
    if [ $DRY = 1 ]; then echo "  [dry-run] (as $TARGET_USER) $*"; return 0; fi
    [ -n "$TARGET_UID" ] || return 1
    launchctl asuser "$TARGET_UID" sudo -u "$TARGET_USER" "$@" >/dev/null 2>&1
}

# Only ever a path of ours: the name says AlwaysConnect.
remove() {
    local p=$1
    [ -e "$p" ] || [ -L "$p" ] || return 0
    case "$(basename "$p")" in
        *[Aa]lways[Cc]onnect*) ;;
        *) say "skip $p (not ours by name)"; return 0;;
    esac
    say "remove $p"
    if [ $DRY = 1 ]; then echo "  [dry-run] rm -rf $p"; else rm -rf "$p"; fi
}

# An App bundle, only when it really is AlwaysConnect.
remove_app() {
    local p=${1%/}
    case "$p" in *.app) ;; *) return 0;; esac
    [ -d "$p" ] || return 0
    local id
    id=$(plutil -extract CFBundleIdentifier raw -o - "$p/Contents/Info.plist" 2>/dev/null || true)
    if [ "$id" != "$BUNDLE_ID" ]; then
        say "keep $p (bundle id ${id:-unknown}, not ours)"
        return 0
    fi
    say "remove the App $p"
    if [ $DRY = 1 ]; then echo "  [dry-run] rm -rf $p"; else rm -rf "$p"; fi
}

# ---- stage: run from a root-only copy outside the App bundle
if [ $FINISH = 0 ] && [ $DRY = 0 ]; then
    BASE=/private/tmp
    [ $TESTING = 1 ] && BASE="$R/tmp" && mkdir -p "$BASE"
    STAGE=$(mktemp -d "$BASE/alwaysconnect-uninstall.XXXXXX") || { echo "== 卸载没有开始：无法创建临时目录"; exit 1; }
    chmod 700 "$STAGE"
    cp "$0" "$STAGE/uninstall.sh"
    HERE=$(cd "$(dirname "$0")" && pwd)
    [ -f "$HERE/reset-network.sh" ] && cp "$HERE/reset-network.sh" "$STAGE/reset-network.sh"
    ARGS=(--finish --stage "$STAGE")
    [ -n "$TARGET_USER" ] && ARGS+=(--user "$TARGET_USER")
    [ -n "$APP_PID" ] && ARGS+=(--app-pid "$APP_PID")
    [ -n "$APP_PATH" ] && ARGS+=(--app "$APP_PATH")
    [ $FROM_APP = 1 ] && ARGS+=(--from-app)
    [ $KEEP_SETTINGS = 1 ] && ARGS+=(--keep-settings)
    [ $KEEP_PASSWORD = 1 ] && ARGS+=(--keep-password)
    if [ $FROM_APP = 1 ]; then
        # Detached: the App is still running and quits once we return.
        /bin/bash "$STAGE/uninstall.sh" "${ARGS[@]}" </dev/null >/dev/null 2>&1 &
        echo "== 卸载已开始：AlwaysConnect 退出后几秒内完成。"
        exit 0
    fi
    exec /bin/bash "$STAGE/uninstall.sh" "${ARGS[@]}"
fi

echo "== AlwaysConnect 卸载 $( [ $DRY = 1 ] && echo '(dry-run)')"

# ---- 1 the App quits first: its own quit ends the VPN and the session
if [ -n "$APP_PID" ]; then
    for _ in $(seq 1 60); do kill -0 "$APP_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$APP_PID" 2>/dev/null; then
        say "the App did not quit within 60 s: stop it"
        [ $DRY = 1 ] || kill -9 "$APP_PID" 2>/dev/null || true
    fi
elif [ $TESTING = 0 ] && pgrep -x AlwaysConnect >/dev/null 2>&1; then
    say "ask AlwaysConnect to quit (VPN off, direct network)"
    as_user osascript -e "tell application id \"$BUNDLE_ID\" to quit" || true
    if [ $DRY = 0 ]; then
        for _ in $(seq 1 30); do pgrep -x AlwaysConnect >/dev/null 2>&1 || break; sleep 1; done
    fi
fi

# ---- 2 network back to direct, the background service kept unloaded
NET_OK=1
RESET="${STAGE:+$STAGE/reset-network.sh}"
[ -n "$RESET" ] && [ -f "$RESET" ] || RESET="$(cd "$(dirname "$0")" && pwd)/reset-network.sh"
if [ $TESTING = 1 ]; then
    echo "reset-network --keep-unloaded" >> "$R/commands.log"
elif [ -f "$RESET" ]; then
    say "restore the direct network"
    if [ $DRY = 1 ]; then
        /bin/bash "$RESET" --dry-run --keep-unloaded | sed 's/^/  /'
    else
        /bin/bash "$RESET" --keep-unloaded | sed 's/^/  /'
        [ "${PIPESTATUS[0]}" = 0 ] || NET_OK=0
    fi
else
    say "reset-network.sh not found: empty our pf anchor only"
    sys pfctl -a "$ANCHOR" -F all
fi
sys launchctl bootout "system/$LABEL"

# ---- 3 system files
remove "$R/Library/LaunchDaemons/$LABEL.plist"
remove "$R/Library/PrivilegedHelperTools/$LABEL"
remove "$R/Library/PrivilegedHelperTools/AlwaysConnect-openconnect"
remove "$R/Library/Application Support/AlwaysConnect"
remove "$R/Library/Logs/AlwaysConnect"

# ---- 4 the user's files
if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
    L="$USER_HOME/Library"
    remove "$L/Logs/AlwaysConnect"
    remove "$L/Application Support/AlwaysConnect"
    remove "$L/Caches/$BUNDLE_ID"
    remove "$L/HTTPStorages/$BUNDLE_ID"
    remove "$L/HTTPStorages/$BUNDLE_ID.binarycookies"
    remove "$L/WebKit/$BUNDLE_ID"
    remove "$L/Saved Application State/$BUNDLE_ID.savedState"
    # Left by the offscreen UI renderer of development builds.
    remove "$L/Preferences/group.com.alwaysconnect.render.plist"
    # The Desktop copy of the network reset, only if it is ours.
    DESK="$USER_HOME/Desktop/AlwaysConnect 恢复网络.command"
    if [ -f "$DESK" ] && grep -q "AlwaysConnect emergency network reset" "$DESK" 2>/dev/null; then
        remove "$DESK"
    fi
    if [ $KEEP_SETTINGS = 1 ]; then
        say "keep settings (servers, split list, preferences)"
    else
        # Through cfprefsd first, so no cached copy is written back.
        as_user defaults delete "$BUNDLE_ID" || true
        as_user defaults delete "group.$BUNDLE_ID" || true
        remove "$L/Preferences/$BUNDLE_ID.plist"
        remove "$L/Preferences/group.$BUNDLE_ID.plist"
        remove "$L/Group Containers/group.$BUNDLE_ID"
        remove "$L/Containers/$BUNDLE_ID"
    fi
    if [ $KEEP_PASSWORD = 1 ] || [ $FROM_APP = 1 ]; then
        [ $FROM_APP = 1 ] || say "keep the password in the keychain"
    else
        say "remove the password from the keychain"
        for _ in $(seq 1 20); do
            as_user security delete-generic-password -s "$KEYCHAIN_SERVICE" || break
            [ $TESTING = 1 ] || [ $DRY = 1 ] && break
        done
    fi
    # Privacy permissions given to the App (accessibility for the hotkey).
    as_user tccutil reset All "$BUNDLE_ID" || true
else
    say "no user home found: the user's files were not cleaned"
fi

# ---- 5 the App itself
[ -n "$APP_PATH" ] && remove_app "$APP_PATH"
[ "${APP_PATH%/}" = "$R/Applications/AlwaysConnect.app" ] || remove_app "$R/Applications/AlwaysConnect.app"

if [ $DRY = 1 ]; then
    echo "== dry-run done, nothing changed"
    exit 0
fi
if [ $NET_OK = 1 ]; then
    MSG="AlwaysConnect 已卸载，网络已恢复直连。"
else
    MSG="AlwaysConnect 已卸载；网页仍打不开，请检查 Wi-Fi 或网线，或重启电脑。"
fi
echo "== $MSG"
if [ $FROM_APP = 1 ]; then
    as_user osascript -e "display notification \"$MSG\" with title \"AlwaysConnect\"" || true
fi
# The staged copy goes last (bash already holds this file open).
case "$STAGE" in */alwaysconnect-uninstall.*) rm -rf "$STAGE";; esac
exit 0
