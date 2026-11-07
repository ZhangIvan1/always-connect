#!/bin/bash
# Script-level assertions with codesign stubbed. Real signature coverage lives
# in install-test.sh; this harness needs neither a keychain nor a signing identity.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
cat >"$WORK/bin/codesign" <<'STUB'
#!/bin/bash
# No installed certificate: use install.sh's release signer.
[ "$1" != -d ] || exit 1
# Simulate a valid but differently signed final copy. Only a pinned
# requirement rejects it; generic integrity verification would accept it.
pin=0 last=""
for last in "$@"; do
    case "$last" in -R=*'certificate leaf'*) pin=1 ;; esac
done
if [ "${AC_TAMPER_FINAL:-0}" = 1 ] && [ "$last" = "${AC_FINAL_DEST:-}" ] && [ "$pin" = 1 ]; then
    exit 1
fi
exit 0
STUB
chmod +x "$WORK/bin/codesign"
export PATH="$WORK/bin:$PATH"
app() {
    mkdir -p "$1/Contents/MacOS"
    cat >"$1/Contents/Info.plist" <<PLIST
<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.alwaysconnect.app</string>
<key>CFBundleShortVersionString</key><string>$2</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
PLIST
}
DEST="$WORK/Installed.app"
NEW="$WORK/New.app"
expect() { # status pattern args...
    local want=$1 pattern=$2 status=0 output
    shift 2
    output=$(/bin/bash "$ROOT/install.sh" --from "$NEW" --app "$DEST" --no-open "$@" 2>&1) || status=$?
    if { [ "$want" = pass ] && [ "$status" = 0 ]; } || { [ "$want" = fail ] && [ "$status" != 0 ]; }; then
        echo "$output" | grep -q "$pattern" || { echo "FAIL expected message: $pattern; output: $output"; exit 1; }
    else echo "FAIL expected $want: $output"; exit 1; fi
    echo "PASS $pattern"
}
app "$DEST" 1.3.0
app "$NEW" 1.2.3
expect fail 拒绝降级 --expected-version 1.2.3
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$DEST/Contents/Info.plist")" = 1.3.0 ]
expect pass 已安装 --expected-version 1.2.3 --allow-downgrade
expect fail 版本与发布版本不符 --expected-version 99.0.0
expect fail 缺少期望版本
app "$NEW" 1.2.3-beta.1
expect fail 拒绝降级 --expected-version 1.2.3-beta.1
expect pass 已安装 --expected-version 1.2.3-beta.1 --allow-downgrade
app "$NEW" 1.2.3-beta.10
expect pass 已安装 --expected-version 1.2.3-beta.10
app "$NEW" 1.2.3-beta.2
expect fail 拒绝降级 --expected-version 1.2.3-beta.2
app "$NEW" 1.2.3
expect pass 已安装 --expected-version 1.2.3
app "$NEW" invalid
expect fail 版本号无效 --expected-version invalid
app "$NEW" 1.2.4
AC_TAMPER_FINAL=1 AC_FINAL_DEST="$DEST" expect fail 复制后校验不通过 --expected-version 1.2.4
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$DEST/Contents/Info.plist")" = 1.2.3 ]
echo 'PASS final signer mismatch restores installed App'
cat >"$WORK/bin/ditto" <<'STUB'
#!/bin/bash
/usr/bin/ditto "$@" || exit $?
last=""
for last in "$@"; do :; done
if [ "$last" = "$AC_VERSION_DEST" ]; then
    /usr/libexec/PlistBuddy -c 'Set :CFBundleShortVersionString 1.0.0' "$last/Contents/Info.plist"
fi
STUB
chmod +x "$WORK/bin/ditto"
AC_VERSION_DEST="$DEST" expect fail 复制后校验不通过 --expected-version 1.2.4
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$DEST/Contents/Info.plist")" = 1.2.3 ]
echo 'PASS final version mismatch restores installed App'
echo 'install-policy-test: all passed (codesign stubbed)'
