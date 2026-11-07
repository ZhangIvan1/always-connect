#!/bin/bash
# Script assertions only: never run the generated privileged bootstrap.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/AppIdentity.swift" "$ROOT/Sources/App/AdminScript.swift" \
    "$ROOT/Sources/App/PrivilegedBundle.swift" "$ROOT/core/scripts/PrivilegedBundleTest.swift" -o "$WORK/test"
"$WORK/test" "$WORK/bootstrap.sh"
bash -n "$WORK/bootstrap.sh"
echo 'PASS bootstrap shell syntax (not executed)'
# An ad-hoc bundle cannot satisfy the root bootstrap's certificate pin.
APP="$WORK/AlwaysConnect.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
printf 'int main(void){return 0;}' | cc -x c - -o "$APP/Contents/MacOS/AlwaysConnect"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.alwaysconnect.app</string>
<key>CFBundleExecutable</key><string>AlwaysConnect</string>
</dict></plist>
PLIST
echo 'exit 0' >"$APP/Contents/Resources/dev-helper.sh"
codesign --force --sign - "$APP" 2>/dev/null
if codesign --verify --strict --deep -R='certificate leaf = H"0123456789abcdef0123456789abcdef01234567"' "$APP" 2>/dev/null; then
    echo 'FAIL ad-hoc bundle accepted by certificate pin'; exit 1
fi
echo 'PASS ad-hoc snapshot refused by real codesign requirement'
echo 'changed' >>"$APP/Contents/Resources/dev-helper.sh"
if codesign --verify --strict --deep "$APP" 2>/dev/null; then
    echo 'FAIL changed resource accepted'; exit 1
fi
echo 'PASS changed bundled script refused by real codesign verification'
