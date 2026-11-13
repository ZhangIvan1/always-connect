#!/bin/bash
# Inspect the packaged bytes, not only the build directory. No App is launched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:?version tag}
VERSION=${TAG#v}
ZIP="$ROOT/.local-build/AlwaysConnect-$VERSION-macos-arm64.zip"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$(dirname "$ZIP")" && shasum -a 256 -c "$(basename "$ZIP").sha256")
ditto -x -k "$ZIP" "$WORK"
APP="$WORK/AlwaysConnect.app"
PIN=$(sed -n 's/.*ALWAYSCONNECT_RELEASE_SIGNER:-\([0-9a-f]*\)}.*/\1/p' "$ROOT/install.sh")
[ ${#PIN} -eq 40 ]
codesign --verify --strict --deep -R="certificate leaf = H\"$PIN\"" "$APP"
ACTUAL=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")
[ "$ACTUAL" = "$VERSION" ]
for FILE in "$APP/Contents/MacOS/AlwaysConnect" \
    "$APP/Contents/Library/LaunchDaemons/AlwaysConnectHelper" \
    "$APP/Contents/Resources/openconnect/bin/openconnect"; do
    [ -x "$FILE" ]
    [ "$(lipo -archs "$FILE")" = arm64 ]
done
"$APP/Contents/Resources/openconnect/bin/openconnect" --version >/dev/null 2>&1
if otool -L "$APP/Contents/Resources/openconnect/bin/openconnect" \
    "$APP"/Contents/Resources/openconnect/lib/*.dylib | grep -Eq '/opt/homebrew|/usr/local|@rpath'; then
    echo 'Release depends on build-machine libraries' >&2; exit 1
fi
test -s "$ROOT/.local-build/AlwaysConnect-$VERSION-third-party-sources.tar.gz"
echo 'Packaged version, fixed signer, arm64 and bundled libraries verified'
