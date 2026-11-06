#!/bin/bash
# Local build without Xcode (DESIGN.md §二十): Command Line Tools only.
#
# Compiles the Rust staticlib and the four Swift targets with swiftc,
# then assembles .local-build/AlwaysConnect.app the way project.yml's
# "Embed Helper daemon" phase does (Helper + launchd plist under
# Contents/Library/LaunchDaemons). The transparent proxy is compiled
# as a check but not embedded: it needs the Network Extension
# entitlement, i.e. a paid developer team.
#
# Signing: with the local identity from scripts/dev-signing-identity.sh
# when present, so "Always Allow" on the keychain item survives rebuilds
# (DESIGN.md §21.15); ad-hoc otherwise. Neither has a team identifier.
# Set SIGN_IDENTITY to a codesigning identity to sign with a real team;
# only then can SMAppService install the Helper and the Helper's team
# check mean anything.
#
# Usage: scripts/build-local.sh            build everything
#        scripts/build-local.sh --tests    build, then run the CI-equivalent
#                                          Helper / vpnc-script / harness checks
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/.local-build"
SRC="$ROOT/Sources"
LIB="$ROOT/core/target/release/libalwaysconnect_core.a"
DEPLOY=13.0
ARCH=$(uname -m)
SWIFTC=(swiftc -target "$ARCH-apple-macos$DEPLOY" -sdk "$(xcrun --show-sdk-path)" -O)

mkdir -p "$OUT"
echo "== Rust staticlib"
# A Homebrew Rust ships its std built for the host macOS, so the link
# warns "built for newer macOS": fine for running on this Mac, not for
# shipping to older ones (release builds go through CI's toolchain).
# Panic locations embed source paths; under the builder's home they name
# the user (DESIGN.md §36.5). Map the home directory and the crate
# registry to neutral prefixes (the more specific mapping last: rustc
# applies the last one that matches).
CARGO_DIR=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build --remap-path-prefix=$CARGO_DIR/registry/src=/cargo/registry/src"
(cd "$ROOT/core" && cargo build --release --quiet)

# swiftc, minus the Homebrew-std "built for newer macOS" link noise.
sw() {
    local log rc=0
    log=$(mktemp)
    "${SWIFTC[@]}" "$@" >"$log" 2>&1 || rc=$?
    grep -v "was built for newer 'macOS' version" "$log" || true
    rm -f "$log"
    return $rc
}

echo "== Swift targets"
sw -module-name AlwaysConnectHelper \
    "$SRC"/Helper/*.swift "$SRC"/Shared/*.swift "$LIB" -o "$OUT/AlwaysConnectHelper"
# The App links the staticlib too: the certificate relay's plaintext
# side and DTLS channel are Rust (DESIGN.md §32.7).
sw -parse-as-library -module-name AlwaysConnect \
    "$SRC"/App/*.swift "$SRC"/Shared/*.swift "$LIB" -o "$OUT/AlwaysConnect"

echo "== App bundle"
APP="$OUT/AlwaysConnect.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Library/LaunchDaemons"
cp "$OUT/AlwaysConnect" "$APP/Contents/MacOS/AlwaysConnect"
sed -e 's/$(EXECUTABLE_NAME)/AlwaysConnect/' \
    -e 's/$(PRODUCT_BUNDLE_IDENTIFIER)/com.alwaysconnect.app/' \
    -e 's/$(PRODUCT_NAME)/AlwaysConnect/' \
    -e "s/\$(MACOSX_DEPLOYMENT_TARGET)/$DEPLOY/" \
    "$SRC/App/Info.plist" > "$APP/Contents/Info.plist"
cp "$OUT/AlwaysConnectHelper" "$APP/Contents/Library/LaunchDaemons/AlwaysConnectHelper"
cp "$SRC/App/AlwaysConnectHelper.plist" \
    "$APP/Contents/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist"
# The App installs/updates the Helper itself through this script when
# it has no developer-team signature (DESIGN.md §21.8).
mkdir -p "$APP/Contents/Resources"
cp "$ROOT/scripts/dev-helper.sh" "$APP/Contents/Resources/dev-helper.sh"
# The split list's site lists and geoip data (scripts/make-geo-data.py).
cp "$SRC"/App/GeoData/*.txt "$APP/Contents/Resources/"
# App icon (scripts/make-app-icon.swift draws it from the menu-bar globe).
cp "$SRC/App/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
# Emergency network reset, usable without the App (DESIGN.md §24.6).
cp "$ROOT/scripts/reset-network.sh" "$APP/Contents/Resources/reset-network.sh"
# Clean uninstall, from Settings or a terminal (DESIGN.md §31).
cp "$ROOT/scripts/uninstall.sh" "$APP/Contents/Resources/uninstall.sh"
# Licences and third-party notices travel with every copy (DESIGN.md §三十四).
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE.txt"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$ROOT/RESPONSIBLE-USE.md" "$APP/Contents/Resources/"
rm -rf "$APP/Contents/Resources/third_party"
cp -R "$ROOT/third_party" "$APP/Contents/Resources/third_party"
# One-click update runs the same script as the one-line install (§三十五).
cp "$ROOT/install.sh" "$APP/Contents/Resources/install.sh"
plutil -lint -s "$APP/Contents/Info.plist" \
    "$APP/Contents/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist"

# Inside-out: the embedded Helper first, then the bundle. No
# entitlements: the App is not sandboxed, so its App Groups suite is a
# plain preferences domain and needs none to work locally.
LOCAL_IDENTITY="AlwaysConnect Local Dev"
if [ -z "${SIGN_IDENTITY:-}" ] &&
    security find-identity -p codesigning | grep -q "\"$LOCAL_IDENTITY\""; then
    SIGN_IDENTITY=$LOCAL_IDENTITY
fi
IDENTITY=${SIGN_IDENTITY:--}
# The App's own openconnect and libraries (DESIGN.md §27.3): users need
# no Homebrew. The build machine does (brew install openconnect).
if ! "$ROOT/scripts/bundle-openconnect.sh" "$APP/Contents/Resources/openconnect" "$IDENTITY" >/tmp/ac-bundle-oc.log 2>&1; then
    echo "warning: openconnect not bundled (see /tmp/ac-bundle-oc.log)" >&2
fi
codesign --force --options runtime --sign "$IDENTITY" \
    --identifier com.alwaysconnect.app.helper \
    "$APP/Contents/Library/LaunchDaemons/AlwaysConnectHelper"
codesign --force --options runtime --sign "$IDENTITY" "$APP"
codesign --verify --strict "$APP"
echo "built $APP (signed: $IDENTITY)"
if [ "$IDENTITY" = - ]; then
    echo "warning: ad-hoc signed: the background service accepts no App without a signing certificate" >&2
    echo "         (DESIGN.md §36.3); run scripts/dev-signing-identity.sh once, then rebuild" >&2
fi

if [ "${1:-}" = "--tests" ]; then
    "$ROOT/scripts/local-checks.sh"
fi
