#!/bin/bash
# Builds the zip for a GitHub Release (DESIGN.md §三十三):
#   scripts/package-release.sh v0.2.0
# The tag must equal CFBundleShortVersionString in Sources/App/Info.plist
# with a leading "v": the App's update check compares the two, and a tag
# ahead of the bundle version would tell everyone on the new build that a
# newer one exists.
#
# Signed with the fixed self-signed identity "AlwaysConnect Local Dev"
# (scripts/dev-signing-identity.sh; DESIGN.md §35.5), not ad-hoc: an
# ad-hoc signature's designated requirement is the cdhash, new with every
# version, so every update asked again for the keychain password and
# certificate ("始终允许" did not carry over). With the same certificate
# on every release the requirement stays identifier + certificate leaf.
# It needs no trust and no developer account; Gatekeeper is not involved
# (install.sh downloads without quarantine). Keep that one identity for
# all releases; a new one costs every user one more keychain prompt.
# RELEASE_SIGN_IDENTITY=- packages ad-hoc on purpose.
#
# Writes .local-build/AlwaysConnect-<version>-macos-<arch>.zip, its
# .sha256 and AlwaysConnect-<version>-third-party-sources.tar.gz (the
# LGPL corresponding source, fetched and checked against SOURCES);
# publishing the Release stays a manual step.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:-}
PLIST_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$ROOT/Sources/App/Info.plist")
if [ -z "$TAG" ]; then
    echo "usage: $0 v$PLIST_VERSION" >&2
    exit 2
fi
if [ "$TAG" != "v$PLIST_VERSION" ]; then
    echo "tag $TAG does not match Info.plist CFBundleShortVersionString $PLIST_VERSION;" >&2
    echo "raise the version in Sources/App/Info.plist first (or tag v$PLIST_VERSION)" >&2
    exit 1
fi
IDENTITY=${RELEASE_SIGN_IDENTITY:-AlwaysConnect Local Dev}
if [ "$IDENTITY" != - ] && ! security find-identity -p codesigning | grep -q "\"$IDENTITY\""; then
    echo "signing identity \"$IDENTITY\" not found in the keychain." >&2
    echo "Releases must keep one identity: restore it, or (first release only) create it with" >&2
    echo "scripts/dev-signing-identity.sh; RELEASE_SIGN_IDENTITY=- packages ad-hoc." >&2
    exit 1
fi
SIGN_IDENTITY=$IDENTITY "$ROOT/scripts/build-local.sh"
APP="$ROOT/.local-build/AlwaysConnect.app"
if [ "$IDENTITY" != - ]; then
    codesign -d -r- "$APP" 2>&1 | grep -q 'certificate leaf' \
        || { echo "built App is not signed with a fixed certificate" >&2; exit 1; }
    # install.sh refuses any other signer (DESIGN.md §36.3): the release
    # certificate and its pin there must be the same.
    CERTS=$(mktemp -d)
    codesign -d --extract-certificates="$CERTS/c" "$APP" >/dev/null 2>&1
    LEAF=$(shasum -a 1 "$CERTS/c0" | awk '{print tolower($1)}')
    rm -rf "$CERTS"
    grep -q "ALWAYSCONNECT_RELEASE_SIGNER:-$LEAF}" "$ROOT/install.sh" || {
        echo "the App is signed with certificate $LEAF, but install.sh's RELEASE_SIGNER is another:" >&2
        echo "every installed copy would refuse this release. Sign with the release identity" >&2
        echo "(or, for a fork's first release, set RELEASE_SIGNER in install.sh)." >&2
        exit 1
    }
fi
# Nothing in the shipped files may name the builder (DESIGN.md §36.5):
# no home directory or user name in any string of any file.
LEAK=$(find "$APP" -type f -print0 | xargs -0 strings -a 2>/dev/null \
    | grep -F -e "$HOME" -e "/Users/$(id -un)" | sort -u | head -5 || true)
if [ -n "$LEAK" ]; then
    echo "the App contains the builder's paths; not packaging:" >&2
    echo "$LEAK" >&2
    exit 1
fi
BUILT=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")
[ "$BUILT" = "$PLIST_VERSION" ] || { echo "built App reports $BUILT, expected $PLIST_VERSION" >&2; exit 1; }
ARCH=$(uname -m)
ZIP="$ROOT/.local-build/AlwaysConnect-$PLIST_VERSION-macos-$ARCH.zip"
rm -f "$ZIP" "$ZIP.sha256"
ditto -c -k --keepParent "$APP" "$ZIP"
(cd "$(dirname "$ZIP")" && shasum -a 256 "$(basename "$ZIP")" > "$(basename "$ZIP").sha256")
echo "packaged $ZIP"
# LGPL: the corresponding source goes on the same Release as the App
# (DESIGN.md §34.2, §36.4), one archive of what openconnect/SOURCES lists.
SRC_DIR="$ROOT/.local-build/third-party-sources-$PLIST_VERSION"
SRC_TAR="$ROOT/.local-build/AlwaysConnect-$PLIST_VERSION-third-party-sources.tar.gz"
rm -rf "$SRC_DIR" "$SRC_TAR"
if "$ROOT/scripts/fetch-third-party-sources.sh" "$SRC_DIR" "$APP/Contents/Resources/openconnect/SOURCES"; then
    tar -czf "$SRC_TAR" -C "$(dirname "$SRC_DIR")" "$(basename "$SRC_DIR")"
    rm -rf "$SRC_DIR"
    echo "packaged $SRC_TAR"
else
    echo "third-party sources incomplete (see above): fix before publishing; the Release must carry them" >&2
    exit 1
fi
echo "next: gh release create $TAG \"$ZIP\" \"$ZIP.sha256\" \"$SRC_TAR\" (add --prerelease for a pre-release)"
