#!/bin/bash
# No administrator operation: only a harmless AppleScript return in a test binary.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
. "$ROOT/scripts/lib-test-identity.sh"
trap 'test_identity_cleanup; rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/AppIdentity.swift" \
    "$ROOT/Sources/App/AdminScript.swift" "$ROOT/core/scripts/AdminParentTest.swift" -o "$WORK/test"
codesign --force --sign - --identifier com.alwaysconnect.app "$WORK/test" 2>/dev/null
"$WORK/test"
echo 'PASS same ad-hoc parent accepted'
if "$WORK/test" --admin-script </dev/null; then echo 'FAIL external parent accepted'; exit 1; fi
echo 'PASS external parent refused before reading script'
[ "${1:-}" != --adhoc-only ] || exit 0
test_identity_setup "$WORK"
codesign --force --sign "$TEST_SIGN_NAME" --identifier com.alwaysconnect.app "$WORK/test" 2>/dev/null
"$WORK/test"
echo 'PASS same certificate parent accepted'
cp "$WORK/test" "$WORK/other"
"$WORK/test" "$WORK/other"
echo 'PASS same signer at another path refused'
codesign --force --sign - --identifier com.alwaysconnect.app "$WORK/other" 2>/dev/null
"$WORK/test" "$WORK/other"
echo 'PASS another signature refused'
