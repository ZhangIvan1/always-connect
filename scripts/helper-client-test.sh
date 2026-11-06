#!/bin/bash
# Who may talk to the root background service (DESIGN.md §36.3):
# only the App signed with the same certificate as the service.
# Binaries are signed with a real certificate (lib-test-identity.sh:
# the local dev identity, or a throwaway one in CI). A second
# certificate is stood in for by a requirement naming another leaf
# hash. The live XPC path (listener refusal, per-message audit-token
# check) needs the real Mac: mac-proof I21.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
# shellcheck source=scripts/lib-test-identity.sh
. "$ROOT/scripts/lib-test-identity.sh"
trap 'test_identity_cleanup; rm -rf "$WORK"' EXIT
FAILS=0
ok() { echo "PASS $1"; }
no() { echo "FAIL $1"; FAILS=$((FAILS+1)); }

swiftc -O -parse-as-library "$ROOT/Sources/Helper/ClientRequirement.swift" \
    "$ROOT/core/scripts/ClientRequirementTest.swift" -o "$WORK/test"
"$WORK/test" unit || FAILS=$((FAILS+1))

test_identity_setup "$WORK"
NAME=$TEST_SIGN_NAME

printf 'int main(void){return 0;}\n' > "$WORK/t.c"
cc "$WORK/t.c" -o "$WORK/bin"
sign() { # out identity id
    cp "$WORK/bin" "$WORK/$1"
    codesign --force --sign "$2" --identifier "$3" "$WORK/$1" 2>/dev/null
}
sign helperA "$NAME" com.alwaysconnect.app.helper
sign appA    "$NAME" com.alwaysconnect.app
sign otherA  "$NAME" com.example.other
sign appAdhoc - com.alwaysconnect.app
sign helperAdhoc - com.alwaysconnect.app.helper

REQ=$("$WORK/test" req "$WORK/helperA")
case "$REQ" in
    'identifier "com.alwaysconnect.app" and certificate leaf = H"'*) ok "self-signed service pins its own certificate" ;;
    *) no "requirement from a self-signed service: $REQ" ;;
esac
"$WORK/test" check "$WORK/appA" "$REQ" && ok "App with the same certificate is accepted" || no "same-certificate App refused"
OTHER=$(printf '%s' "$REQ" | sed -E 's/H"[0-9a-f]{40}"/H"0123456789abcdef0123456789abcdef01234567"/')
"$WORK/test" check "$WORK/appA" "$OTHER" && no "App accepted by a service with another certificate" || ok "another certificate is refused"
"$WORK/test" check "$WORK/otherA" "$REQ" && no "other program with the same certificate accepted" || ok "other identifier is refused"
"$WORK/test" check "$WORK/appAdhoc" "$REQ" && no "ad-hoc App accepted" || ok "ad-hoc App is refused"
[ "$("$WORK/test" req "$WORK/helperAdhoc")" = none ] && ok "ad-hoc service accepts nobody" || no "ad-hoc service derived a requirement"

[ $FAILS -eq 0 ] && echo "ALL PASS" || { echo "FAILS=$FAILS"; exit 1; }
