#!/bin/bash
# Own connection: the phone-approval wait (DESIGN.md §30.9), with the
# REAL openconnect client against the mock gateway, which holds its
# answer to the password the way the company gateway does while it
# waits for the phone. Needs a built background service
# (.local-build/AlwaysConnectHelper) and openconnect on PATH (Homebrew,
# the same build the App bundles). Touches no routes, no pf, no tun.
#
#   scripts/approval-wait-test.sh [AlwaysConnectHelper]
#
#   approved  answer after 6 s           -> awaiting-approval, then on
#   quick     answer at once             -> never awaiting-approval
#   expired   "Login failed." after 4 s  -> asked again, not stopped
#   rejected  "Login failed." at once    -> stops (anti-lockout)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
HELPER=${1:-$REPO/.local-build/AlwaysConnectHelper}
[ -x "$HELPER" ] || { echo "FAIL build first (scripts/build-local.sh)"; exit 1; }
command -v openconnect >/dev/null || { echo "SKIP no openconnect on PATH"; exit 0; }
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
openssl req -x509 -newkey rsa:2048 -keyout "$W/ca-key.pem" -out "$W/ca.pem" -days 2 -nodes -subj "/CN=Mock Test CA" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$W/key.pem" -out "$W/csr" -nodes -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost" > "$W/ext"
openssl x509 -req -in "$W/csr" -CA "$W/ca.pem" -CAkey "$W/ca-key.pem" -CAcreateserial -out "$W/cert.pem" -days 2 -extfile "$W/ext" 2>/dev/null
FAILS=0
check() { if [ "$2" = yes ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }
has() { grep -q -- "$1" "$W/$2.out" && echo yes || echo no; }
hasnt() { grep -q -- "$1" "$W/$2.out" && echo no || echo yes; }

# run <name> <port> <attempts> <mock flags...>: engine output in $W/<name>.out
run() {
    local name=$1 port=$2 attempts=$3; shift 3
    python3 -I "$REPO/core/scripts/mock-anyconnect.py" "$port" "$W/cert.pem" "$W/key.pem" "$W/ca.pem" "$@" \
        > "$W/$name.mock" 2>&1 &
    local mp=$!
    for _ in $(seq 1 20); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.3; done
    mkdir -p "$W/$name"
    ( printf 'testpass\n' | ALWAYSCONNECT_TEST_APPROVAL_MIN=2 ALWAYSCONNECT_TEST_PUSH_BACKOFF=1 \
        "$HELPER" run-once --server "https://127.0.0.1:$port" --user testuser --cafile "$W/ca.pem" \
        --max-attempts "$attempts" --no-routes --cookie-store "$W/$name/session.json" --support-dir "$W/$name" \
        > "$W/$name.out" 2>&1 ) &
    local rp=$!
    ( sleep 60; kill $rp 2>/dev/null ) & local wp=$!
    wait $rp 2>/dev/null; kill $wp $mp 2>/dev/null; wait $mp 2>/dev/null
}

run approved 4471 1 --approval-hold 6
check "approved: the held password shows as waiting for the phone" "$(has '^STATE awaiting-approval' approved)"
check "approved: the answer ends the wait" "$(grep -A1 '^STATE awaiting-approval' "$W/approved.out" | grep -q 'approval answered' && echo yes || echo no)"
check "approved: not taken as a rejected password" "$(hasnt 'TERMINAL auth-failure' approved)"

run quick 4472 1
check "quick: an instant answer never shows as an approval wait" "$(hasnt 'awaiting-approval' quick)"

run expired 4473 2 --approval-expire 4
check "expired: shown as waiting first" "$(has '^STATE awaiting-approval' expired)"
check "expired: the approval is asked for again" "$(has '手机上的批准已超时' expired)"
check "expired: a second login follows" "$(has 'spawning openconnect (attempt 2' expired)"
check "expired: never stopped as a rejected password" "$(hasnt 'TERMINAL auth-failure' expired)"

run rejected 4474 3 --reject-password
check "rejected: a wrong password still stops at once" "$(has 'TERMINAL auth-failure' rejected)"
check "rejected: never shown as an approval wait" "$(hasnt 'awaiting-approval' rejected)"
check "rejected: no second try (anti-lockout)" "$(hasnt 'attempt 2' rejected)"

grep -q testpass "$W"/*.out && check "password never in the output" no || check "password never in the output" yes
[ $FAILS -eq 0 ] || for f in "$W"/*.out; do echo "== $f"; grep -E '^(STATE|TERMINAL)' "$f"; done
echo "approval-wait FAILS=$FAILS"
[ $FAILS -eq 0 ]
