#!/bin/bash
# Certificate relay harness (DESIGN.md §二十三). Loopback and test
# certificates only: no keychain, no administrator, no real gateway.
#
#   1 framing      gateway address choice and URL unit checks (CSTP,
#                  CONNECT and login-trace units: cargo test, §32.7)
#   2 records      relay end to end: fragmented CONNECT, then one TLS
#                  record per CSTP packet in both directions; the fixture
#                  gateway demands the "company" client certificate
#   3 local mTLS   the relay refuses no certificate and a foreign one
#   3b DTLS        the CONNECT's DTLS offer loses PSK-NEGOTIATE, the
#                  answer's X-DTLS-Port points at the relay, datagrams
#                  go through both ways unchanged (§26.10)
#   3c renewal     an expired automatic choice is swapped for the newest
#                  valid certificate at the next connection; one still
#                  valid is kept (§45)
#   4 engine       the Helper's openconnect engine through the relay
#                  against the mock gateway that demands a client
#                  certificate: login, cookie capture and cookie reuse
#
# Usage: scripts/relay-test.sh [path/to/AlwaysConnectHelper]
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER=${1:-$ROOT/.local-build/AlwaysConnectHelper}
W=$(mktemp -d /tmp/ac-relay.XXXXXX)
# The relay's log goes here, not into the user's ~/Library/Logs.
export ALWAYSCONNECT_RELAY_LOG="$W/relay.log"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    rm -rf "$W"
}
trap cleanup EXIT
FAILS=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
ssl() { /usr/bin/openssl "$@" >/dev/null 2>&1; }

# The relay's plaintext side and DTLS channel are Rust (§32.7); their
# unit checks are cargo tests (core/src/relay.rs).
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -parse-as-library -module-name RelayHarness \
    "$ROOT/Sources/App/CertificateRelay.swift" "$ROOT/Sources/Shared/GatewayAddress.swift" \
    "$ROOT/core/scripts/RelayHarness.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" \
    -o "$W/RelayHarness" 2>&1 | grep -v -e warning -e "built for newer" || true
[ -x "$W/RelayHarness" ] || { echo "FAIL relay harness build"; exit 1; }

# 1
"$W/RelayHarness" framing || FAILS=$((FAILS + 1))

# Test PKI: a CA standing in for the company's, the gateway's server
# certificate, the "company" client identity (PKCS#12, as the keychain
# would hold it) and an unrelated client certificate.
D=$W/pki; mkdir -p "$D"; cd "$D" || exit 1
ssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Relay Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.pem
ssl x509 -in ca.pem -outform DER -out ca.der
issue() { # name usage
    ssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr"
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=%s\n' "$2" > "$1.ext"
    ssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile "$1.ext" -out "$1.pem"
}
issue gateway serverAuth
issue company clientAuth
issue stranger clientAuth
for who in company stranger; do
    ssl pkcs12 -export -inkey "$who.key" -in "$who.pem" -out "$who.p12" -passout pass:test \
        -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
done
# The certificate the Helper gives openconnect (and the App's relay).
"$HELPER" relay-client-cert --support-dir "$W/support" > relay-client.pem
cp "$W/support/relay/client.key" relay-client.key
[ -s relay-client.pem ] && [ -s relay-client.key ] || { echo "FAIL relay client identity"; exit 1; }

start_relay() { # listen upstream [identity.p12 [renewal.p12]] -> sets RELAY_IP RELAY_PIN
    "$W/RelayHarness" relay "${3:-company.p12}" test ca.der "$1" "$2" relay-client.pem ${4:+"$4"} \
        > "$W/relay-$1.out" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 40); do grep -q "^READY\|^SKIP" "$W/relay-$1.out" && break; sleep 0.25; done
    if grep -q "^SKIP" "$W/relay-$1.out"; then echo "SKIP relay: $(cat "$W/relay-$1.out")"; exit 0; fi
    read -r _ RELAY_IP RELAY_PIN < <(grep "^READY" "$W/relay-$1.out")
    [ -n "${RELAY_PIN:-}" ] || { echo "FAIL relay start: $(cat "$W/relay-$1.out")"; exit 1; }
}

# 2 + 3
start_relay 4461 4462
python3 -I "$ROOT/core/scripts/relay-framing-check.py" frames 4461 4462 "$D" || FAILS=$((FAILS + 1))
python3 -I "$ROOT/core/scripts/relay-framing-check.py" dtls 4461 4462 "$D" || FAILS=$((FAILS + 1))
for who in relay-client none stranger company; do
    python3 -I "$ROOT/core/scripts/relay-framing-check.py" access 4461 4462 "$D" "$who" || FAILS=$((FAILS + 1))
done

# 3c: the relay starts with "stranger" standing in for the certificate
# that has since expired; "company" is the renewal in the keychain.
start_relay 4465 4466 stranger.p12 company.p12
python3 -I "$ROOT/core/scripts/relay-framing-check.py" presents 4465 4466 "$D" company || FAILS=$((FAILS + 1))
grep -q "client certificate expired: switched" "$W/relay.log" &&
    pass "relay log records the switch" || fail "relay log: no switch recorded"
# Control: a certificate that has not expired is kept.
start_relay 4467 4468 stranger.p12
python3 -I "$ROOT/core/scripts/relay-framing-check.py" presents 4467 4468 "$D" stranger || FAILS=$((FAILS + 1))

# 4
python3 -I "$ROOT/core/scripts/mock-anyconnect.py" 4464 gateway.pem gateway.key ca.pem \
    --require-client-cert > "$W/mock.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 20); do nc -z 127.0.0.1 4464 2>/dev/null && break; sleep 0.5; done
start_relay 4463 4464
[ "$RELAY_IP" = 127.0.0.1 ] && pass "relay pins the gateway's IPv4" || fail "relay gateway ip: $RELAY_IP"
# ALWAYSCONNECT_TEST_OPENCONNECT: run the engine with that openconnect
# (CI points it at the App's bundled copy, DESIGN.md §27.3).
OCARG=(); [ -n "${ALWAYSCONNECT_TEST_OPENCONNECT:-}" ] && OCARG=(--openconnect "$ALWAYSCONNECT_TEST_OPENCONNECT")
printf 'testpass\n' | "$HELPER" run-once --server https://localhost:4463 --user testuser ${OCARG[@]+"${OCARG[@]}"} \
    --relay-ip "$RELAY_IP" --relay-pin "$RELAY_PIN" --max-attempts 3 --no-routes --debug-child-output \
    --cookie-store "$W/session.json" --support-dir "$W/support" > "$W/engine.out" 2>&1 &
RP=$!
( sleep 120; kill $RP 2>/dev/null ) & WP=$!
wait $RP; E=$?; kill $WP 2>/dev/null; wait $WP 2>/dev/null
O=$W/engine.out
[ "$E" = 3 ] && grep -q "credential password" "$O" && grep -q "credential cookie" "$O" &&
    grep -q mockcookie123 "$W/session.json" &&
    pass "engine logs in through the relay and reuses the cookie" ||
    { fail "engine through relay exit=$E"; tail -30 "$O"; tail -20 "$W/mock.log"; }
grep -q "MOCK client certificate verified" "$W/mock.log" &&
    pass "mock gateway saw the company certificate on the relayed connections" ||
    fail "mock gateway client certificate"
grep -q 'testpass' "$O" && fail "password leaked into output" || pass "no password in engine output"
# §30.9: the login's shape is in the relay log, nothing the user typed.
grep -q "login: POST with the password sent" "$W/relay.log" &&
    grep -qE "login: POST \(password\) answered after [0-9.]+s: 200 auth=success" "$W/relay.log" &&
    pass "relay log traces the login (password answered, auth=success)" ||
    { fail "relay login trace"; grep "login:" "$W/relay.log" | head; }
grep -qE 'testpass|mockcookie123|webvpn=' "$W/relay.log" && fail "relay log leaked a secret" ||
    pass "relay log carries no password or cookie"
# Straight to the mock without the relay: refused for want of a certificate.
printf 'testpass\n' | "$HELPER" run-once --server https://127.0.0.1:4464 --user testuser --cafile ca.pem \
    --max-attempts 1 --no-routes --cookie-store "$W/direct.json" --support-dir "$W/direct" > "$W/direct.out" 2>&1
grep -q "credential password" "$W/direct.out" && ! grep -q mockcookie123 "$W/direct.json" 2>/dev/null &&
    pass "without the relay the gateway refuses openconnect" || fail "direct login unexpectedly worked"

echo "relay FAILS=$FAILS"
[ "$FAILS" = 0 ]
