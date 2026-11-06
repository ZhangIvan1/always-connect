#!/bin/bash
# The macOS CI job's runtime checks, run against scripts/build-local.sh
# output (.local-build/). Same assertions as .github/workflows/ci.yml:
# engine smoke (no server), mock-gateway auth + cookie reuse, pf text
# generation, vpnc-script branches (test mode, no routes touched),
# harnesses. Needs Homebrew openconnect; touches no routes and no pf.
# Verification level: CI harness, run locally (AGENTS.md).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
HELPER=$REPO/.local-build/AlwaysConnectHelper
pass(){ echo "PASS $1"; }; fail(){ echo "FAIL $1"; FAILS=$((FAILS+1)); }; FAILS=0
# 1 smoke
rm -rf /tmp/ac-engine-test && mkdir -p /tmp/ac-engine-test
OUT=$(printf 'x\n' | "$HELPER" run-once --server https://127.0.0.1:9 --user nobody --max-attempts 2 --no-routes --cookie-store /tmp/ac-engine-test/session.json --support-dir /tmp/ac-engine-test 2>&1); E=$?
[ $E -eq 3 ] && echo "$OUT" | grep -q "STATE authenticating" && echo "$OUT" | grep -q "TERMINAL attempts-exhausted" && pass smoke || { fail smoke; echo "$OUT" | tail -20; }
# 2 mock gateway
D=/tmp/ac-mock; rm -rf $D; mkdir -p $D
openssl req -x509 -newkey rsa:2048 -keyout $D/ca-key.pem -out $D/ca-cert.pem -days 2 -nodes -subj "/CN=Mock Test CA" 2>/dev/null
openssl req -newkey rsa:2048 -keyout $D/server-key.pem -out $D/server.csr -nodes -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost" > $D/server.ext
openssl x509 -req -in $D/server.csr -CA $D/ca-cert.pem -CAkey $D/ca-key.pem -CAcreateserial -out $D/server-cert.pem -days 2 -extfile $D/server.ext 2>/dev/null
python3 "$REPO/core/scripts/mock-anyconnect.py" 4444 $D/server-cert.pem $D/server-key.pem $D/ca-cert.pem >$D/mock.log 2>&1 & MP=$!
for _ in $(seq 1 20); do nc -z 127.0.0.1 4444 2>/dev/null && break; sleep 0.5; done
rm -rf /tmp/ac-engine-test && mkdir -p /tmp/ac-engine-test
printf 'testpass\n' | "$HELPER" run-once --server https://127.0.0.1:4444 --user testuser --cafile $D/ca-cert.pem --max-attempts 3 --no-routes --debug-child-output --cookie-store /tmp/ac-engine-test/session.json --support-dir /tmp/ac-engine-test > /tmp/ac-engine-test/out.txt 2>&1 & RP=$!
( sleep 120; kill $RP 2>/dev/null ) & WP=$!
wait $RP; E=$?; kill $WP 2>/dev/null; kill $MP 2>/dev/null
O=/tmp/ac-engine-test/out.txt
[ "$E" = 3 ] && grep -q "credential password" $O && grep -q "credential cookie" $O && grep -q "TERMINAL attempts-exhausted" $O && grep -q mockcookie123 /tmp/ac-engine-test/session.json && pass mock-gateway || { fail "mock-gateway exit=$E"; tail -30 $O; }
grep -q 'testpass' $O && fail "password leaked into output" || pass "no-password-in-output"
# 2b established tunnel: hook -> connected, drop -> reconnecting, cookie reuse
rm -rf /tmp/ac-drop && mkdir -p /tmp/ac-drop
OUT=$(printf 'pw\n' | "$HELPER" run-once --server https://gw.invalid --user u --max-attempts 3 --no-routes --openconnect "$REPO/core/scripts/fake-openconnect.sh" --cookie-store /tmp/ac-drop/session.json --support-dir /tmp/ac-drop 2>&1); E=$?
[ $E -eq 3 ] && echo "$OUT" | grep -q "^STATE connected tunnel up" \
  && echo "$OUT" | grep -q "^STATE reconnecting dropped, retrying" \
  && echo "$OUT" | grep -q "^STATE reconnecting spawning openconnect (attempt 2, credential cookie)" \
  && grep -q fakecookie42 /tmp/ac-drop/session.json && pass drop-episode || { fail drop-episode; echo "$OUT" | grep -E "^(STATE|TERMINAL)"; }
# 2b an internal reconnect is reported as reconnecting, then connected (§28.1)
rm -rf /tmp/ac-irc; OUT=$(printf 'pw\n' | FAKE_INTERNAL_RECONNECT=1 "$HELPER" run-once --server https://gw.invalid --user u --max-attempts 1 --no-routes --openconnect "$REPO/core/scripts/fake-openconnect.sh" --cookie-store /tmp/ac-irc/session.json --support-dir /tmp/ac-irc 2>&1)
echo "$OUT" | grep -E "^STATE" | grep -A1 "隧道断了，正在重连" | grep -q "^STATE connected tunnel up" \
  && echo "$OUT" | grep -q "^STATE reconnecting 隧道断了，正在重连" && pass internal-reconnect \
  || { fail internal-reconnect; echo "$OUT" | grep -E "^(STATE|TERMINAL)"; }
# 3 pf
"$HELPER" generate-pf --phys en0 --tun utun5 --gateway 203.0.113.10 --allow 192.168.0.0/16 | grep -q "block drop out quick all" && \
"$HELPER" generate-pf --phys en0 --tun utun5 --gateway 203.0.113.10 --allow 192.168.0.0/16 --connected | grep -q "pass out quick on en0 all" && \
! "$HELPER" generate-pf --phys en0 --tun utun5 --allow 192.168.0.0/16 2>/dev/null && pass pf || fail pf
# 3b pfctl itself parses both sets under the real anchor (-n: no load, no root)
PFOK=1
for C in "" --connected --allow-dns "--dns 192.168.1.1,fd00::1 --direct-table"; do
  "$HELPER" generate-pf --phys en0 --tun utun5 --gateway 203.0.113.10 --allow 192.168.0.0/16 $C > /tmp/ac-pf.conf
  pfctl -n -a com.apple/300.AlwaysConnect -f /tmp/ac-pf.conf 2>/dev/null || PFOK=0
done
[ $PFOK = 1 ] && pass pfctl-parse || fail pfctl-parse
# 4 vpnc-script
S=/tmp/ac-vpnc-script.sh; "$HELPER" dump-script > $S; chmod +x $S
( export TUNDEV=utun9 VPNGATEWAY=10.0.0.1 ALWAYSCONNECT_NO_ROUTES=1
  head -1 $S | grep -q '#!/bin/sh' || exit 1
  env -u ALWAYSCONNECT_MANUAL_FLAG_PATH $S disconnect | grep -q 'AC_HOOK disconnect-held' || exit 2
  ALWAYSCONNECT_MANUAL_FLAG_PATH=/tmp/ac-manual-flag-missing $S disconnect | grep -q 'AC_HOOK disconnect-held' || exit 3
  touch /tmp/ac-manual-flag-present
  ALWAYSCONNECT_MANUAL_FLAG_PATH=/tmp/ac-manual-flag-present $S disconnect | grep -q 'AC_HOOK disconnect-manual' || exit 4
  rm -f /tmp/ac-manual-flag-present
  $S connect | grep -q 'AC_HOOK connect tun=utun9 gateway=10.0.0.1' || exit 5
  INTERNAL_IP4_DNS="8.8.8.8 1.1.1.1" $S connect | grep -q 'AC_HOOK connect tun=utun9 gateway=10.0.0.1 dns=8.8.8.8,1.1.1.1' || exit 6
  ALWAYSCONNECT_GATEWAY_IP=198.51.100.7 VPNGATEWAY=127.0.0.1 $S connect | grep -q 'gateway=198.51.100.7' || exit 8
  $S pre-init && $S attempt-reconnect && $S bogus-reason || exit 7 ) && pass vpnc-script || fail "vpnc-script rc=$?"
# 4b vpnc-script route plan (stubbed route/ifconfig/scutil, routes ON)
"$REPO/core/scripts/vpnc-route-plan-test.sh" $S > /tmp/ac-route-plan.log 2>&1 && pass vpnc-route-plan || { fail vpnc-route-plan; grep -v '^AC-SCRIPT' /tmp/ac-route-plan.log; }
# 4c Cisco engine against a fake Cisco CLI
"$REPO/scripts/cisco-engine-test.sh" > /tmp/ac-cisco-engine.log 2>&1 && pass cisco-engine || { fail cisco-engine; grep -E "MISSING|UNEXPECTED|error" /tmp/ac-cisco-engine.log; }
# 4d Cisco session traffic parser (no live Cisco required)
"$REPO/scripts/cisco-traffic-test.sh" && pass cisco-traffic || fail cisco-traffic
# 4d2 quit cleanup: ending every descendant process (§23.11)
"$REPO/scripts/process-sweep-test.sh" > /tmp/ac-process-sweep.log 2>&1 && pass process-sweep || { fail process-sweep; grep FAIL /tmp/ac-process-sweep.log || true; }
# 4d3 boot staleness: no blocking set from an earlier boot (§23.12)
# 4d3a who may drive the root background service (§36.3)
"$REPO/scripts/helper-client-test.sh" > /tmp/ac-helper-client.log 2>&1 && pass helper-client || { fail helper-client; grep -E "FAIL" /tmp/ac-helper-client.log || tail -5 /tmp/ac-helper-client.log; }
"$REPO/scripts/diagnostics-redaction-test.sh" > /tmp/ac-diag-redaction.log 2>&1 && pass diagnostics-redaction || { fail diagnostics-redaction; grep FAIL /tmp/ac-diag-redaction.log || true; }
"$REPO/scripts/boot-session-test.sh" > /tmp/ac-boot-session.log 2>&1 && pass boot-session || { fail boot-session; grep FAIL /tmp/ac-boot-session.log || true; }
# 4d4 drop history: episodes, outcomes, retries, old records (§21.22)
"$REPO/scripts/drop-history-test.sh" > /tmp/ac-drop-history.log 2>&1 && pass drop-history || { fail drop-history; grep FAIL /tmp/ac-drop-history.log || true; }
# 4d5 approval card: when it shows, updates, finishes, hides (§29)
"$REPO/scripts/approval-prompt-test.sh" > /tmp/ac-approval-prompt.log 2>&1 && pass approval-prompt || { fail approval-prompt; grep FAIL /tmp/ac-approval-prompt.log || true; }
"$REPO/scripts/list-rules-test.sh" > /tmp/ac-list-rules.log 2>&1 && pass list-rules || { fail list-rules; grep FAIL /tmp/ac-list-rules.log || true; }
"$REPO/scripts/neighbors-test.sh" > /tmp/ac-neighbors.log 2>&1 && pass neighbors || { fail neighbors; grep FAIL /tmp/ac-neighbors.log || true; }
"$REPO/scripts/connections-test.sh" > /tmp/ac-connections.log 2>&1 && pass connections || { fail connections; grep FAIL /tmp/ac-connections.log || true; }
"$REPO/scripts/uninstall-test.sh" > /tmp/ac-uninstall.log 2>&1 && pass uninstall || { fail uninstall; grep FAIL /tmp/ac-uninstall.log || true; }
"$REPO/scripts/connection-check-test.sh" > /tmp/ac-connection-check.log 2>&1 && pass connection-check || { fail connection-check; grep FAIL /tmp/ac-connection-check.log || true; }
"$REPO/scripts/update-check-test.sh" > /tmp/ac-update-check.log 2>&1 && pass update-check || { fail update-check; grep FAIL /tmp/ac-update-check.log || true; }
"$REPO/scripts/install-test.sh" > /tmp/ac-install.log 2>&1 && pass install-script || { fail install-script; grep FAIL /tmp/ac-install.log || true; }
# 4d4 background-service lifecycle: disconnect / release paths (§二十五)
"$REPO/scripts/session-test.sh" > /tmp/ac-session.log 2>&1 && pass session || { fail session; grep -E "^FAIL|^==" /tmp/ac-session.log || true; }
# 4f DNS forwarder for the domain split (DESIGN.md §26.4), loopback fake upstreams
"$REPO/scripts/dns-forwarder-test.sh" > /tmp/ac-dns-forwarder.log 2>&1 && pass dns-forwarder || { fail dns-forwarder; grep -E "^FAIL" /tmp/ac-dns-forwarder.log; }
# 4e certificate relay: framing, local mutual TLS, engine through the relay
"$REPO/scripts/relay-test.sh" "$HELPER" > /tmp/ac-relay.log 2>&1 && pass relay || { fail relay; grep -E "^FAIL|SKIP" /tmp/ac-relay.log; }
"$REPO/scripts/approval-wait-test.sh" "$HELPER" > /tmp/ac-approval-wait.log 2>&1 && pass approval-wait || { fail approval-wait; grep -E "^FAIL|SKIP|^(STATE|TERMINAL)" /tmp/ac-approval-wait.log; }
# 4g third-party notices (DESIGN.md §三十四): Rust list matches Cargo.lock,
# and the built App carries the notices, licence texts and source list.
"$REPO/scripts/make-rust-notices.sh" --check > /tmp/ac-notices.log 2>&1 && pass rust-notices || { fail rust-notices; cat /tmp/ac-notices.log; }
RES=$REPO/.local-build/AlwaysConnect.app/Contents/Resources
NOK=1
for f in THIRD_PARTY_NOTICES.md RESPONSIBLE-USE.md LICENSE.txt third_party/rust-crates.txt third_party/licenses/LGPL-2.1.txt \
         third_party/licenses/v2fly-domain-list-community.txt; do [ -s "$RES/$f" ] || { echo "  missing $f"; NOK=0; }; done
if [ -x "$RES/openconnect/bin/openconnect" ]; then
  for f in SOURCES README-LGPL.txt licenses/LGPL-2.1.txt licenses/LGPL-3.0.txt licenses/GPL-2.0.txt licenses/GPL-3.0.txt; do
    [ -s "$RES/openconnect/$f" ] || { echo "  missing openconnect/$f"; NOK=0; }; done
  # Every bundled library has a source line.
  grep -q "^openconnect .* https://" "$RES/openconnect/SOURCES" || { echo "  no openconnect source line"; NOK=0; }
fi
[ $NOK = 1 ] && pass app-notices || fail app-notices
grep -q "^SKIP" /tmp/ac-relay.log && echo "  (relay skipped: $(grep ^SKIP /tmp/ac-relay.log))" || true
echo "FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
