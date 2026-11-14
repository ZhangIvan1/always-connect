#!/bin/bash
# Cisco engine harness (DESIGN.md §21.4): compiles Sources/App/
# CiscoEngine.swift with core/scripts/CiscoEngineHarness.swift and runs
# it against core/scripts/fake-cisco-vpn.sh. Asserts the state, kill
# switch and terminal sequence for connect, drop + re-login, manual
# disconnect, rejected login (no retry), transient failure + retry,
# and adopting an already-connected session. Touches nothing real.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
export FAKE_CISCO_DIR=$WORK
# The engine is Rust (DESIGN.md §32.11); CiscoEngine.swift is its shell.
(cd "$ROOT/core" && cargo build --release --quiet) || exit 1
swiftc -O -parse-as-library -module-name CiscoHarness \
    "$ROOT/Sources/Shared/PhysicalConnectivity.swift" "$ROOT/Sources/App/CiscoEngine.swift" "$ROOT/core/scripts/CiscoEngineHarness.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/harness" 2>&1 | grep -v "built for newer"
[ -x "$WORK/harness" ] || exit 1
OUT=$("$WORK/harness" "$ROOT/core/scripts/fake-cisco-vpn.sh")
echo "$OUT"
FAILS=0
section() { echo "$OUT" | awk -v s="STEP $1" -v e="STEP $2" '$0 ~ s {p=1; next} $0 ~ e {p=0} p'; }
need() { echo "$2" | grep -q -- "$3" || { echo "MISSING in $1: $3"; FAILS=$((FAILS+1)); }; }
none() { ! echo "$2" | grep -q -- "$3" || { echo "UNEXPECTED in $1: $3"; FAILS=$((FAILS+1)); }; }
S=$(section connect drop)
need connect "$S" "state=authenticating"
need connect "$S" "state=awaitingApproval"
need connect "$S" "state=connected"
need connect "$S" "killswitch=1 gw=198.51.100.9"
S=$(section drop manual-disconnect)
need drop "$S" "killswitch=2"
need drop "$S" "state=reconnecting"
need drop "$S" "state=connected"
need drop "$S" "killswitch=1"
S=$(section manual-disconnect rejected)
need manual "$S" "state=disconnected manual disconnect"
need manual "$S" "terminal=1"
S=$(section rejected transient-then-good)
need rejected "$S" "terminal=2"
need rejected "$S" "账号或密码被拒绝"
none rejected "$S" "秒后重试"
S=$(section transient-then-good approval-expired)
need transient "$S" "秒后重试"
need transient "$S" "state=connected"
S=$(section approval-expired quick-login-failed)
need approval-expired "$S" "手机上的批准已超时，"
need approval-expired "$S" "后重新发起批准"
none approval-expired "$S" "terminal=2"
S=$(section quick-login-failed pushed-failure)
need quick-login-failed "$S" "terminal=2"
S=$(section pushed-failure adopt-on-refresh)
# A failure after the password went in (phone pushed) backs off >= 24 s.
echo "$S" | grep -qE "；(2[4-9]|3[0-6]) 秒后重试" || { echo "MISSING in pushed: long backoff"; FAILS=$((FAILS+1)); }
S=$(section adopt-on-refresh no-adopt-foreign)
need adopt "$S" "EVENT2 state=connected"
need adopt "$S" "EVENT2 killswitch=1"
S=$(section no-adopt-foreign offline-cancel)
need foreign "$S" "EVENT3 managing=false"
if echo "$S" | grep -qE "EVENT3 (state=connected|killswitch=)"; then
    echo "UNEXPECTED in foreign: adopted a session the App did not start"; FAILS=$((FAILS+1))
fi
S=$(section offline-cancel offline-resume)
need offline "$S" "等待网络恢复"
need offline "$S" "offline owned=true"
need offline "$S" "offline cancel-issued=true"
need offline "$S" "offline daemon-state=Disconnected"
# The daemon cancel must run even though terminating -s already ended the CLI.
[ -s "$WORK/cancellations" ] || { echo "MISSING Cisco cancel"; FAILS=$((FAILS+1)); }
S=$(section offline-resume offline-manual-stop)
need resume "$S" "state=connected"
S=$(section restored-after-manual DONE)
none manual-offline "$S" "state=authenticating"
none manual-offline "$S" "state=connected"
LOGINS=$(grep -c . "$WORK/commands" 2>/dev/null || true)
echo "logins attempted: $LOGINS"
rm -rf "$WORK"
echo "cisco-engine FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
