#!/bin/bash
# Background-service lifecycle harness (DESIGN.md §二十五): HelperSession,
# the Cisco kill switch and the openconnect engine driven directly, with
# a logging pfctl stand-in and core/scripts/fake-openconnect.sh under a
# scratch ALWAYSCONNECT_TEST_ROOT. Never touches real pf, routes or VPN.
# Usage: scripts/session-test.sh [scenario ...]   (default: all)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LIB="$ROOT/core/target/release/libalwaysconnect_core.a"
[ -f "$LIB" ] || (cd "$ROOT/core" && cargo build --release --quiet)
SOURCES=()
for f in "$ROOT"/Sources/Helper/*.swift; do
    [ "$(basename "$f")" = HelperMain.swift ] || SOURCES+=("$f")
done
swiftc -O -parse-as-library -module-name SessionHarness "${SOURCES[@]}" \
    "$ROOT"/Sources/Shared/*.swift "$ROOT/core/scripts/SessionHarness.swift" "$LIB" \
    -o "$WORK/harness" 2>&1 | grep -v "was built for newer 'macOS' version" || true
[ -x "$WORK/harness" ] || { echo "FAIL build"; exit 1; }

SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(cisco-disconnect protection-off own-disconnect own-then-cisco
    own-protection-off own-protection-toggle
    grace-expiry grace-cancelled quit-no-relaunch restart-same-boot restart-other-boot legacy-pf-state
    own-replace orphan-sweep journal-at-start direct-routes-journal
    takeover-adopted takeover-replace protection-off-adopted held-allow-update
    direct-table direct-before-hold direct-adopt old-record)
FAILED=0
for s in "${SCENARIOS[@]}"; do
    T="$WORK/$s"; mkdir -p "$T"
    cat > "$T/pfctl" <<'STUB'
#!/bin/bash
D=$(dirname "$0")
printf "%s\n" "$*" >> "$D/pfctl.log"
# The rule text of each load, for checks on what a set lets through.
if [ "$3" = "-f" ]; then
    [ "$4" = "-" ] || exit 1
    { echo "=== load"; cat; } >> "$D/pf-rules.log"
fi
if [ "$*" = "-E" ]; then
    n=$(( $(cat "$D/token" 2>/dev/null || echo 0) + 1 )); echo $n > "$D/token"
    echo "Token : 1000$n" >&2
fi
exit 0
STUB
    cp "$ROOT/core/scripts/fake-openconnect.sh" "$T/openconnect"
    chmod +x "$T/pfctl" "$T/openconnect"
    echo "== $s"
    if ! ALWAYSCONNECT_TEST_ROOT="$T" ALWAYSCONNECT_NO_ROUTES=1 ALWAYSCONNECT_TEST_GRACE=2 FAKE_UP_SECONDS=600 \
        "$WORK/harness" "$s" 2> "$T/stderr.log"; then
        FAILED=$((FAILED+1)); echo "  pfctl calls:"; sed 's/^/    /' "$T/pfctl.log" 2>/dev/null || true
        tail -5 "$T/stderr.log" | sed 's/^/    stderr: /'
    fi
done
echo "session-test failures: $FAILED"
[ $FAILED -eq 0 ]
