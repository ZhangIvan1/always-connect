#!/bin/bash
# The App's quit from every kind of caller (DESIGN.md §37): AppQuit must
# end a .terminateLater quit whether it was asked from a main-queue block,
# OperationQueue.main (Settings → App notifications) or another thread.
# A plain NSApp.terminate from a main-queue block is the hang the uninstall
# from Settings ran into; it must still hang here, or the harness proves
# nothing. Starts tiny invisible processes; touches nothing else.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/AppQuit.swift" "$ROOT/core/scripts/QuitTest.swift" -o "$WORK/quit-test" 2>&1 \
    | grep -v "built for newer" || true
[ -x "$WORK/quit-test" ] || { echo "FAIL build"; exit 1; }
FAILS=0
run() {  # caller expected(exits|hangs)
    "$WORK/quit-test" "$1" & local pid=$!
    for _ in $(seq 1 50); do kill -0 $pid 2>/dev/null || break; sleep 0.1; done
    local got=exits
    if kill -0 $pid 2>/dev/null; then got=hangs; kill -9 $pid 2>/dev/null; fi
    wait $pid 2>/dev/null
    if [ "$got" = "$2" ]; then echo "PASS $1 $got"; else echo "FAIL $1 $got (expected $2)"; FAILS=$((FAILS+1)); fi
}
run gcd exits
run opqueue exits
run background exits
run direct exits
run plain-gcd hangs
[ $FAILS = 0 ] && echo "quit: all passed" || { echo "quit: $FAILS failed"; exit 1; }
