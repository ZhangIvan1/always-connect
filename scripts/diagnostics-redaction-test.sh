#!/bin/bash
# The diagnostics file names no VPN (DESIGN.md §36.3). Local only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/App/DiagnosticsRedaction.swift" \
    "$ROOT/core/scripts/DiagnosticsRedactionTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test"
"$WORK/test"

python3 "$ROOT/core/scripts/diagnostics-export-test.py" --root "$ROOT"
