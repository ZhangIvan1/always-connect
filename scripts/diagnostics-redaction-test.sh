#!/bin/bash
# The diagnostics file names no VPN (DESIGN.md §36.3). Local only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/DiagnosticsRedaction.swift" \
    "$ROOT/core/scripts/DiagnosticsRedactionTest.swift" -o "$WORK/test"
"$WORK/test"
