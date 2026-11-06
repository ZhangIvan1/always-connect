#!/bin/bash
# The own connection's self-check rule (DESIGN.md §26.11):
# Sources/App/ConnectionCheck.swift with core/scripts/ConnectionCheckTest.swift.
# Pure logic: touches no network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/ConnectionCheck.swift" \
    "$ROOT/core/scripts/ConnectionCheckTest.swift" -o "$WORK/test"
"$WORK/test"
