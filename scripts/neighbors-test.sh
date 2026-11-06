#!/bin/bash
# Other-VPN / proxy notices (DESIGN.md §27.2): pure classification, no
# probing of this Mac.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/NetworkNeighbors.swift" \
    "$ROOT/core/scripts/NeighborsTest.swift" -o "$WORK/test"
"$WORK/test"
