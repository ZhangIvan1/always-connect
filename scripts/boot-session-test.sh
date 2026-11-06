#!/bin/bash
# Boot-staleness contract (DESIGN.md §23.12): pf-state / route-state
# from an earlier boot is never reloaded. Local files only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/Helper/BootSession.swift" \
    "$ROOT/core/scripts/BootSessionTest.swift" -o "$WORK/test"
"$WORK/test"
