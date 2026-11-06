#!/bin/bash
# Drop-history contract (DESIGN.md §21.22): Sources/App/DropHistory.swift
# with core/scripts/DropHistoryTest.swift. Episodes, outcomes, terminal
# reasons, old records and the shown text. Touches nothing real.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/DropHistory.swift" \
    "$ROOT/core/scripts/DropHistoryTest.swift" -o "$WORK/test"
"$WORK/test"
