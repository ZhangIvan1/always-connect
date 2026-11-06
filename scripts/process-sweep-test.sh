#!/bin/bash
# Quit cleanup contract (DESIGN.md §23.11): listing and ending every
# descendant process, SIGTERM then SIGKILL. Local processes only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/Shared/ProcessSweep.swift" \
    "$ROOT/core/scripts/ProcessSweepTest.swift" -o "$WORK/test"
"$WORK/test"
