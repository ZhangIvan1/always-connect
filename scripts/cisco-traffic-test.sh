#!/bin/bash
# Parser contract only: no Cisco installation, credentials or network needed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/CiscoTrafficStats.swift" \
    "$ROOT/core/scripts/CiscoTrafficStatsTest.swift" -o "$WORK/test"
"$WORK/test"
