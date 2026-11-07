#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/Helper/ClientUIDPolicy.swift" \
    "$ROOT/core/scripts/ClientUIDTest.swift" -o "$WORK/test"
"$WORK/test"
