#!/bin/bash
# The connections page's listing and route lookup (DESIGN.md §28.7,
# §32.9). Reads this Mac's sockets and routing table only; changes nothing.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/Helper/Connections.swift" "$ROOT/Sources/Shared/Models.swift" "$ROOT/core/scripts/ConnectionsTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test" 2>&1 | grep -v "built for newer" || true
"$WORK/test"
