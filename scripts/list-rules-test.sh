#!/bin/bash
# The split list's rule syntax and bundled data (DESIGN.md §26.13).
# Pure logic plus the bundled files; touches no network or settings.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# CiscoProfiles.swift reads Cisco's files through the Rust core (§三十八).
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/App/ListRules.swift" "$ROOT/Sources/App/DirectSites.swift" \
    "$ROOT/Sources/App/OnDemand.swift" "$ROOT/Sources/App/ProfileStore.swift" "$ROOT/Sources/App/DropHistory.swift" "$ROOT/Sources/App/CiscoProfiles.swift" "$ROOT"/Sources/Shared/*.swift \
    "$ROOT/core/scripts/ListRulesTest.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" \
    -o "$WORK/test" 2>&1 | grep -v "built for newer" || true
ALWAYSCONNECT_GEODATA="$ROOT/Sources/App/GeoData" "$WORK/test"
