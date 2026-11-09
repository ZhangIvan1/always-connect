#!/bin/bash
# Stub network facts + Rust policy; no App, location, routes, pf or live probes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -target "$(uname -m)-apple-macos13.0" -parse-as-library \
    "$ROOT/Sources/App/OnDemand.swift" "$ROOT/core/scripts/OnDemandTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test" >"$WORK/build.log" 2>&1 || { cat "$WORK/build.log"; exit 1; }
"$WORK/test"
