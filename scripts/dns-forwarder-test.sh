#!/bin/bash
# DNS forwarder harness (DESIGN.md §26.4): loopback fake upstreams only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The forwarder is Rust (§32.6): build the staticlib, link the Swift shell.
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/core/scripts/DNSForwarderShell.swift" \
    "$ROOT/core/scripts/DNSForwarderTest.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" \
    -o "$WORK/test" 2>&1 | grep -v -e warning -e "built for newer" || true
"$WORK/test"
