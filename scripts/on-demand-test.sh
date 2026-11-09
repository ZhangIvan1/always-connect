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

# Compile actual production callback/entry-point bodies with deterministic XPC
# and Cisco substitutes; no App, service, credentials or network is touched.
python3 "$ROOT/core/scripts/on-demand-wiring.py" "$ROOT" "$WORK/Wiring.swift"
swiftc -O -target "$(uname -m)-apple-macos13.0" -parse-as-library \
    "$ROOT/Sources/App/OnDemand.swift" "$ROOT/Sources/App/OnDemandDisconnect.swift" \
    "$WORK/Wiring.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" \
    -o "$WORK/wiring" >"$WORK/wiring-build.log" 2>&1 || { cat "$WORK/wiring-build.log"; exit 1; }
"$WORK/wiring"
# Compile the actual system shell without executing permissions or probes.
swiftc -target "$(uname -m)-apple-macos13.0" -parse-as-library -typecheck \
    "$ROOT/Sources/App/OnDemand.swift" "$ROOT/Sources/App/NetworkFacts.swift"
