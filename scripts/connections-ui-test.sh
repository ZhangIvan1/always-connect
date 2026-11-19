#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
(cd core && cargo build --release --quiet)
sed "s/group\.com\.alwaysconnect\.app/com.example.$(basename "$WORK")/g" Sources/Shared/Models.swift > "$WORK/Models.swift"
sed 's|"/opt/cisco/|"/nonexistent/connections-ui-test/|g' Sources/App/CiscoProfiles.swift > "$WORK/CiscoProfiles.swift"
SOURCES=("$WORK/Models.swift" "$WORK/CiscoProfiles.swift")
for file in Sources/App/*.swift Sources/Shared/*.swift; do
    case "$file" in
        */AlwaysConnectApp.swift|*/Models.swift|*/CiscoProfiles.swift) ;;
        *) SOURCES+=("$file") ;;
    esac
done
swiftc -target "$(uname -m)-apple-macos13.0" -parse-as-library -module-name ConnectionsUITest "${SOURCES[@]}" \
    core/scripts/ConnectionsUITest.swift core/target/release/libalwaysconnect_core.a \
    -o "$WORK/ConnectionsUITest" > "$WORK/swift.log" 2>&1 || { cat "$WORK/swift.log"; exit 1; }
"$WORK/ConnectionsUITest" --settings -settingsTab connections
