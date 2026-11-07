#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/SettingsTransport.swift" \
    "$ROOT/core/scripts/SettingsTransportTest.swift" -o "$WORK/test"
"$WORK/test"
if rg 'DistributedNotificationCenter|SETTINGS_TOKEN|AppRole.token' "$ROOT/Sources/App/SettingsProcess.swift"; then
    echo 'FAIL public settings transport remains'; exit 1
fi
echo 'PASS settings actions have no broadcast endpoint'
