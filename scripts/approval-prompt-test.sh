#!/bin/bash
# Approval card contract (DESIGN.md §29): Sources/App/ApprovalPromptTracker.swift
# with core/scripts/ApprovalPromptTest.swift. When the card shows, updates,
# finishes and hides, request counting, user hiding, the text. Touches
# nothing real; the window itself is Mac proof.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/ApprovalPromptTracker.swift" \
    "$ROOT/core/scripts/ApprovalPromptTest.swift" -o "$WORK/test"
"$WORK/test"
