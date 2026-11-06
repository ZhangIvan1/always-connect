#!/bin/bash
# Put the local build into /Applications so the user can find it in
# Launchpad / Spotlight (owner's request, 2026-11-05). A running copy is
# quit first (quit = VPN off, direct network, DESIGN.md §21.5), so this
# must not be run while a test or a needed VPN session is up without
# telling the user. Admin users can write /Applications without sudo.
#
# Usage: scripts/install-app.sh [--open]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/.local-build/AlwaysConnect.app"
DST=/Applications/AlwaysConnect.app
[ -d "$SRC" ] || { echo "build first: scripts/build-local.sh" >&2; exit 1; }
if pgrep -f "AlwaysConnect.app/Contents/MacOS/AlwaysConnect" >/dev/null; then
    echo "quitting the running AlwaysConnect (VPN off, direct network)"
    osascript -e 'tell application id "com.alwaysconnect.app" to quit' >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
        pgrep -f "AlwaysConnect.app/Contents/MacOS/AlwaysConnect" >/dev/null || break
        sleep 1
    done
fi
rm -rf "$DST"
ditto "$SRC" "$DST"
codesign --verify --strict "$DST"
echo "installed $DST"
[ "${1:-}" = "--open" ] && open "$DST"
exit 0
