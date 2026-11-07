#!/bin/bash
# The update check (DESIGN.md §三十三): the App's UpdateChecker and the
# Rust decision against a local server standing in for GitHub's releases
# list. Touches no network beyond 127.0.0.1 and no App preferences
# (a scratch defaults suite). Verification level: CI harness.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
SERVER=""
# The scratch suite's emptied plist file stays behind otherwise.
SUITE_PLIST="$HOME/Library/Preferences/com.alwaysconnect.update-check-test.plist"
trap '[ -n "$SERVER" ] && kill $SERVER 2>/dev/null; defaults delete com.alwaysconnect.update-check-test >/dev/null 2>&1 || true; rm -f "$SUITE_PLIST"; rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/App/UpdateChecker.swift" "$ROOT/Sources/App/AppQuit.swift" "$ROOT/core/scripts/UpdateCheckTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test" 2>&1 | grep -v "built for newer" || true

mkdir -p "$WORK/www"
rel() { printf '{"tag_name":"%s","html_url":"https://github.com/o/r/releases/tag/%s","draft":%s,"prerelease":%s,"name":"%s","body":"notes","assets":[]}' "$1" "$1" "$2" "$3" "$1"; }
echo "[$(rel v9.0.0 true false),$(rel v0.2.0-beta.1 false true),$(rel v0.1.0 false true)]" > "$WORK/www/releases.json"
echo "[$(rel v0.3.0 false false),$(rel v0.2.0-beta.1 false true),$(rel v0.1.0 false true)]" > "$WORK/www/later.json"
echo '{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}' > "$WORK/www/notfound.json"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
CLOSED=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK/www" >"$WORK/server.log" 2>&1 &
SERVER=$!
disown "$SERVER"
for _ in $(seq 1 40); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.25; done
"$WORK/test" "http://127.0.0.1:$PORT/" "http://127.0.0.1:$CLOSED/releases"
