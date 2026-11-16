#!/bin/bash
# Extract only the recovery journal reader. Its run() records commands; no
# launchctl, route, pfctl, network process, or live state is touched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 - "$ROOT/scripts/reset-network.sh" "$WORK/reader.sh" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text(); start=s.index('restore_scoped_routes_from_journal() {'); end=s.index('\n}',start)+2
Path(sys.argv[2]).write_text(s[start:end]+'\n')
PY
source "$WORK/reader.sh"
run() { printf '%s\n' "$*" >> "$WORK/calls"; }
printf 'AC_TUN=utun7\nAC_TUNS="utun7 utun8"\n' > "$WORK/journal"
restore_scoped_routes_from_journal "$WORK/journal"
[ "$(wc -l < "$WORK/calls" | tr -d ' ')" = 2 ]
grep -qx '/sbin/route -n delete -ifscope utun7 default' "$WORK/calls"
grep -qx '/sbin/route -n delete -ifscope utun8 default' "$WORK/calls"
: > "$WORK/calls"
printf 'AC_TUN=en0\nAC_TUNS="utun5;evil utun6$(evil) /tmp/evil"\n' > "$WORK/journal"
restore_scoped_routes_from_journal "$WORK/journal"
restore_scoped_routes_from_journal "$WORK/missing"
[ ! -s "$WORK/calls" ]
bash -n "$ROOT/scripts/reset-network.sh"
echo 'PASS emergency scoped-route recovery, deduplication and invalid journal rejection (stubbed)'
