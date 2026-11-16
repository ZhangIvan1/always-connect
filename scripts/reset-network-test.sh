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
s=Path(sys.argv[1]).read_text(); start=s.index('scope_interface_identity() {'); reader=s.index('restore_scoped_routes_from_journal() {'); end=s.index('\n}',reader)+2
native=s.index('native_route_entry() {'); native_end=s.index('\n}',native)+2
retire=s.index('retire_direct_routes() {'); retire_end=s.index('\n}',retire)+2
Path(sys.argv[2]).write_text(s[native:native_end]+'\n'+s[retire:retire_end]+'\n'+s[start:end]+'\n')
PY
source "$WORK/reader.sh"
for address in 0.0.0.0 127.0.0.1 127.0.0.0/8 169.254.1.2 224.0.0.1 240.0.0.1 255.255.255.255 203.0.113.8; do
  native_route_entry "$address" 1 '203.0.113.8' || { echo 'native/control entry not protected'; exit 1; }
done
for address in 10.0.0.1 172.16.0.1 192.168.1.2 203.0.113.9 10.20.0.0/16; do
  if native_route_entry "$address" 1 '203.0.113.8'; then echo 'ordinary private/unicast entry rejected'; exit 1; fi
done
native_route_entry '203.0.113.9' 0 ''

run() { printf '%s\n' "$*" >> "$WORK/calls"; }
scope_interface_identity() { [ "${TEST_UNKNOWN:-}" != 1 ] || return 2; printf '%s\n' "${TEST_IDENTITY:-107 10.8.0.2}"; }
printf 'AC_BOOT=boot-1\nAC_TUN=utun8\nAC_TUNS="utun7 utun8"\nAC_SCOPED_TUN=utun8\nAC_SCOPED_INDEX=107\nAC_SCOPED_ADDR=10.8.0.2\n' > "$WORK/journal"
restore_scoped_routes_from_journal "$WORK/journal" boot-1
[ "$(wc -l < "$WORK/calls" | tr -d ' ')" = 1 ]
grep -qx '/sbin/route -n delete -ifscope utun8 default' "$WORK/calls"
: > "$WORK/calls"
if TEST_UNKNOWN=1 restore_scoped_routes_from_journal "$WORK/journal" boot-1; then
  echo "unknown interface identity must remain pending"; exit 1
fi
restore_scoped_routes_from_journal "$WORK/journal" new-boot
TEST_IDENTITY='999 10.8.0.2' restore_scoped_routes_from_journal "$WORK/journal" boot-1
TEST_IDENTITY='107 198.51.100.2' restore_scoped_routes_from_journal "$WORK/journal" boot-1
restore_scoped_routes_from_journal "$WORK/missing" boot-1
printf 'AC_BOOT=boot-1\nAC_SCOPED_TUN="utun5;evil"\nAC_SCOPED_INDEX=107\nAC_SCOPED_ADDR=10.8.0.2\n' > "$WORK/journal"
restore_scoped_routes_from_journal "$WORK/journal" boot-1
[ ! -s "$WORK/calls" ]
# Unknown facts and actual delete errors preserve only unfinished entries.
DRY=0
say() { :; }
run() {
  if [ "$1" = /sbin/route ]; then
    printf '%s\n' "$*" >> "$WORK/direct-calls"
    case "$*" in *"${FAILED_TARGET:-never-match}"*) return 1;; esac
    return 0
  fi
  "$@"
}
printf 'boot boot-1\n203.0.113.9 192.168.1.1\n203.0.113.10 192.168.1.1\n' > "$WORK/direct"
if retire_direct_routes "$WORK/direct" boot-1 0 ''; then echo 'unknown facts lost pending state'; exit 1; fi
[ -f "$WORK/direct" ] && [ ! -e "$WORK/direct-calls" ]
if FAILED_TARGET=203.0.113.10 retire_direct_routes "$WORK/direct" boot-1 1 ''; then echo 'failed delete was retired'; exit 1; fi
! grep -q '203.0.113.9 ' "$WORK/direct"
grep -q '203.0.113.10 ' "$WORK/direct"
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ]
: > "$WORK/direct-calls"
printf 'boot previous-boot\n203.0.113.9 192.168.1.1\n' > "$WORK/direct"
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ] && [ ! -s "$WORK/direct-calls" ]
bash -n "$ROOT/scripts/reset-network.sh"
echo 'PASS emergency scoped-route recovery, boot/interface ownership and invalid journal rejection (stubbed)'
