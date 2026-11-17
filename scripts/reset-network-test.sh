#!/bin/bash
# Exercise journal cleanup and the final recovery check with command
# replacements; no launchctl, route, pfctl or live network state is touched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 - "$ROOT/scripts/reset-network.sh" "$WORK/reader.sh" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text(); start=s.index('scope_interface_identity() {'); reader=s.index('restore_scoped_routes_from_journal() {'); end=s.index('\n}',reader)+2
native=s.index('native_route_entry() {'); native_end=s.index('\n}',native)+2
retire=s.index('direct_route_table() {'); retire_fn=s.index('retire_direct_routes() {'); retire_end=s.index('\n}',retire_fn)+2
Path(sys.argv[2]).write_text(s[native:native_end]+'\n'+s[retire:retire_end]+'\n'+s[start:end]+'\n')
Path(sys.argv[2]).with_name('verify.sh').write_text(s[s.index('# 6 verify'):])
PY
source "$WORK/reader.sh"
for address in 0.0.0.0 127.0.0.1 127.0.0.0/8 169.254.1.2 224.0.0.1 240.0.0.1 255.255.255.255 203.0.113.8; do
  native_route_entry "$address" 1 '203.0.113.8' || { echo 'native/control entry not protected'; exit 1; }
done
for address in 10.0.0.1 172.16.0.1 192.168.1.2 203.0.113.9 10.20.0.0/16; do
  if native_route_entry "$address" 1 '203.0.113.8'; then echo 'ordinary private/unicast entry rejected'; exit 1; fi
done
native_route_entry '203.0.113.9' 0 ''
native_route_entry '203.0.113.8/32' 1 $'127.0.0.1\n203.0.113.8\n10.8.0.2'

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
direct_route_table() {
 printf 'Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n203.0.113.10 192.168.1.1 UGHS en0\n'
}
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
[ -f "$WORK/direct" ]
[ ! -e "$WORK/direct-calls" ]
if FAILED_TARGET=203.0.113.10 retire_direct_routes "$WORK/direct" boot-1 1 ''; then echo 'failed delete was retired'; exit 1; fi
! grep -q '203.0.113.9 ' "$WORK/direct"
grep -q '203.0.113.10 ' "$WORK/direct"
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ]
: > "$WORK/direct-calls"
printf 'boot previous-boot\n203.0.113.9 192.168.1.1\n' > "$WORK/direct"
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ]
[ ! -s "$WORK/direct-calls" ]
: > "$WORK/direct-calls"
printf 'boot boot-1\nretire 203.0.113.9 192.168.1.1\n' > "$WORK/direct"
if retire_direct_routes "$WORK/direct" boot-1 1 '';then echo 'unconfirmed intent was replayed';exit 1;fi
[ ! -s "$WORK/direct-calls" ]
grep -q '^retire 203.0.113.9' "$WORK/direct"
direct_route_table() { printf 'Destination Gateway Flags Netif Expire\nunreadable-row\n'; }
if retire_direct_routes "$WORK/direct" boot-1 1 '';then echo 'unknown table was treated as absent';exit 1;fi
[ ! -s "$WORK/direct-calls" ]
grep -q '^retire 203.0.113.9' "$WORK/direct"
direct_route_table() { printf 'Destination Gateway Flags Netif Expire\n'; }
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ]
# Fail the final metadata write after one deletion completed and one failed.
# The durable intent must prevent another deletion after a process restart.
writer_definition=$(declare -f write_direct_journal)
eval "${writer_definition/write_direct_journal/real_write_direct_journal}"
JOURNAL_WRITES=0
write_direct_journal() {
  JOURNAL_WRITES=$((JOURNAL_WRITES+1))
  [ "$JOURNAL_WRITES" -eq 1 ] || return 1
  real_write_direct_journal "$@"
}
direct_route_table() {
 printf 'Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n203.0.113.10 192.168.1.1 UGHS en0\n'
}
: > "$WORK/direct-calls"
printf 'boot boot-1\n203.0.113.9 192.168.1.1\n203.0.113.10 192.168.1.1\n' > "$WORK/direct"
if FAILED_TARGET=203.0.113.10 retire_direct_routes "$WORK/direct" boot-1 1 '';then echo 'metadata failure reported success';exit 1;fi
[ "$(wc -l < "$WORK/direct-calls" | tr -d ' ')" = 2 ]
grep -q '^retire 203.0.113.9' "$WORK/direct"
eval "$writer_definition"
if retire_direct_routes "$WORK/direct" boot-1 1 '';then echo 'interrupted deletion was replayed';exit 1;fi
[ "$(wc -l < "$WORK/direct-calls" | tr -d ' ')" = 2 ]
direct_route_table() { printf 'Destination Gateway Flags Netif Expire\n'; }
retire_direct_routes "$WORK/direct" boot-1 1 ''
[ ! -e "$WORK/direct" ]
# A failed system validator must keep its delete authority pending.
native_definition=$(declare -f native_route_entry)
printf '#!/bin/bash\nexit 2\n' > "$WORK/failed-awk"
chmod +x "$WORK/failed-awk"
failed_awk_command="\"$WORK/failed-awk\""
eval "${native_definition/\/usr\/bin\/awk/$failed_awk_command}"
direct_route_table() { printf 'Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n'; }
: > "$WORK/direct-calls"
printf 'boot boot-1\n203.0.113.9 192.168.1.1\n' > "$WORK/direct"
if retire_direct_routes "$WORK/direct" boot-1 1 ''; then echo 'failed native validator authorized deletion'; exit 1; fi
[ ! -s "$WORK/direct-calls" ]
grep -q '203.0.113.9' "$WORK/direct"
eval "$native_definition"

# A failed website probe never authorizes disabling shared packet filtering.
# Execute the production tail in a child because it deliberately calls exit.
cat > "$WORK/verify-harness.sh" <<'SH'
#!/bin/bash
set -u
WORK=$1; DRY=$2; PROBE_STATUS=$3
say() { printf '%s\n' "$*"; }
sleep() { :; }
route() { printf 'interface: en0\n'; }
pfctl() { printf '%s\n' "$*" >> "$WORK/pf-calls"; }
webok() { printf 'probe\n' >> "$WORK/probe-calls"; return "$PROBE_STATUS"; }
source "$WORK/verify.sh"
SH
for probe_status in 0 1; do
  : > "$WORK/pf-calls"
  if bash "$WORK/verify-harness.sh" "$WORK" 0 "$probe_status" > "$WORK/verify-output"; then
    verify_status=0
  else
    verify_status=$?
  fi
  [ ! -s "$WORK/pf-calls" ] || { echo 'FAIL recovery changed shared PF after a website probe'; exit 1; }
  [ "$verify_status" = "$probe_status" ] || { echo 'FAIL recovery reported the wrong connectivity result'; exit 1; }
done
: > "$WORK/probe-calls"
bash "$WORK/verify-harness.sh" "$WORK" 1 1 > "$WORK/verify-output"
[ ! -s "$WORK/probe-calls" ]
[ ! -s "$WORK/pf-calls" ]
bash -n "$ROOT/scripts/reset-network.sh"
echo 'PASS emergency recovery: journal ownership, failure handling and shared PF preservation (stubbed)'
