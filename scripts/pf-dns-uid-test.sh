#!/bin/bash
# CI-only kernel harness: an isolated localhost port, never the real DNS or VPN.
# This script stays unprivileged; sudo executes only fixed macOS system tools.
set -euo pipefail
[ "${1:-}" = --ci ] && [ "${GITHUB_ACTIONS:-}" = true ] || {
    echo 'CI-only: this harness changes a temporary PF anchor; not run locally.' >&2; exit 2;
}
[ "$(uname -s)" = Darwin ]
[ "$(id -u)" != 0 ] || { echo "Run this script as the CI user, not root" >&2; exit 2; }
HELPER=${2:?built Helper path}
WORK=$(mktemp -d)
ANCHOR="com.apple/299.AlwaysConnectDNSUID.$$"
TOKEN=""; SERVER=""; LOADED=0; TEST_OK=0
cleanup() {
    status=$?; trap - EXIT
    errors=0
    if [ "$LOADED" = 1 ]; then
        sudo -n /sbin/pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1 || errors=1
        if ! remaining=$(sudo -n /sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null); then errors=1
        elif [ -n "$remaining" ]; then errors=1; fi
    fi
    if [ -n "$TOKEN" ]; then sudo -n /sbin/pfctl -X "$TOKEN" >/dev/null 2>&1 || errors=1; fi
    if [ -n "$SERVER" ]; then kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true; fi
    rm -rf "$WORK"
    if [ "$errors" != 0 ]; then echo 'FAIL UID harness cleanup not confirmed'; status=1; fi
    if [ "$status" = 0 ] && [ "$TEST_OK" = 1 ]; then echo 'PASS kernel DNS UID barrier and cleanup'; fi
    exit "$status"
}
trap cleanup EXIT
cat > "$WORK/server.py" <<'PY'
import socket,threading
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));port=udp.getsockname()[1]
tcp=socket.socket();tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);tcp.bind(('127.0.0.1',port));tcp.listen()
def datagrams():
    while True:
        data,peer=udp.recvfrom(4096);udp.sendto(data,peer)
threading.Thread(target=datagrams,daemon=True).start()
print(port,flush=True)
while True:
    client,_=tcp.accept()
    with client:
        data=client.recv(4096)
        if data:client.sendall(data)
PY
python3 -u "$WORK/server.py" > "$WORK/port" & SERVER=$!
for _ in $(seq 1 30); do [ -s "$WORK/port" ] && break; sleep .1; done
PORT=$(head -1 "$WORK/port")
[ -n "$PORT" ]
# Use the production generator, isolating only its physical DNS barrier. The
# loopback pass is intentionally omitted to exercise UID matching on localhost.
# Both probes target loopback, so the isolated root permission must match
# that same interface. Using en0 here tests an interface mismatch, not UID.
"$HELPER" generate-pf --phys lo0 --tun utun5 --gateway 203.0.113.1 --dns 127.0.0.1 --direct-table \
  | awk '/port 53 user root no state$/ || /^block drop out quick proto .* to any port 53$/ { print }' \
  | sed -e "s/port 53/port $PORT/g" -e 's/to any port/to 127.0.0.1 port/g' > "$WORK/rules"
grep -q 'user root' "$WORK/rules"
# The root exception names the forwarder's source ports (DESIGN §61.1).
RANGE=$(sed -n 's/.*from any port \([0-9]*\):\([0-9]*\) to .*/\1 \2/p' "$WORK/rules" | head -1)
read -r SOURCE_LOW SOURCE_HIGH <<< "$RANGE"
[ -n "$SOURCE_LOW" ] && [ -n "$SOURCE_HIGH" ] && [ "$SOURCE_LOW" -lt "$SOURCE_HIGH" ]
grep -q 'block drop out quick' "$WORK/rules"
# Main rules belong to the explicit runner-initialisation step, not this test.
sudo -n /sbin/pfctl -s rules 2>/dev/null | grep -q 'anchor "com.apple/\*"' || {
    echo 'Missing wildcard anchor; refusing to replace the global PF rules' >&2; exit 1;
}
# Labels are only counter identifiers and do not change matching semantics.
sed -i '' -e '/^pass /s/$/ label "AC_UID_ROOT"/' -e '/^block /s/$/ label "AC_UID_BLOCK"/' "$WORK/rules"
probe() {
    who=$1; proto=$2; stage=$3; source_port=${4:-}
    args=(-n -w 1); [ "$proto" != udp ] || args+=(-u)
    [ -z "$source_port" ] || args+=(-p "$source_port")
    if [ "$who" = root ]; then command=(sudo -n /usr/bin/nc); else command=(/usr/bin/nc); fi
    code=0
    reply=$(printf uid-query | "${command[@]}" "${args[@]}" 127.0.0.1 "$PORT" 2> "$WORK/$stage-$who-$proto.err") || code=$?
    PROBE_REPLY=$reply; PROBE_CODE=$code
    if grep -Eiq 'permission denied|too many open files|invalid|illegal|not found|not permitted' "$WORK/$stage-$who-$proto.err"; then
        cat "$WORK/$stage-$who-$proto.err" >&2; echo 'Probe could not be initiated' >&2; exit 1
    fi
}
counters() {
    sudo -n /sbin/pfctl -a "$ANCHOR" -vvs rules > "$WORK/counters"
    python3 - "$WORK/counters" "$1" <<'PYCODE'
import re,sys
label=sys.argv[2];target=False;values=[]
for line in open(sys.argv[1]):
    stripped=line.strip()
    if stripped.startswith(('@','pass ','block ')): target=('label "'+label+'"') in line
    if target:
        m=re.search(r'Packets:\s*(\d+)',line)
        if m:values.append(int(m[1]))
if len(values)!=2:raise SystemExit('Missing per-protocol counter evidence')
print(sum(values))
PYCODE
}
# Positive controls with the dedicated anchor absent, for BOTH callers.
for proto in tcp udp; do
    for who in user root; do
        probe "$who" "$proto" baseline
        [ "$PROBE_CODE" = 0 ] && [ "$PROBE_REPLY" = uid-query ] || { echo "FAIL $who $proto baseline"; exit 1; }
    done
done
TOKEN=$(sudo -n /sbin/pfctl -E 2>&1 | sed -n 's/.*Token[[:space:]]*:[[:space:]]*//p')
[ -n "$TOKEN" ]
sudo -n /sbin/pfctl -a "$ANCHOR" -f - < "$WORK/rules"; LOADED=1
offset=1
for proto in tcp udp; do
    before_root=$(counters AC_UID_ROOT)
    probe root "$proto" protected $((SOURCE_LOW + offset)); offset=$((offset + 1))
    [ "$PROBE_CODE" = 0 ] && [ "$PROBE_REPLY" = uid-query ] || { echo "FAIL root $proto barrier"; exit 1; }
    after_root=$(counters AC_UID_ROOT)
    [ "$after_root" -gt "$before_root" ] || { echo 'Root pass did not match this anchor'; exit 1; }
    # Root from any other port stands for a root extension re-sending a
    # user's query: it must meet the DNS barrier like the user does.
    for who in root user; do
        before_block=$(counters AC_UID_BLOCK)
        probe "$who" "$proto" protected-other
        [ -z "$PROBE_REPLY" ] || { echo "FAIL $who outside the source ports bypassed $proto barrier"; exit 1; }
        after_block=$(counters AC_UID_BLOCK)
        [ "$after_block" -gt "$before_block" ] || { echo 'Drop not attributable to this anchor'; exit 1; }
    done
done
sudo -n /sbin/pfctl -a "$ANCHOR" -F rules
for proto in tcp udp; do
    probe user "$proto" restored
    [ "$PROBE_CODE" = 0 ] && [ "$PROBE_REPLY" = uid-query ] || { echo "FAIL user $proto recovery"; exit 1; }
done
TEST_OK=1
