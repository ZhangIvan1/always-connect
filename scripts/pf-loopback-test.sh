#!/bin/bash
# Real-pf check (DESIGN.md §26.8): a loopback TCP connection opened
# BEFORE the split-mode anchor loads must keep working after it loads.
# That connection is openconnect's link to the certificate relay; the
# first split-mode run cut it and the Mac went offline (2026-11-05).
#
#   sudo scripts/pf-loopback-test.sh /path/to/AlwaysConnectHelper
#
# Safe on any Mac, CI included: the generated rules are loaded with
# their final "block drop out quick all" narrowed to lo0, so no other
# interface is touched; the anchor is flushed and pf's reference
# released on exit. A negative control (the old stateful lo0 pass)
# must fail, proving the check can see the bug.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
HELPER="${1:?path to AlwaysConnectHelper}"
ANCHOR=com.apple/300.AlwaysConnect
WORK=$(mktemp -d)
TOKEN=""
cleanup() {
    pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true
    [ -n "$TOKEN" ] && pfctl -X "$TOKEN" >/dev/null 2>&1 || true
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

"$HELPER" generate-pf --phys en0 --tun utun5 --gateway 203.0.113.10 \
    --allow 192.168.0.0/16 --dns 192.0.2.53 --direct-table > "$WORK/split.conf" || exit 1
grep -q '^block drop out quick all$' "$WORK/split.conf" || { echo "split set has no final block" >&2; exit 1; }
sed 's/^block drop out quick all$/block drop out quick on lo0 all/' "$WORK/split.conf" > "$WORK/fixed.conf"
sed 's/^pass out quick on lo0 all no state$/pass out quick on lo0 all/' "$WORK/fixed.conf" > "$WORK/old.conf"
grep -q '^pass out quick on lo0 all$' "$WORK/old.conf" || { echo "negative control not built" >&2; exit 1; }

# pf must evaluate com.apple/* (load the system ruleset if it is not).
pfctl -s Anchors 2>/dev/null | grep -q 'com.apple' || pfctl -f /etc/pf.conf >/dev/null 2>&1
TOKEN=$(pfctl -E 2>&1 | awk '/Token/{print $3}')

# Echo server on loopback; the client below keeps one connection open
# across the anchor load and reports whether an exchange still works.
cat > "$WORK/echo.py" <<'EOF'
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(8)
print(s.getsockname()[1], flush=True)
def serve(c):
    while True:
        d = c.recv(64)
        if not d: return
        c.sendall(d)
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
cat > "$WORK/client.py" <<'EOF'
import socket, sys, subprocess
port, conf, anchor = int(sys.argv[1]), sys.argv[2], sys.argv[3]
c = socket.create_connection(("127.0.0.1", port), timeout=3)
c.sendall(b"before"); assert c.recv(64) == b"before"
subprocess.run(["pfctl", "-a", anchor, "-f", conf], check=True, capture_output=True)
try:
    c.sendall(b"after"); ok = c.recv(64) == b"after"
except OSError:
    ok = False
try:
    n = socket.create_connection(("127.0.0.1", port), timeout=3)
    n.sendall(b"new"); new_ok = n.recv(64) == b"new"
except OSError:
    new_ok = False
print("established=%s new=%s" % ("ok" if ok else "cut", "ok" if new_ok else "cut"))
EOF
python3 -u "$WORK/echo.py" > "$WORK/port" &
SRV=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/port" ] && break; sleep 0.2; done
PORT=$(head -1 "$WORK/port")

FAILS=0
pfctl -a "$ANCHOR" -F all >/dev/null 2>&1
R=$(python3 "$WORK/client.py" "$PORT" "$WORK/fixed.conf" "$ANCHOR" 2>&1 | tail -1)
echo "current rules:  $R"
[ "$R" = "established=ok new=ok" ] || FAILS=$((FAILS + 1))
pfctl -a "$ANCHOR" -F all >/dev/null 2>&1
R=$(python3 "$WORK/client.py" "$PORT" "$WORK/old.conf" "$ANCHOR" 2>&1 | tail -1)
echo "old rules (control, must cut): $R"
case "$R" in established=cut*) ;; *) FAILS=$((FAILS + 1));; esac
echo "pf-loopback FAILS=$FAILS"
[ $FAILS = 0 ]
