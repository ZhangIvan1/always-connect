#!/bin/bash
# One real authentication against the gateway, no tunnel (DESIGN.md
# §20.12). Runs as the normal user, so openconnect can authenticate
# but cannot create a tun device: routes, DNS and pf are never
# touched. Answers the open question — does the gateway accept
# username + password (+ phone approval) without a client
# certificate? — and records the redacted output shape (approval
# wait, rejection text) for DESIGN §16.5 / Mac proof A3, F3.
#
# Usage: scripts/probe-gateway.sh <username> [server-or-Cisco-entry, default VPN-A] [group, default Staff]
# The password is read silently; approve the phone push on your phone
# when it arrives. Redacted output: /tmp/ac-probe/out.txt (passwords
# and session cookies masked by the engine; the username and gateway
# responses are in it, so review before sharing).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HELPER="$ROOT/.local-build/AlwaysConnectHelper"
[ -x "$HELPER" ] || { echo "build first: scripts/build-local.sh" >&2; exit 2; }
USER_NAME=${1:?usage: probe-gateway.sh <username> [server] [group]}
SERVER=${2:-VPN-A}
GROUP=${3:-Staff}

case "$SERVER" in
*.*|*:*) ADDRESS=$SERVER ;;
*)
    # Same lookup as the App (CiscoProfiles.swift): entry name -> HostAddress.
    ADDRESS=$(python3 -I - "$SERVER" <<'EOF'
import glob, re, sys
name = sys.argv[1]
for d in ("/opt/cisco/secureclient/vpn/profile", "/opt/cisco/anyconnect/profile"):
    for f in sorted(glob.glob(d + "/*.xml")):
        text = open(f, errors="replace").read()
        for entry in re.findall(r"<HostEntry>.*?</HostEntry>", text, re.S):
            n = re.search(r"<HostName>\s*(.*?)\s*</HostName>", entry)
            a = re.search(r"<HostAddress>\s*(.*?)\s*</HostAddress>", entry)
            if n and a and n.group(1) == name:
                print(a.group(1))
                sys.exit(0)
EOF
)
    [ -n "$ADDRESS" ] || { echo "no Cisco profile entry named $SERVER" >&2; exit 2; }
    ;;
esac

OUT=/tmp/ac-probe
rm -rf "$OUT"; mkdir -p "$OUT"; chmod 700 "$OUT"
printf 'Password for %s: ' "$USER_NAME" >&2
IFS= read -rs PASSWORD; echo >&2
echo "authenticating (approve the phone push if one arrives)..." >&2
printf '%s\n' "$PASSWORD" | "$HELPER" run-once --server "$ADDRESS" --group "$GROUP" \
    --user "$USER_NAME" --max-attempts 1 --no-routes --debug-child-output \
    --cookie-store "$OUT/session.json" --support-dir "$OUT" > "$OUT/out.txt" 2>&1
unset PASSWORD
chmod 600 "$OUT/out.txt"

if [ -s "$OUT/session.json" ]; then
    echo "RESULT: authenticated (session cookie captured; no tunnel was created, by design)"
elif grep -q "Login failed" "$OUT/out.txt"; then
    echo "RESULT: credentials rejected"
elif grep -q "Certificate Validation Failure" "$OUT/out.txt"; then
    echo "RESULT: not authenticated; gateway reported Certificate Validation Failure (client certificate likely required)"
else
    echo "RESULT: not authenticated; see $OUT/out.txt"
fi
rm -f "$OUT/session.json"
echo "redacted log: $OUT/out.txt"
