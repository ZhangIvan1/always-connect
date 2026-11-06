#!/bin/bash
# One real connection through the Cisco Secure Client CLI (DESIGN.md
# §二十一), to record facts before AlwaysConnect drives it: the prompt
# sequence, the state/stats output shapes, and what the system looks
# like while Cisco's tunnel is up. Cisco handles the keychain client
# certificate itself; this script only answers its prompts.
#
# Needs the Cisco GUI app to be quit (only one Cisco client may hold
# the connect capability). Leaves the VPN CONNECTED: disconnect with
#   /opt/cisco/secureclient/bin/vpn disconnect
#
# Usage: scripts/probe-cisco.sh [username] [entry, default VPN-A]
# Without a username, Cisco's own prefilled username is accepted.
# Output (passwords removed, username and addresses masked):
#   /tmp/ac-cisco/connect.txt, /tmp/ac-cisco/snapshot.txt
set -uo pipefail

VPN=/opt/cisco/secureclient/bin/vpn
[ -x "$VPN" ] || { echo "Cisco Secure Client CLI not found" >&2; exit 2; }
USER_NAME=${1:-}
ENTRY=${2:-VPN-A}
OUT=/tmp/ac-cisco
rm -rf "$OUT"; mkdir -p "$OUT"; chmod 700 "$OUT"

if pgrep -xq "Cisco Secure Client"; then
    echo "quit the Cisco Secure Client app first (it holds the connect capability)" >&2
    exit 2
fi

printf '请输入 VPN 密码（输入时不显示，输完按回车）: ' >&2
IFS= read -rs PASSWORD; echo >&2
echo "connecting (approve the phone push when it arrives)..." >&2

mask() {
    python3 -I -c '
import re, sys
pw, user = sys.argv[1], sys.argv[2]
text = sys.stdin.read()
if pw:
    text = text.replace(pw, "<password>")
if user:
    text = text.replace(user, "<user>")
text = re.sub(r"Username: \[[^\]]*\]", "Username: [<default>]", text)
text = re.sub(r"[A-Za-z0-9.-]+\.(com|io|net|org)\b[^\s\]]*", "<host>", text)
text = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", text)
sys.stdout.write(text)
' "$1" "$USER_NAME"
}

printf 'connect %s\n%s\n%s\n' "$ENTRY" "$USER_NAME" "$PASSWORD" \
    | "$VPN" -s 2>&1 | mask "$PASSWORD" > "$OUT/connect.txt"
unset PASSWORD

{
    echo "== vpn state"; "$VPN" state 2>&1
    echo "== vpn stats"; "$VPN" stats 2>&1
    echo "== route default"; route -n get default 2>&1
    echo "== netstat -rn -f inet"; netstat -rn -f inet 2>&1
    echo "== utun interfaces"; ifconfig 2>&1 | awk '/^utun/{p=1} /^[a-z]/{if($0 !~ /^utun/)p=0} p'
    echo "== scutil --dns (resolver 1-3)"; scutil --dns 2>&1 | sed -n '1,60p'
} | mask "" > "$OUT/snapshot.txt"
chmod 600 "$OUT"/*.txt

grep -E ">> (state|error|notice|warning|alert)" "$OUT/connect.txt" | tail -8
echo "state now: $("$VPN" state 2>&1 | grep -o 'state: [A-Za-z]*' | tail -1)"
echo "files: $OUT/connect.txt $OUT/snapshot.txt"
