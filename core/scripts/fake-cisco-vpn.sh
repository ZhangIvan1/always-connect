#!/bin/bash
# Stand-in for Cisco's `vpn` CLI (DESIGN.md §21.4), shaped after the
# 2026-11-03 transcripts: `>> state: X` lines, the Username/Password
# prompts, "Login error." on a rejected login, `vpn stats` Server
# Address. State lives in $FAKE_CISCO_DIR/state. Password "good"
# connects, "bad" is rejected ("Login error."), "noapprove" lets the
# approval expire ("Login failed." after a while), "quickfail" gets
# "Login failed." at once, "pushfail" fails after the password went in
# (a push was sent), anything else fails before the login form
# (gateway unreachable).
DIR=${FAKE_CISCO_DIR:?}
STATE=$(cat "$DIR/state" 2>/dev/null || echo Disconnected)
banner() { printf '\n  >> state: Unknown\nVPN>   >> state: %s\nVPN>   >> registered with local VPN subsystem.\n' "$STATE"; }
case "${1:-}" in
state) banner ;;
stats) banner; printf '[ Address Information ]\n    Server Address:              198.51.100.9\n' ;;
disconnect) echo cancel >> "$DIR/cancellations"; banner; echo Disconnected > "$DIR/state"; printf '  >> state: Disconnecting\n  >> state: Disconnected\n' ;;
-s)
    banner
    read -r cmd; read -r user; read -r pass
    echo "$cmd" >> "$DIR/commands"
    printf 'VPN> %s\n  >> contacting host for login information...\n' "$cmd"
    case "$pass" in
    good|bad|pushfail|noapprove|quickfail|slow) ;;
    *) printf '  >> error: The VPN connection failed due to unsuccessful domain name resolution.\n'; exit 0 ;;
    esac
    printf '\n  >> Please enter your username and password.\nGroup: Staff\n\nUsername: [default] '
    sleep 0.3
    case "$pass" in
    slow) echo Connecting > "$DIR/state"; exec sleep 30 ;;
    good) sleep 1; echo Connected > "$DIR/state"
          printf '  >> state: Connecting\n  >> notice: Establishing VPN session...\n  >> state: Connected\nVPN> goodbye...\n' ;;
    bad)  printf '\n  >> Login error.\n' ;;
    noapprove) sleep 1; printf '\n  >> Login failed.\n' ;;
    quickfail) printf '\n  >> Login failed.\n' ;;
    *)    printf '\n  >> error: The VPN connection failed: no response from the gateway.\n' ;;
    esac
    ;;
esac
