#!/bin/sh
# Stand-in for the openconnect CLI (DESIGN.md §20.8): exercises the
# engine's established-tunnel paths (connect hook, drop, reconnect)
# that a real gateway or tun device would be needed for otherwise.
# Reads the credential line from stdin like --passwd-on-stdin /
# --cookie-on-stdin, prints the CSTP CONNECT cookie header the engine
# captures, runs the given --script connect (the engine's env keeps
# test mode on), stays "up" for FAKE_UP_SECONDS, then runs the
# script's disconnect and exits non-zero: an unexpected drop.
# The script is run the way real openconnect runs it: --script is a
# shell command line for /bin/sh -c, the reason is in $reason (no
# argument). Running it as "$script" connect hid two bugs (§23.5).
script=""
for arg in "$@"; do
  case "$arg" in --script=*) script=${arg#--script=} ;; esac
done
read -r credential || true
# FAKE_SIGNAL_LOG: record how the engine ended this process (HUP keeps
# the session, TERM logs it off, DESIGN.md §30.1).
if [ -n "${FAKE_SIGNAL_LOG:-}" ]; then
  trap 'echo HUP >> "$FAKE_SIGNAL_LOG"; exit 129' HUP
fi
# FAKE_CONNECT_DELAY: a login that takes a while (what happens before
# the tunnel is up).
[ -n "${FAKE_CONNECT_DELAY:-}" ] && sleep "$FAKE_CONNECT_DELAY"
echo "Cookie: webvpn=fakecookie42; webvpncontext=x"
export TUNDEV=utun99 VPNGATEWAY=198.51.100.7 INTERNAL_IP4_ADDRESS=10.9.0.2
# FAKE_CONNECT_HOOK: the connect hook line a real network would give
# (phys=, physgw=, lanex= are absent in test mode), sent instead of the
# script's own.
if [ -n "${FAKE_CONNECT_HOOK:-}" ]; then
  echo "AC_HOOK $FAKE_CONNECT_HOOK"
else
  reason=connect /bin/sh -c "$script" || exit 1
fi
# SIGTERM (a manual stop) ends the stand-in and its sleep together: an
# orphaned sleep would keep the caller's output pipe open.
sleep "${FAKE_UP_SECONDS:-1}" &
up=$!
trap 'kill $up 2>/dev/null; [ -n "${FAKE_SIGNAL_LOG:-}" ] && echo TERM >> "$FAKE_SIGNAL_LOG"; exit 143' TERM
[ -n "${FAKE_SIGNAL_LOG:-}" ] && trap 'kill $up 2>/dev/null; echo HUP >> "$FAKE_SIGNAL_LOG"; exit 129' HUP
wait $up
trap - TERM
# FAKE_INTERNAL_RECONNECT=1: lose the session once and get it back inside
# this process, as openconnect does after a network change (§28.1).
if [ -n "${FAKE_INTERNAL_RECONNECT:-}" ]; then
  reason=attempt-reconnect /bin/sh -c "$script"
  sleep 1
  reason=reconnect /bin/sh -c "$script"
  sleep 1
fi
reason=disconnect /bin/sh -c "$script"
exit 1
