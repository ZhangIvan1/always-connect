#!/bin/bash
# vpnc-script route plan with stubbed route/ifconfig/scutil
# (DESIGN.md §20.4). Runs the script's real connect/disconnect/restore
# branches with routes ON, but every system command is a PATH stub
# that only logs its argv (and scutil its stdin) and answers
# `route -n get default` from $FAKE_DEFAULT ("<gateway> <interface>",
# or empty for no default route). Proves the plan, not the effect:
# nothing is changed on the host. Usage: vpnc-route-plan-test.sh <script>
set -u
SCRIPT=$1
WORK=$(mktemp -d)
STUBS=$WORK/bin; mkdir -p "$STUBS"
CALLS=$WORK/calls
cat > "$STUBS/route" <<'STUB'
#!/bin/sh
echo "route $*" >> "$CALLS"
[ "${FAKE_SCOPE_DELETE_FAIL:-}" = 1 ] && [ "$2 $3" = "delete -ifscope" ] && exit 1
[ -n "$FAKE_HOST_ROUTE_FAIL" ] && [ "$2 $3" = "add -host" ] && exit 1
[ -n "$FAKE_HOST_ROUTE_FAIL" ] && [ "$2 $3" = "change -host" ] && exit 1
if [ "$1 $2 $3" = "-n get default" ]; then
  [ -n "$FAKE_DEFAULT" ] || exit 1
  set -- $FAKE_DEFAULT
  printf '   route to: default\ndestination: default\n    gateway: %s\n  interface: %s\n' "$1" "$2"
fi
# Scoped default per interface: FAKE_SCOPED="gw if;gw if" (§28.1).
if [ "$1 $2 $3 $5" = "-n get -ifscope default" ]; then
  IFS=';'; for e in ${FAKE_SCOPED:-}; do
    IFS=' '; set -- $e $4
    [ "$2" = "$3" ] && { printf '    gateway: %s\n  interface: %s\n' "$1" "$2"; exit 0; }
  done
  exit 1
fi
exit 0
STUB
cat > "$STUBS/ifconfig" <<'STUB'
#!/bin/sh
echo "ifconfig $*" >> "$CALLS"
[ "$1" = "-l" ] && echo "${FAKE_IFLIST:-lo0 en0}"
if [ "$1" = "-v" ]; then
  if [ "$2" = "${TUNDEV:-}" ]; then
    echo "$2: flags=8051 mtu 1300 index ${FAKE_TUN_INDEX:-107}"
    echo "    inet ${FAKE_TUN_ADDR:-$INTERNAL_IP4_ADDRESS} --> $INTERNAL_IP4_ADDRESS netmask 0xffffffff"
  elif [ "$2" = "${FAKE_OTHER_TUN:-}" ]; then
    echo "$2: flags=8051 mtu 1300 index ${FAKE_OTHER_INDEX:-999}"
    echo "    inet ${FAKE_OTHER_ADDR:-198.51.100.2} --> 198.51.100.2 netmask 0xffffffff"
  else exit 1; fi
fi
exit 0
STUB
cat > "$STUBS/scutil" <<'STUB'
#!/bin/sh
echo "scutil $(tr '\n' ';')" >> "$CALLS"
STUB
cat > "$STUBS/netstat" <<'STUB'
#!/bin/sh
printf 'Destination Gateway Flags Netif Expire\n'
[ "${FAKE_SCOPE_ROUTE_PRESENT:-}" = 1 ] && printf 'default link#107 UCSI %s\n' "${FAKE_SCOPE_ROUTE_TUN:-$TUNDEV}"
exit 0
STUB
chmod +x "$STUBS"/*
export CALLS PATH="$STUBS:$PATH"
export TUNDEV=utun7 VPNGATEWAY=203.0.113.5 INTERNAL_IP4_ADDRESS=10.8.0.2 \
  INTERNAL_IP4_MTU=1390 INTERNAL_IP4_DNS="10.1.1.1 10.1.1.2"
export ALWAYSCONNECT_ROUTE_STATE_PATH=$WORK/route-state ALWAYSCONNECT_BOOT_SESSION=boot-1
unset ALWAYSCONNECT_NO_ROUTES
FAILS=0
expect() { grep -qF -- "$1" "$CALLS" || { echo "  missing: $1"; FAILS=$((FAILS+1)); }; }
reject() { ! grep -qF -- "$1" "$CALLS" || { echo "  unexpected: $1"; FAILS=$((FAILS+1)); }; }
step() { : > "$CALLS"; echo "-- $1"; }

step "fresh connect (default via en0)"
OUT=$(FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect)
echo "$OUT" | grep -q 'AC_HOOK connect tun=utun7 gateway=203.0.113.5 dns=10.1.1.1,10.1.1.2 phys=en0 physgw=192.168.1.1$' || { echo "  hook missing"; FAILS=$((FAILS+1)); }
expect "ifconfig utun7 inet 10.8.0.2 10.8.0.2 netmask 255.255.255.255 mtu 1390 up"
expect "route -n add -host 203.0.113.5 192.168.1.1"
expect "route -n delete default"
expect "route -n add default -interface utun7"
expect "route -n add -ifscope utun7 default -interface utun7"
expect "d.add ServerAddresses * 10.1.1.1 10.1.1.2;set State:/Network/Service/utun7/DNS"
expect "d.add OverridePrimary # 1;set State:/Network/Service/utun7/IPv4"
grep -q '^AC_PHYS_GW=192.168.1.1$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  state gw"; FAILS=$((FAILS+1)); }

step "unexpected drop: disconnect without flag holds"
FAKE_DEFAULT="" "$SCRIPT" disconnect | grep -q 'AC_HOOK disconnect-held' || FAILS=$((FAILS+1))
reject "route -n add default"
reject "remove State:"
[ -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  state lost on hold"; FAILS=$((FAILS+1)); }

step "reconnect after drop (no default route, new utun) reuses saved gateway"
OUT=$(TUNDEV=utun8 FAKE_DEFAULT="" "$SCRIPT" connect)
echo "$OUT" | grep -q 'AC_HOOK connect tun=utun8 .* phys=en0 physgw=192.168.1.1$' || { echo "  hook missing (saved phys)"; FAILS=$((FAILS+1)); }
expect "route -n add -host 203.0.113.5 192.168.1.1"
expect "route -n add default -interface utun8"
expect "remove State:/Network/Service/utun7/IPv4"
grep -q '^AC_TUN=utun8$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  state tun"; FAILS=$((FAILS+1)); }
grep -q '^AC_TUNS="utun7 utun8"$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal keeps every tunnel (§26.3)"; FAILS=$((FAILS+1)); }
grep -q "^AC_BOOT=boot-1$" "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal records the boot"; FAILS=$((FAILS+1)); }

step "manual disconnect restores the saved default"
touch "$WORK/flag"
OUT=$(TUNDEV=utun8 FAKE_DEFAULT="10.8.0.2 utun8" ALWAYSCONNECT_MANUAL_FLAG_PATH=$WORK/flag "$SCRIPT" disconnect)
echo "$OUT" | grep -q 'AC_HOOK disconnect-manual' || FAILS=$((FAILS+1))
expect "remove State:/Network/Service/utun8/IPv4"
expect "remove State:/Network/Service/utun7/DNS"
reject "route -n delete -ifscope utun7 default"
expect "route -n delete -ifscope utun8 default"
expect "route -n add default 192.168.1.1"
expect "route -n delete -host 203.0.113.5"
[ ! -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  state not cleared"; FAILS=$((FAILS+1)); }

step "Helper's second restore is a no-op for routes"
"$SCRIPT" restore | grep -q 'AC_HOOK restore' || FAILS=$((FAILS+1))
reject "route -n add default"
reject "route -n delete"

step "restore keeps a physical default configd already installed"
printf 'AC_BOOT=boot-1\nAC_PHYS_GW=192.168.1.1\nAC_VPN_GW=203.0.113.5\nAC_TUN=utun8\n' > "$ALWAYSCONNECT_ROUTE_STATE_PATH"
FAKE_DEFAULT="172.20.0.1 en0" "$SCRIPT" restore >/dev/null
reject "route -n add default"
reject "route -n delete default"
expect "route -n delete -host 203.0.113.5"

step "connect with no physical gateway and no saved state fails without hook"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
OUT=$(FAKE_DEFAULT="" "$SCRIPT" connect 2>/dev/null); RC=$?
[ $RC -ne 0 ] && ! echo "$OUT" | grep -q AC_HOOK || { echo "  expected failure"; FAILS=$((FAILS+1)); }
reject "route -n add default"

step "through the certificate relay: host route and hook use the real gateway (§二十三)"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
OUT=$(FAKE_DEFAULT="192.168.1.1 en0" VPNGATEWAY=127.0.0.1 ALWAYSCONNECT_GATEWAY_IP=198.51.100.20 "$SCRIPT" connect)
echo "$OUT" | grep -q 'AC_HOOK connect tun=utun7 gateway=198.51.100.20 ' || { echo "  hook gateway"; FAILS=$((FAILS+1)); }
expect "route -n add -host 198.51.100.20 192.168.1.1"
reject "route -n add -host 127.0.0.1"
grep -q '^AC_VPN_GW=198.51.100.20$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  state vpn gw"; FAILS=$((FAILS+1)); }

step "domain split: only the forwarder can resolve names (§48)"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
OUT=$(FAKE_DEFAULT="192.168.1.1 en0" ALWAYSCONNECT_DNS_FIRST=127.0.0.1 "$SCRIPT" connect)
expect "d.add ServerAddresses * 127.0.0.1;set State:/Network/Service/utun7/DNS"
reject "ServerAddresses * 127.0.0.1 10.1.1.1"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null

step "retired utun reused by another VPN is not deleted again"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
TUNDEV=utun8 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
: > "$CALLS"
TUNDEV=utun8 FAKE_OTHER_TUN=utun7 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null
reject "route -n delete -ifscope utun7 default"
expect "route -n delete -ifscope utun8 default"
step "current utun name with a different kernel index belongs to another owner"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
: > "$CALLS"
FAKE_TUN_INDEX=999 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null
reject "route -n delete -ifscope utun7 default"
step "already absent scoped route retires, actual failure preserves its ownership"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
FAKE_SCOPE_DELETE_FAIL=1 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null
[ ! -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  absent scope was not retired"; FAILS=$((FAILS+1)); }
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
if FAKE_SCOPE_DELETE_FAIL=1 FAKE_SCOPE_ROUTE_PRESENT=1 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null 2>&1; then
  echo "  scope failure was reported as restored"; FAILS=$((FAILS+1))
fi
grep -q '^AC_SCOPED_TUN=utun7$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  pending scope lost its ownership"; FAILS=$((FAILS+1)); }
# A new tunnel must not overwrite pending ownership from failed recovery.
: > "$CALLS"
if TUNDEV=utun8 FAKE_OTHER_TUN=utun7 FAKE_OTHER_INDEX=107 FAKE_OTHER_ADDR=10.8.0.2 \
  FAKE_SCOPE_DELETE_FAIL=1 FAKE_SCOPE_ROUTE_PRESENT=1 FAKE_SCOPE_ROUTE_TUN=utun7 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null 2>&1; then
  echo "  pending owner was overwritten by new connect"; FAILS=$((FAILS+1))
fi
grep -q '^AC_SCOPED_TUN=utun7$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  old owner lost"; FAILS=$((FAILS+1)); }
reject "route -n add -ifscope utun8"
TUNDEV=utun8 FAKE_OTHER_TUN=utun7 FAKE_OTHER_INDEX=107 FAKE_OTHER_ADDR=10.8.0.2 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
grep -q '^AC_SCOPED_TUN=utun8$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  successful retirement did not allow replacement"; FAILS=$((FAILS+1)); }
TUNDEV=utun8 FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null
[ ! -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  successful retry retained state"; FAILS=$((FAILS+1)); }

step "another boot's ledger never changes routes"
printf 'AC_BOOT=previous-boot\nAC_PHYS_GW=192.168.1.1\nAC_VPN_GW=203.0.113.1\nAC_TUN=utun7\nAC_SCOPED_TUN=utun7\nAC_SCOPED_INDEX=107\nAC_SCOPED_ADDR=10.8.0.2\n' > "$ALWAYSCONNECT_ROUTE_STATE_PATH"
: > "$CALLS"
FAKE_DEFAULT="" "$SCRIPT" restore >/dev/null
reject "route -n delete"
reject "route -n add"

step "journal comes first: a session cut off at its first change leaves an undoable record (§26.3)"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
OUT=$(FAKE_DEFAULT="192.168.1.1 en0" FAKE_HOST_ROUTE_FAIL=1 "$SCRIPT" connect 2>/dev/null); RC=$?
[ $RC -ne 0 ] || { echo "  expected the connect to fail"; FAILS=$((FAILS+1)); }
grep -q '^AC_VPN_GW=203.0.113.5$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" 2>/dev/null || { echo "  journal not written before the change"; FAILS=$((FAILS+1)); }
: > "$CALLS"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" restore >/dev/null
expect "route -n delete -host 203.0.113.5"
expect "remove State:/Network/Service/utun7/DNS"
[ ! -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  journal not cleared by restore"; FAILS=$((FAILS+1)); }

step "the gateway's private split-excludes are reported (§28.5)"
OUT=$(FAKE_DEFAULT="192.168.1.1 en0" CISCO_SPLIT_EXC=3 \
  CISCO_SPLIT_EXC_0_ADDR=203.0.113.0 CISCO_SPLIT_EXC_0_MASKLEN=24 \
  CISCO_SPLIT_EXC_1_ADDR=192.168.0.0 CISCO_SPLIT_EXC_1_MASKLEN=16 \
  CISCO_SPLIT_EXC_2_ADDR=172.20.0.0 CISCO_SPLIT_EXC_2_MASKLEN=14 "$SCRIPT" connect 2>/dev/null)
echo "$OUT" | grep -q ' lanex=192.168.0.0/16,172.20.0.0/14 ' || { echo "  lanex: $OUT"; FAILS=$((FAILS+1)); }
FAKE_DEFAULT="" "$SCRIPT" restore >/dev/null 2>&1

step "network change: attempt-reconnect moves the gateway route (§28.1)"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
: > "$CALLS"
OUT=$(FAKE_DEFAULT="10.8.0.2 utun7" FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" attempt-reconnect 2>/dev/null)
echo "$OUT" | grep -q 'AC_HOOK attempt-reconnect phys=en0 physgw=10.200.0.1$' || { echo "  hook: $OUT"; FAILS=$((FAILS+1)); }
expect "route -n change -host 203.0.113.5 10.200.0.1"
grep -q '^AC_PHYS_GW=10.200.0.1$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal not updated"; FAILS=$((FAILS+1)); }

step "same network again: nothing moves"
OUT=$(FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" attempt-reconnect 2>/dev/null)
reject "route -n change"
echo "$OUT" | grep -q 'AC_HOOK attempt-reconnect phys=en0 physgw=10.200.0.1$' || { echo "  hook same net"; FAILS=$((FAILS+1)); }

step "moved to another interface (Wi-Fi gone, phone hotspot on en5)"
OUT=$(FAKE_IFLIST="lo0 en0 en5 utun7" FAKE_SCOPED="172.20.10.1 en5" "$SCRIPT" attempt-reconnect 2>/dev/null)
expect "route -n change -host 203.0.113.5 172.20.10.1"
echo "$OUT" | grep -q 'phys=en5 physgw=172.20.10.1$' || { echo "  hook en5: $OUT"; FAILS=$((FAILS+1)); }

step "no physical network yet: route untouched, still reported"
OUT=$(FAKE_IFLIST="lo0 en0" FAKE_SCOPED="" "$SCRIPT" attempt-reconnect 2>/dev/null)
reject "route -n change"
echo "$OUT" | grep -q 'AC_HOOK attempt-reconnect' || { echo "  hook without network"; FAILS=$((FAILS+1)); }

step "reconnected: reported"
"$SCRIPT" reconnect 2>/dev/null | grep -q '^AC_HOOK reconnect tun=utun7 dns=10.1.1.1,10.1.1.2$' || { echo "  reconnect hook"; FAILS=$((FAILS+1)); }
FAKE_DEFAULT="" "$SCRIPT" restore >/dev/null 2>&1

step "drop, then another network: the next connect uses the router there, not the journal's (§30.2)"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
FAKE_DEFAULT="192.168.1.1 en0" "$SCRIPT" connect >/dev/null
FAKE_DEFAULT="" "$SCRIPT" disconnect >/dev/null 2>&1
: > "$CALLS"
OUT=$(TUNDEV=utun8 FAKE_DEFAULT="" FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" connect 2>/dev/null)
echo "$OUT" | grep -q 'phys=en0 physgw=10.200.0.1$' || { echo "  hook: $OUT"; FAILS=$((FAILS+1)); }
expect "route -n add -host 203.0.113.5 10.200.0.1"
reject "route -n add -host 203.0.113.5 192.168.1.1"
grep -q '^AC_PHYS_GW=10.200.0.1$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal not on the new router"; FAILS=$((FAILS+1)); }

step "between two attempts: follow-network moves the gateway route and the journal (§30.2)"
printf 'AC_BOOT=boot-1\nAC_PHYS_GW=192.168.1.1\nAC_PHYS_IF=en0\nAC_VPN_GW=203.0.113.5\nAC_TUN=utun8\nAC_TUNS="utun8"\n' > "$ALWAYSCONNECT_ROUTE_STATE_PATH"
: > "$CALLS"
OUT=$(FAKE_DEFAULT="" FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" follow-network 2>/dev/null)
echo "$OUT" | grep -q '^AC_HOOK follow-network$' || { echo "  follow hook: $OUT"; FAILS=$((FAILS+1)); }
expect "route -n change -host 203.0.113.5 10.200.0.1"
grep -q '^AC_PHYS_GW=10.200.0.1$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal not updated"; FAILS=$((FAILS+1)); }
grep -q '^AC_TUNS="utun8"$' "$ALWAYSCONNECT_ROUTE_STATE_PATH" || { echo "  journal lost its tunnels"; FAILS=$((FAILS+1)); }
: > "$CALLS"
FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" follow-network >/dev/null 2>&1
reject "route -n change"

step "follow-network without a session's routes changes nothing"
rm -f "$ALWAYSCONNECT_ROUTE_STATE_PATH"
: > "$CALLS"
FAKE_SCOPED="10.200.0.1 en0" "$SCRIPT" follow-network >/dev/null 2>&1
reject "route -n change"
reject "route -n add"
[ ! -f "$ALWAYSCONNECT_ROUTE_STATE_PATH" ] || { echo "  journal created from nothing"; FAILS=$((FAILS+1)); }

rm -rf "$WORK"
echo "route-plan FAILS=$FAILS"
[ "$FAILS" -eq 0 ]
