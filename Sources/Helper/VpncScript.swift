import Foundation

/// The Helper's custom vpnc-script (DESIGN.md §16.4).
///
/// openconnect runs --script as a shell command line (/bin/sh -c, so
/// the engine passes the path shell-quoted: it contains a space) with
/// the reason in the environment as $reason (vpnc-script standard:
/// pre-init, connect, disconnect, attempt-reconnect) next to the tunnel
/// parameters ($TUNDEV, $VPNGATEWAY, $INTERNAL_IP4_ADDRESS,
/// $INTERNAL_IP4_DNS, ...). Tests may pass the reason as $1 instead.
/// Both were wrong until the first real own-connection run (§23.5).
///
/// The two properties that matter for AlwaysConnect, both fully
/// implemented here and testable without a Mac:
/// - connect emits `AC_HOOK connect tun=<if> gateway=<ip>` on stdout
///   so the engine (and only the engine) learns the tunnel is up;
/// - disconnect NEVER tears anything down unless the engine marked
///   this stop as manual: the engine passes the flag file's path in
///   the child's environment at spawn time
///   (ALWAYSCONNECT_MANUAL_FLAG_PATH) and creates that file before
///   terminating the child on a manual stop; the script tests the
///   file's existence. A value set after spawn could never reach
///   the script (its environment is frozen at launch), so no env
///   VALUE is ever consulted here. An unexpected drop leaves routes
///   and pf in place: fail closed.
///
/// Routes, interface and DNS (DESIGN.md §20.4) follow the stock
/// openconnect vpnc-script's Darwin branch — the shape every macOS
/// openconnect user runs — trimmed to AlwaysConnect's full tunnel:
/// - connect configures the utun address, pins a host route to the
///   VPN gateway via the physical default gateway, replaces the
///   default route with one into the utun, and publishes the tunnel
///   DNS as the primary service (scutil State: keys, OverridePrimary).
///   The physical gateway is saved in a Helper-owned state file
///   (ALWAYSCONNECT_ROUTE_STATE_PATH) that survives respawns: after a
///   drop the default route is gone with the old utun, so a reconnect
///   reuses the saved gateway instead of finding none.
/// - restore undoes connect and is idempotent (the state file is the
///   "something to undo" marker). It runs from the manual disconnect
///   branch and again from the Helper after every manual stop, since
///   a child stopped between retries never calls disconnect.
/// Any connect step failing exits non-zero WITHOUT the hook, so the
/// engine never reports Connected when setup did not complete.
/// Test/sandbox runs set ALWAYSCONNECT_NO_ROUTES=1 to skip the
/// macOS-only commands and still exercise the hook logic; the route
/// plan itself is asserted with stubbed route/ifconfig/scutil on PATH
/// (scripts/local-checks.sh, CI). Real-Mac effect: Mac proof B1/B2.
enum VpncScript {
    static let text = #"""
    #!/bin/sh
    # AlwaysConnect vpnc-script. See DESIGN.md §16.4, §20.4.
    # Reason: $reason from openconnect, or $1 from tests.
    # Env: TUNDEV, VPNGATEWAY, INTERNAL_IP4_ADDRESS,
    # INTERNAL_IP4_MTU, INTERNAL_IP4_DNS, CISCO_DEF_DOMAIN,
    # ALWAYSCONNECT_MANUAL_FLAG_PATH, ALWAYSCONNECT_ROUTE_STATE_PATH,
    # ALWAYSCONNECT_NO_ROUTES, ALWAYSCONNECT_GATEWAY_IP,
    # ALWAYSCONNECT_BOOT_SESSION, ALWAYSCONNECT_DNS_FIRST (the domain
    # split's forwarder, asked before the tunnel's servers, §26.5).
    # The route-state file is the journal of what this script changed
    # (DESIGN.md §26.3): it is written BEFORE each change, so a session
    # killed at any point leaves a record that `restore` can undo.
    log() { echo "AC-SCRIPT [$1] $2" >&2; }
    hook() { echo "AC_HOOK $*"; }
    STATE="$ALWAYSCONNECT_ROUTE_STATE_PATH"
    # Through the certificate relay openconnect connects to 127.0.0.1;
    # the gateway's real address comes from the Helper (DESIGN.md §二十三).
    [ -n "$ALWAYSCONNECT_GATEWAY_IP" ] && VPNGATEWAY="$ALWAYSCONNECT_GATEWAY_IP"

    # "<gateway> <interface>" of the physical default route; empty
    # when there is no default route or it already points into a
    # tunnel (a reconnect after a drop: the old default went down
    # with the old utun).
    physical_route() {
      route -n get default 2>/dev/null | awk '
        /gateway:/ { g = $2 } /interface:/ { i = $2 }
        END { if (g != "" && i != "" && i !~ /^(utun|ipsec|ppp)/) print g, i }'
    }
    physical_gw() { physical_route | awk '{ print $1 }'; }

    # "<gateway> <interface>" of the physical network right now, also
    # while our tunnel holds the default route: the scoped default of
    # the last physical interface first, then any other en* (Wi-Fi to
    # Ethernet, a dock, a phone hotspot). Empty when none has one.
    physical_now() {
      for i in $AC_PHYS_IF $(ifconfig -l 2>/dev/null); do
        case "$i" in en*) ;; *) continue ;; esac
        g=$(route -n get -ifscope "$i" default 2>/dev/null | awk '/gateway:/ { print $2 }')
        case "$g" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) echo "$g $i"; return ;; esac
      done
    }

    remove_service_keys() {
      [ -n "$1" ] || return 0
      printf 'open\nremove State:/Network/Service/%s/IPv4\nremove State:/Network/Service/%s/DNS\nclose\n' "$1" "$1" | scutil >/dev/null 2>&1 || true
    }

    load_state() {
      AC_BOOT=""; AC_PHYS_GW=""; AC_PHYS_IF=""; AC_VPN_GW=""; AC_TUN=""; AC_TUNS=""
      if [ -n "$STATE" ] && [ -f "$STATE" ]; then . "$STATE"; fi
    }

    # Journal entry first, change second.
    save_state() {
      printf 'AC_BOOT=%s\nAC_PHYS_GW=%s\nAC_PHYS_IF=%s\nAC_VPN_GW=%s\nAC_TUN=%s\nAC_TUNS="%s"\n' \
        "$AC_BOOT" "$AC_PHYS_GW" "$AC_PHYS_IF" "$AC_VPN_GW" "$AC_TUN" "$AC_TUNS" > "$STATE"
    }

    # Undo connect. Idempotent: without a state file only stale
    # service keys are cleaned. The default route is put back only
    # if none is in place outside a tunnel (configd may already have
    # installed one for a new network while the drop was held).
    restore() {
      load_state
      for t in $AC_TUNS; do remove_service_keys "$t"; done
      remove_service_keys "$AC_TUN"
      remove_service_keys "$TUNDEV"
      [ -n "$STATE" ] && [ -f "$STATE" ] || return 0
      if [ -n "$AC_PHYS_GW" ] && [ -z "$(physical_gw)" ]; then
        route -n delete default >/dev/null 2>&1 || true
        route -n add default "$AC_PHYS_GW" >/dev/null 2>&1 ||
          log restore "default route via $AC_PHYS_GW failed"
      fi
      if [ -n "$AC_VPN_GW" ]; then
        route -n delete -host "$AC_VPN_GW" >/dev/null 2>&1 || true
      fi
      rm -f "$STATE"
    }

    REASON=${1:-${reason:-}}
    case "$REASON" in
      pre-init)
        exit 0
        ;;
      connect)
        if [ -n "$ALWAYSCONNECT_NO_ROUTES" ]; then
          log connect "routes skipped (test mode)"
        else
          [ -n "$STATE" ] || { log connect "no route state path"; exit 1; }
          log connect "split-include=${CISCO_SPLIT_INC:-0} split-exclude=${CISCO_SPLIT_EXC:-0} (full tunnel regardless)"
          ifconfig "$TUNDEV" inet "$INTERNAL_IP4_ADDRESS" "$INTERNAL_IP4_ADDRESS" \
            netmask 255.255.255.255 mtu "${INTERNAL_IP4_MTU:-1300}" up || {
            log connect "ifconfig $TUNDEV failed"; exit 1; }
          load_state
          # The physical network now: the default route if it is one,
          # else the scoped default of an en* interface (after a drop
          # the default went down with the old utun, and the Mac may
          # be on another network than the journal's, §30.2).
          cur=$(physical_route)
          [ -n "$cur" ] || cur=$(physical_now)
          if [ -n "$cur" ]; then
            AC_PHYS_GW=${cur%% *}
            AC_PHYS_IF=${cur#* }
          fi
          [ -n "$AC_PHYS_GW" ] || { log connect "no physical default gateway"; exit 1; }
          if [ -n "$AC_TUN" ] && [ "$AC_TUN" != "$TUNDEV" ]; then
            remove_service_keys "$AC_TUN"
          fi
          # Journal before any change: this boot, the physical default
          # to put back, the gateway host route, every tunnel whose DNS
          # entries we are about to write.
          AC_BOOT="$ALWAYSCONNECT_BOOT_SESSION"
          AC_VPN_GW="$VPNGATEWAY"
          AC_TUN="$TUNDEV"
          case " $AC_TUNS " in *" $TUNDEV "*) ;; *) AC_TUNS="${AC_TUNS:+$AC_TUNS }$TUNDEV";; esac
          save_state || { log connect "route state write failed"; exit 1; }
          route -n add -host "$VPNGATEWAY" "$AC_PHYS_GW" >/dev/null 2>&1 ||
            route -n change -host "$VPNGATEWAY" "$AC_PHYS_GW" >/dev/null 2>&1 || {
            log connect "gateway host route via $AC_PHYS_GW failed"; exit 1; }
          route -n delete default >/dev/null 2>&1 || true
          route -n add default -interface "$TUNDEV" >/dev/null 2>&1 || {
            log connect "default route via $TUNDEV failed"; exit 1; }
          if [ -n "$INTERNAL_IP4_DNS" ]; then
            servers="${ALWAYSCONNECT_DNS_FIRST:+$ALWAYSCONNECT_DNS_FIRST }$INTERNAL_IP4_DNS"
            printf 'open\nd.init\nd.add ServerAddresses * %s\nset State:/Network/Service/%s/DNS\nd.init\nd.add Router %s\nd.add Addresses * %s\nd.add SubnetMasks * 255.255.255.255\nd.add InterfaceName %s\nd.add OverridePrimary # 1\nset State:/Network/Service/%s/IPv4\nclose\n' \
              "$servers" "$TUNDEV" "$INTERNAL_IP4_ADDRESS" "$INTERNAL_IP4_ADDRESS" "$TUNDEV" "$TUNDEV" | scutil >/dev/null 2>&1 || {
              log connect "scutil DNS setup failed"; exit 1; }
            if [ -n "$CISCO_DEF_DOMAIN" ]; then
              printf 'open\nget State:/Network/Service/%s/DNS\nd.add DomainName %s\nd.add SearchDomains * %s\nset State:/Network/Service/%s/DNS\nclose\n' \
                "$TUNDEV" "$CISCO_DEF_DOMAIN" "$CISCO_DEF_DOMAIN" "$TUNDEV" | scutil >/dev/null 2>&1 || true
            fi
          fi
        fi
        # Report the tunnel DNS set to the engine (DESIGN.md §十九):
        # INTERNAL_IP4_DNS is whitespace-separated; the hook line
        # carries it comma-joined. When the gateway sends no DNS,
        # the line has no dns= field at all. phys= is the interface
        # the physical default route used (pf blocks THAT interface,
        # DESIGN.md §20.7); absent in test mode.
        dns_csv=""
        for d in $INTERNAL_IP4_DNS; do
          if [ -z "$dns_csv" ]; then dns_csv="$d"; else dns_csv="$dns_csv,$d"; fi
        done
        line="connect tun=$TUNDEV gateway=$VPNGATEWAY"
        if [ -n "$dns_csv" ]; then line="$line dns=$dns_csv"; fi
        # Private networks the company's gateway itself excludes from the
        # VPN (DESIGN.md §28.5): home LAN gear behind the router (a
        # modem at 192.168.100.1) goes direct, as it does under Cisco.
        lanex=""
        n=0
        while [ "$n" -lt "${CISCO_SPLIT_EXC:-0}" ]; do
          eval "a=\${CISCO_SPLIT_EXC_${n}_ADDR:-} m=\${CISCO_SPLIT_EXC_${n}_MASKLEN:-}"
          case "$a" in
            10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
              case "$m" in [0-9]|[12][0-9]|3[0-2]) lanex="${lanex:+$lanex,}$a/$m" ;; esac ;;
          esac
          n=$((n + 1))
        done
        if [ -n "$lanex" ]; then line="$line lanex=$lanex"; fi
        if [ -z "$ALWAYSCONNECT_NO_ROUTES" ] && [ -n "$AC_PHYS_IF" ]; then
          line="$line phys=$AC_PHYS_IF physgw=$AC_PHYS_GW"
        fi
        hook "$line"
        exit 0
        ;;
      disconnect)
        if [ -n "$ALWAYSCONNECT_MANUAL_FLAG_PATH" ] && [ -f "$ALWAYSCONNECT_MANUAL_FLAG_PATH" ]; then
          # Only a user-confirmed manual disconnect restores the
          # local network. Everything else keeps holding the line.
          if [ -z "$ALWAYSCONNECT_NO_ROUTES" ]; then
            restore
          fi
          hook "disconnect-manual"
        else
          log disconnect "held: routes and pf left in place (not a manual disconnect)"
          hook "disconnect-held"
        fi
        exit 0
        ;;
      restore)
        # Run by the Helper itself after a manual stop, never by
        # openconnect.
        if [ -z "$ALWAYSCONNECT_NO_ROUTES" ]; then
          restore
        fi
        hook "restore"
        exit 0
        ;;
      attempt-reconnect)
        # openconnect calls this before each internal reconnect, so the
        # route to the gateway can follow a network change (DESIGN.md
        # §28.1: home after the office, the old route pointed at the
        # office router and every retry failed for minutes).
        log attempt-reconnect "tunnel layer retrying internally"
        if [ -z "$ALWAYSCONNECT_NO_ROUTES" ]; then
          load_state
          now=$(physical_now)
          if [ -n "$now" ] && [ -n "$VPNGATEWAY" ] && [ "$now" != "$AC_PHYS_GW $AC_PHYS_IF" ]; then
            AC_PHYS_GW=${now%% *}
            AC_PHYS_IF=${now#* }
            save_state || log attempt-reconnect "route state write failed"
            route -n change -host "$VPNGATEWAY" "$AC_PHYS_GW" >/dev/null 2>&1 ||
              route -n add -host "$VPNGATEWAY" "$AC_PHYS_GW" >/dev/null 2>&1 ||
              log attempt-reconnect "gateway host route via $AC_PHYS_GW failed"
            log attempt-reconnect "network changed: gateway now via $AC_PHYS_IF"
          fi
        fi
        if [ -n "$AC_PHYS_IF" ]; then
          hook "attempt-reconnect phys=$AC_PHYS_IF physgw=$AC_PHYS_GW"
        else
          hook "attempt-reconnect"
        fi
        exit 0
        ;;
      follow-network)
        # Run by the Helper when it sees the physical network change
        # while openconnect is not (yet) reconnecting itself — between
        # two attempts after a drop, say (DESIGN.md §30.2): the gateway
        # host route of this session moves to the new router, journal
        # first. Nothing to do without a session's routes in place.
        if [ -z "$ALWAYSCONNECT_NO_ROUTES" ]; then
          load_state
          now=$(physical_now)
          if [ -n "$STATE" ] && [ -f "$STATE" ] && [ -n "$AC_VPN_GW" ] && [ -n "$now" ] &&
             [ "$now" != "$AC_PHYS_GW $AC_PHYS_IF" ]; then
            AC_PHYS_GW=${now%% *}
            AC_PHYS_IF=${now#* }
            save_state || log follow-network "route state write failed"
            route -n change -host "$AC_VPN_GW" "$AC_PHYS_GW" >/dev/null 2>&1 ||
              route -n add -host "$AC_VPN_GW" "$AC_PHYS_GW" >/dev/null 2>&1 ||
              log follow-network "gateway host route via $AC_PHYS_GW failed"
            log follow-network "gateway now via $AC_PHYS_IF"
          fi
        fi
        hook "follow-network"
        exit 0
        ;;
      reconnect)
        # openconnect 9: the session is back on the same tun after an
        # internal reconnect; routes and DNS are still in place.
        log reconnect "tunnel re-established"
        hook "reconnect"
        exit 0
        ;;
      *)
        log "$REASON" "unknown reason, ignoring"
        exit 0
        ;;
    esac
    """#

    /// Writes the script to a Helper-owned file (0700 dir, 0700 file)
    /// and returns its path. The engine passes this path to openconnect
    /// via --script. `overridePath` (run-once tests) skips the install.
    ///
    /// Domain fallback: the root daemon writes to the local domain
    /// (/Library/Application Support); a user-run Helper (run-once
    /// tests, CI) falls back to the user domain when the local domain
    /// is not writable, instead of failing the whole session.
    static func install(to directory: URL? = nil) throws -> String {
        if let directory {
            return try installIn(directory)
        }
        if let dir = TestSeam.supportDir {
            return try installIn(dir)
        }
        let fm = FileManager.default
        let local = fm.urls(for: .applicationSupportDirectory, in: .localDomainMask)
            .first!.appendingPathComponent("AlwaysConnect")
        do {
            return try installIn(local)
        } catch {
            let user = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
                .first!.appendingPathComponent("AlwaysConnect")
            return try installIn(user)
        }
    }

    private static func installIn(_ dir: URL) throws -> String {
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let url = dir.appendingPathComponent("alwaysconnect-vpnc.sh")
        try text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url.path
    }
}
