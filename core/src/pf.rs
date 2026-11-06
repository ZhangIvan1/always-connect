//! pf kill-switch anchor generator (DESIGN.md §6.4, second line of
//! defense). Pure text generation: no pfctl invocation, no file I/O.
//! The privileged Helper owns loading (`pfctl -a ANCHOR -f file`) and
//! removal (`pfctl -a ANCHOR -F rules`); this module only decides WHAT
//! the rules say, so it is fully testable on Linux.
//!
//! Semantics (pf `quick` = first match wins, so order is the policy):
//! 1. Everything on the tunnel interface passes (it is already inside
//!    the VPN; the kill switch guards the PHYSICAL interface).
//! 2. Loopback passes.
//! 3. DHCP client traffic (UDP 68 -> 67) passes: without it the machine
//!    cannot obtain a LAN address at all.
//! 4. The gateway IPs pass (all protocols): the reconnect itself must
//!    reach the gateway through pf, or the client could never recover
//!    while the rules are installed. This is why gateway endpoints are
//!    REQUIRED (empty list is an error, not a silent footgun).
//! 5. The allowlist networks pass (union of split-excludes and the
//!    kill-switch allowlist, deduplicated, order preserved).
//!    Rules 4, 5 and the DNS pass are `no state`: pf's implicit
//!    `flags S/SA keep state` only lets a TCP connection's first SYN
//!    match, so a connection opened BEFORE the anchor loaded (the
//!    certificate relay's link to the gateway is opened before the
//!    tunnel comes up) had every later packet fall through to the final
//!    block and died by timeout (DESIGN.md §23.6, measured).
//! 6. Bonjour discovery passes (mDNS 224.0.0.251 / ff02::fb port 5353)
//!    and IPv6 link-local (fe80::/10) passes.
//! 7. The final rule depends on the mode (DESIGN.md §17.5):
//!    - blocking set (allow_direct_egress = false, the default): everything
//!      else outbound on the physical interface is dropped. This is the
//!      fail-closed set, loaded when the tunnel is down.
//!    - connected set (allow_direct_egress = true): everything else
//!      outbound on the physical interface passes, so provider-pumped
//!      direct-rule traffic can egress. Loaded only on the connect
//!      hook, while the tunnel is up; a drop reloads the blocking set.
//!
//! Caller responsibilities, stated plainly because the generator cannot
//! enforce them: resolve gateway hostnames to IPs BEFORE calling (this
//! API takes IPs only); regenerate + reload when a gateway IP changes;
//! install these rules only once the tunnel is up (before first connect
//! there is no tunnel and nothing to leak, and no gateway IP is known
//! yet); treat a pfctl load failure as a hard error surfaced to the
//! user, never as a silent skip. Rules are outbound-only; inbound
//! traffic is untouched by this anchor. pfctl itself is the final
//! validator of the generated text.

use std::fmt;

/// pf anchor name the Helper loads this text under. It must sit under
/// an anchor the main ruleset evaluates: macOS's /etc/pf.conf only
/// references `com.apple/*` (and vendor anchors), so a top-level name
/// would load fine and never be evaluated (DESIGN.md §20.5).
pub const ANCHOR: &str = "com.apple/300.AlwaysConnect";

/// Inputs to anchor generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfInput {
    /// Physical interface, e.g. "en0".
    pub physical_if: String,
    /// Tunnel interface, e.g. "utun5".
    pub tunnel_if: String,
    /// Gateway IPs (resolved, not hostnames). Must be non-empty.
    pub gateway_ips: Vec<String>,
    /// Networks allowed out the physical interface, as CIDRs
    /// (e.g. "192.168.0.0/16"). Union of split-excludes and the
    /// kill-switch allowlist; deduplicated in output.
    pub allow_networks: Vec<String>,
    /// Connected set (DESIGN.md §17.5): when true, the final rule
    /// passes the rest of physical-interface outbound instead of
    /// dropping it, so provider-pumped direct traffic can egress.
    /// False (the default) keeps the fail-closed blocking set.
    pub allow_direct_egress: bool,
    /// Let DNS (UDP/TCP port 53) out the physical interface
    /// (DESIGN.md §二十一). The Cisco engine needs it in the blocking
    /// set: re-establishing a lost session resolves the gateway's
    /// hostname, and a resolver off the allowlisted LAN (an office
    /// network's) would otherwise be unreachable, so the client could
    /// never reconnect. Leaks lookups only, never traffic.
    pub allow_dns: bool,
    /// The local network's DNS servers (plan v2, DESIGN.md §25.8): port
    /// 53 passes to these only — the DNS forwarder asks them for the
    /// listed domains. Narrower than `allow_dns`.
    pub dns_servers: Vec<String>,
    /// Plan v2 (§25.8): declare the `<ac_direct>` table in the anchor and
    /// pass outbound to it; the background service fills it with the
    /// addresses of the domains that skip the VPN.
    pub direct_table: bool,
}

/// The direct-address table's name (Sources/Helper/NetworkGuard.swift).
pub const DIRECT_TABLE: &str = "ac_direct";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfError {
    EmptyInterface,
    EmptyGateway,
    BadNetwork(String),
    BadIp(String),
}

impl fmt::Display for PfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfError::EmptyInterface => write!(f, "interface name must be non-empty"),
            PfError::EmptyGateway => write!(
                f,
                "at least one gateway IP is required: without it pf would block the reconnect itself"
            ),
            PfError::BadNetwork(n) => write!(f, "invalid CIDR network: {n}"),
            PfError::BadIp(ip) => write!(f, "invalid IP address: {ip}"),
        }
    }
}

impl std::error::Error for PfError {}

fn valid_iface(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_whitespace())
}

fn valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn valid_ipv6_shape(s: &str) -> bool {
    // Shape check only (pfctl validates fully on load): must contain a
    // colon, no whitespace, no slash, hex digits/colons/dots only.
    !s.is_empty()
        && s.contains(':')
        && !s.contains('/')
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

fn valid_ip(s: &str) -> bool {
    valid_ipv4(s) || valid_ipv6_shape(s)
}

fn valid_cidr(s: &str) -> bool {
    let mut it = s.split('/');
    let (Some(addr), Some(prefix), None) = (it.next(), it.next(), it.next()) else {
        return false;
    };
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let prefix: u32 = match prefix.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    if addr.contains(':') {
        valid_ipv6_shape(addr) && prefix <= 128
    } else {
        valid_ipv4(addr) && prefix <= 32
    }
}

/// Generate the anchor text. Deterministic: same input, same output
/// byte for byte (tests pin the exact text).
pub fn generate(input: &PfInput) -> Result<String, PfError> {
    if !valid_iface(&input.physical_if) || !valid_iface(&input.tunnel_if) {
        return Err(PfError::EmptyInterface);
    }
    if input.gateway_ips.is_empty() {
        return Err(PfError::EmptyGateway);
    }
    for ip in &input.gateway_ips {
        if !valid_ip(ip) {
            return Err(PfError::BadIp(ip.clone()));
        }
    }
    let mut dns_servers: Vec<&str> = Vec::new();
    for ip in &input.dns_servers {
        if !valid_ip(ip) {
            return Err(PfError::BadIp(ip.clone()));
        }
        if !dns_servers.contains(&ip.as_str()) {
            dns_servers.push(ip.as_str());
        }
    }
    let mut networks: Vec<&str> = Vec::new();
    for n in &input.allow_networks {
        if !valid_cidr(n) {
            return Err(PfError::BadNetwork(n.clone()));
        }
        if !networks.contains(&n.as_str()) {
            networks.push(n.as_str());
        }
    }

    let phys = &input.physical_if;
    let mut out = String::new();
    out.push_str("# AlwaysConnect kill-switch anchor (generated; do not hand-edit)\n");
    out.push_str(&format!(
        "# Physical interface: {phys}. Tunnel interface: {}.\n",
        input.tunnel_if
    ));
    if input.direct_table {
        // Declared empty; pf keeps it (persist) while the service adds
        // and deletes addresses without reloading the rules.
        out.push_str(&format!("table <{DIRECT_TABLE}> persist\n"));
    }
    // Tunnel and loopback passes are `no state` like the gateway pass
    // (§26.8): with pf's implicit `flags S/SA keep state` only a SYN
    // matches, so every connection opened before the anchor loaded —
    // openconnect's link to the certificate relay on 127.0.0.1 above
    // all — had its next packet fall through to the final block. The
    // split set ends in a block, so connecting cut the tunnel's own
    // carrier and the Mac went offline (measured 2026-11-05).
    out.push_str(&format!("pass out quick on {} all no state\n", input.tunnel_if));
    // Every tunnel interface passes (§25.7): what enters a utun leaves
    // the Mac only through a physical interface, which stays blocked
    // except for the gateways, so this cannot leak; and a VPN client
    // that re-establishes on a new utun number is not cut off before
    // it has reported the new interface.
    let tuns: Vec<String> = (0..64).map(|n| format!("utun{n}")).collect();
    out.push_str(&format!("pass out quick on {{ {} }} all no state\n", tuns.join(" ")));
    out.push_str("pass out quick on lo0 all no state\n");
    out.push_str("pass out quick proto udp from any port 68 to any port 67\n");
    // Passes and the final block apply to EVERY interface (DESIGN.md
    // §25.3): a drop that moves the default route to another interface
    // (Ethernet, a dock, a phone hotspot) must not leak around a block
    // that only watched the interface in use at connect time.
    for ip in &input.gateway_ips {
        out.push_str(&format!("pass out quick to {ip} no state\n"));
    }
    for n in &networks {
        out.push_str(&format!("pass out quick to {n} no state\n"));
    }
    out.push_str("pass out quick proto udp to 224.0.0.251 port 5353\n");
    out.push_str("pass out quick proto udp to ff02::fb port 5353\n");
    out.push_str("pass out quick inet6 to fe80::/10\n");
    for ip in &dns_servers {
        out.push_str(&format!("pass out quick proto {{ udp tcp }} to {ip} port 53 no state\n"));
    }
    if input.direct_table {
        out.push_str(&format!("pass out quick to <{DIRECT_TABLE}> no state\n"));
    }
    if input.allow_dns {
        out.push_str("pass out quick proto { udp tcp } to any port 53 no state\n");
    }
    if input.allow_direct_egress {
        out.push_str(&format!("pass out quick on {phys} all\n"));
    } else {
        out.push_str("block drop out quick all\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_pass_only_when_asked_and_before_final_block() {
        let mut input = secure_input();
        assert!(!generate(&input).unwrap().contains("to any port 53\n"));
        input.allow_dns = true;
        let text = generate(&input).unwrap();
        let dns = text.find("proto { udp tcp } to any port 53").expect("dns line");
        let block = text.find("block drop out quick all").expect("block line");
        assert!(dns < block);
    }

    fn secure_input() -> PfInput {
        PfInput {
            physical_if: "en0".to_string(),
            tunnel_if: "utun5".to_string(),
            gateway_ips: vec!["203.0.113.10".to_string()],
            allow_networks: vec!["192.168.0.0/16".to_string()],
            allow_direct_egress: false,
            allow_dns: false,
            dns_servers: vec![],
            direct_table: false,
        }
    }

    #[test]
    fn secure_mode_exact_output() {
        let expected = "# AlwaysConnect kill-switch anchor (generated; do not hand-edit)\n\
# Physical interface: en0. Tunnel interface: utun5.\n\
pass out quick on utun5 all no state\n\
pass out quick on { utun0 utun1 utun2 utun3 utun4 utun5 utun6 utun7 utun8 utun9 utun10 utun11 utun12 utun13 utun14 utun15 utun16 utun17 utun18 utun19 utun20 utun21 utun22 utun23 utun24 utun25 utun26 utun27 utun28 utun29 utun30 utun31 utun32 utun33 utun34 utun35 utun36 utun37 utun38 utun39 utun40 utun41 utun42 utun43 utun44 utun45 utun46 utun47 utun48 utun49 utun50 utun51 utun52 utun53 utun54 utun55 utun56 utun57 utun58 utun59 utun60 utun61 utun62 utun63 } all no state\n\
pass out quick on lo0 all no state\n\
pass out quick proto udp from any port 68 to any port 67\n\
pass out quick to 203.0.113.10 no state\n\
pass out quick to 192.168.0.0/16 no state\n\
pass out quick proto udp to 224.0.0.251 port 5353\n\
pass out quick proto udp to ff02::fb port 5353\n\
pass out quick inet6 to fe80::/10\n\
block drop out quick all\n";
        assert_eq!(generate(&secure_input()).unwrap(), expected);
    }

    #[test]
    fn connected_mode_passes_physical_outbound() {
        let input = PfInput {
            allow_direct_egress: true,
            allow_dns: false,
            ..secure_input()
        };
        let expected = "# AlwaysConnect kill-switch anchor (generated; do not hand-edit)\n\
# Physical interface: en0. Tunnel interface: utun5.\n\
pass out quick on utun5 all no state\n\
pass out quick on { utun0 utun1 utun2 utun3 utun4 utun5 utun6 utun7 utun8 utun9 utun10 utun11 utun12 utun13 utun14 utun15 utun16 utun17 utun18 utun19 utun20 utun21 utun22 utun23 utun24 utun25 utun26 utun27 utun28 utun29 utun30 utun31 utun32 utun33 utun34 utun35 utun36 utun37 utun38 utun39 utun40 utun41 utun42 utun43 utun44 utun45 utun46 utun47 utun48 utun49 utun50 utun51 utun52 utun53 utun54 utun55 utun56 utun57 utun58 utun59 utun60 utun61 utun62 utun63 } all no state\n\
pass out quick on lo0 all no state\n\
pass out quick proto udp from any port 68 to any port 67\n\
pass out quick to 203.0.113.10 no state\n\
pass out quick to 192.168.0.0/16 no state\n\
pass out quick proto udp to 224.0.0.251 port 5353\n\
pass out quick proto udp to ff02::fb port 5353\n\
pass out quick inet6 to fe80::/10\n\
pass out quick on en0 all\n";
        assert_eq!(generate(&input).unwrap(), expected);
        // The blocking set is unchanged by the new field's default.
        assert!(generate(&secure_input())
            .unwrap()
            .ends_with("block drop out quick all\n"));
    }

    #[test]
    fn split_mode_extra_networks_and_ipv6() {
        let input = PfInput {
            allow_networks: vec![
                "192.168.0.0/16".to_string(),
                "10.0.0.0/8".to_string(),
                "2001:db8:1::/48".to_string(),
            ],
            gateway_ips: vec!["2001:db8::1".to_string()],
            ..secure_input()
        };
        let text = generate(&input).unwrap();
        // Order preserved: gateway, then allowlist in given order.
        let gw = text.find("to 2001:db8::1 no state\n").unwrap();
        let lan = text.find("to 192.168.0.0/16 no state\n").unwrap();
        let extra = text.find("to 10.0.0.0/8 no state\n").unwrap();
        let v6 = text.find("to 2001:db8:1::/48 no state\n").unwrap();
        let block = text.find("block drop out quick all\n").unwrap();
        assert!(gw < lan && lan < extra && extra < v6 && v6 < block);
    }

    #[test]
    fn blocking_set_covers_every_interface() {
        let text = generate(&secure_input()).unwrap();
        // No pass or block line is tied to the physical interface: a
        // drop that moves traffic to another interface stays blocked.
        assert!(!text.lines().any(|l| l.contains(" on en0")));
        assert!(text.ends_with("block drop out quick all\n"));
    }

    #[test]
    fn passes_before_the_final_block_keep_no_state() {
        // A set that ends in a block must not cut connections opened
        // before it loaded (§23.6, §26.8): openconnect's link to the
        // relay on loopback, traffic already in the tunnel.
        let text = generate(&PfInput { direct_table: true, ..secure_input() }).unwrap();
        for line in text.lines().filter(|l| {
            l.starts_with("pass out quick on ") || l.starts_with("pass out quick to ")
        }) {
            assert!(line.ends_with(" no state"), "stateful pass before the block: {line}");
        }
    }

    #[test]
    fn split_mode_dns_servers_and_direct_table() {
        let input = PfInput {
            dns_servers: vec!["192.168.1.1".to_string(), "192.168.1.1".to_string(), "fd00::1".to_string()],
            direct_table: true,
            ..secure_input()
        };
        let text = generate(&input).unwrap();
        let table = text.find("table <ac_direct> persist\n").expect("table declared");
        let first_rule = text.find("pass out quick on utun5 all").unwrap();
        assert!(table < first_rule, "tables come before rules");
        assert_eq!(
            text.matches("pass out quick proto { udp tcp } to 192.168.1.1 port 53 no state\n").count(),
            1
        );
        assert!(text.contains("pass out quick proto { udp tcp } to fd00::1 port 53 no state\n"));
        let direct = text.find("pass out quick to <ac_direct> no state\n").expect("direct pass");
        assert!(direct < text.find("block drop out quick all").unwrap());
        assert!(!text.contains("to any port 53"), "no blanket DNS pass in split mode");
        let mut bad = input.clone();
        bad.dns_servers = vec!["999.1.1.1".to_string()];
        assert_eq!(generate(&bad), Err(PfError::BadIp("999.1.1.1".to_string())));
    }

    #[test]
    fn no_table_unless_asked() {
        let text = generate(&secure_input()).unwrap();
        assert!(!text.contains("ac_direct"));
    }

    #[test]
    fn allowlist_deduplicated() {
        let input = PfInput {
            allow_networks: vec![
                "192.168.0.0/16".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            ..secure_input()
        };
        let text = generate(&input).unwrap();
        assert_eq!(text.matches("to 192.168.0.0/16 no state\n").count(), 1);
    }

    #[test]
    fn validation_errors() {
        let mut bad = secure_input();
        bad.physical_if = String::new();
        assert_eq!(generate(&bad), Err(PfError::EmptyInterface));
        let mut bad = secure_input();
        bad.tunnel_if = "utun 5".to_string();
        assert_eq!(generate(&bad), Err(PfError::EmptyInterface));
        let mut bad = secure_input();
        bad.gateway_ips = vec![];
        assert_eq!(generate(&bad), Err(PfError::EmptyGateway));
        let mut bad = secure_input();
        bad.gateway_ips = vec!["999.1.1.1".to_string()];
        assert_eq!(
            generate(&bad),
            Err(PfError::BadIp("999.1.1.1".to_string()))
        );
        let mut bad = secure_input();
        bad.allow_networks = vec!["192.168.1.0/33".to_string()];
        assert_eq!(
            generate(&bad),
            Err(PfError::BadNetwork("192.168.1.0/33".to_string()))
        );
        let mut bad = secure_input();
        bad.allow_networks = vec!["not-a-cidr".to_string()];
        assert_eq!(
            generate(&bad),
            Err(PfError::BadNetwork("not-a-cidr".to_string()))
        );
    }
}
