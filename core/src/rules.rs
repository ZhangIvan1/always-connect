//! Split-rule engine (DESIGN.md §4).
//!
//! Priority: LAN hard rule > app rules > domain rules > network rules >
//! default mode. Within one layer, conflicting directions resolve to VPN
//! (fail closed) and the caller is told why.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Vpn,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultMode {
    /// Everything not matched goes through the VPN (Cloudflare "Exclude").
    Secure,
    /// Only matched traffic goes through the VPN (Cloudflare "Include").
    Split,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    App,
    Domain,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub rule_type: RuleType,
    /// App: signing identifier. Domain: `*.example.com` or exact host.
    /// Network: CIDR, e.g. `10.0.0.0/8`.
    pub target: String,
    pub direction: Direction,
    pub enabled: bool,
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut v: u32 = 0;
    for p in parts {
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        v = (v << 8) | n;
    }
    Some(v)
}

fn is_lan(ip: &str) -> bool {
    match parse_ipv4(ip) {
        Some(v) => (v >> 16) == 0xC0A8, // 192.168.0.0/16
        None => false,
    }
}

/// DNS names compare case-insensitively, and a fully qualified name's
/// trailing dot is not part of the host (`Mail.Example.COM.` is
/// `mail.example.com`).
fn domain_matches(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else {
        domain == pattern
    }
}

fn network_matches(cidr: &str, ip: &str) -> bool {
    let (net, plen) = match cidr.split_once('/') {
        Some((n, p)) => (n, p.parse::<u32>().ok()),
        None => return false,
    };
    let (Some(net_v), Some(ip_v), Some(plen)) = (parse_ipv4(net), parse_ipv4(ip), plen) else {
        return false;
    };
    if plen > 32 {
        return false;
    }
    let mask = if plen == 0 {
        0
    } else {
        u32::MAX << (32 - plen)
    };
    (net_v & mask) == (ip_v & mask)
}

/// Resolve a connection to a direction. Returns the direction and a
/// machine-readable reason for the rule tester UI.
pub fn resolve(
    app: &str,
    domain: &str,
    ip: &str,
    rules: &[Rule],
    default: DefaultMode,
) -> (Direction, &'static str) {
    // LAN hard rule wins over everything, even an app rule for VPN.
    if is_lan(ip) {
        return (Direction::Direct, "lan-hard-rule");
    }
    // App layer: match by signing identifier.
    let app_dirs: Vec<Direction> = rules
        .iter()
        .filter(|r| r.enabled && r.rule_type == RuleType::App && r.target == app)
        .map(|r| r.direction)
        .collect();
    if !app_dirs.is_empty() {
        if app_dirs.iter().any(|d| *d != app_dirs[0]) {
            return (Direction::Vpn, "app-conflict->vpn");
        }
        return (app_dirs[0], "app-rule");
    }
    // Domain layer: wildcard suffix match.
    let dom_dirs: Vec<Direction> = rules
        .iter()
        .filter(|r| {
            r.enabled && r.rule_type == RuleType::Domain && domain_matches(&r.target, domain)
        })
        .map(|r| r.direction)
        .collect();
    if !dom_dirs.is_empty() {
        if dom_dirs.iter().any(|d| *d != dom_dirs[0]) {
            return (Direction::Vpn, "domain-conflict->vpn");
        }
        return (dom_dirs[0], "domain-rule");
    }
    // Network layer: CIDR match.
    let net_dirs: Vec<Direction> = rules
        .iter()
        .filter(|r| r.enabled && r.rule_type == RuleType::Network && network_matches(&r.target, ip))
        .map(|r| r.direction)
        .collect();
    if !net_dirs.is_empty() {
        if net_dirs.iter().any(|d| *d != net_dirs[0]) {
            return (Direction::Vpn, "network-conflict->vpn");
        }
        return (net_dirs[0], "network-rule");
    }
    match default {
        DefaultMode::Secure => (Direction::Vpn, "default-secure"),
        DefaultMode::Split => (Direction::Direct, "default-split"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn domain_match_ignores_case_and_trailing_dot() {
        assert!(domain_matches("*.example.com", "Mail.Example.COM."));
        assert!(domain_matches("Example.com", "example.COM"));
        assert!(!domain_matches("*.example.com", "badexample.com"));
        assert!(!domain_matches("*.example.com", ""));
    }

    use super::*;

    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                rule_type: RuleType::App,
                target: "com.example.workapp".into(),
                direction: Direction::Vpn,
                enabled: true,
            },
            Rule {
                rule_type: RuleType::Domain,
                target: "*.video.example".into(),
                direction: Direction::Direct,
                enabled: true,
            },
            Rule {
                rule_type: RuleType::Network,
                target: "10.0.0.0/8".into(),
                direction: Direction::Vpn,
                enabled: true,
            },
        ]
    }

    #[test]
    fn app_rule_beats_domain_and_default() {
        let (d, _) = resolve(
            "com.example.workapp",
            "a.video.example",
            "1.2.3.4",
            &rules(),
            DefaultMode::Split,
        );
        assert_eq!(d, Direction::Vpn);
    }

    #[test]
    fn domain_wildcard_matches() {
        let (d, _) = resolve(
            "other.app",
            "a.video.example",
            "1.2.3.4",
            &rules(),
            DefaultMode::Secure,
        );
        assert_eq!(d, Direction::Direct);
        let (d, _) = resolve(
            "other.app",
            "video.example",
            "1.2.3.4",
            &rules(),
            DefaultMode::Secure,
        );
        assert_eq!(d, Direction::Direct);
        let (d, _) = resolve(
            "other.app",
            "notvideo.example",
            "1.2.3.4",
            &rules(),
            DefaultMode::Secure,
        );
        assert_eq!(d, Direction::Vpn);
    }

    #[test]
    fn network_cidr_matches() {
        let (d, _) = resolve(
            "other.app",
            "other.com",
            "10.5.6.7",
            &rules(),
            DefaultMode::Split,
        );
        assert_eq!(d, Direction::Vpn);
        let (d, _) = resolve(
            "other.app",
            "other.com",
            "11.5.6.7",
            &rules(),
            DefaultMode::Split,
        );
        assert_eq!(d, Direction::Direct);
    }

    #[test]
    fn defaults() {
        let (d, _) = resolve(
            "other.app",
            "other.com",
            "1.2.3.4",
            &rules(),
            DefaultMode::Secure,
        );
        assert_eq!(d, Direction::Vpn);
        let (d, _) = resolve(
            "other.app",
            "other.com",
            "1.2.3.4",
            &rules(),
            DefaultMode::Split,
        );
        assert_eq!(d, Direction::Direct);
    }

    #[test]
    fn lan_hard_rule_beats_app_vpn() {
        let (d, why) = resolve(
            "com.example.workapp",
            "router.home",
            "192.168.1.1",
            &rules(),
            DefaultMode::Secure,
        );
        assert_eq!(d, Direction::Direct);
        assert_eq!(why, "lan-hard-rule");
    }

    #[test]
    fn domain_conflict_fails_closed_to_vpn() {
        let mut r = rules();
        r.push(Rule {
            rule_type: RuleType::Domain,
            target: "*.video.example".into(),
            direction: Direction::Vpn,
            enabled: true,
        });
        let (d, why) = resolve(
            "other.app",
            "a.video.example",
            "1.2.3.4",
            &r,
            DefaultMode::Split,
        );
        assert_eq!(d, Direction::Vpn);
        assert_eq!(why, "domain-conflict->vpn");
    }

    #[test]
    fn disabled_rule_ignored() {
        let mut r = rules();
        r[0].enabled = false;
        let (d, _) = resolve("com.example.workapp", "x.com", "1.2.3.4", &r, DefaultMode::Split);
        assert_eq!(d, Direction::Direct);
    }
}
