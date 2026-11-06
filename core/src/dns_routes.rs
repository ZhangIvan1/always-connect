//! DNS-driven route computation (DESIGN.md §4.2, Cisco dynamic-split /
//! Cloudflare WARP style): a domain's resolved IPs become routes; TTL
//! refresh drops stale IPs and adds new ones; an IP shared by a VPN
//! domain and a direct domain resolves to VPN (fail closed).

use crate::rules::Direction;
use std::collections::HashMap;

/// Current computed route set: destination IP -> direction.
#[derive(Debug, Default)]
pub struct DnsRoutes {
    pub routes: HashMap<String, Direction>,
}

impl DnsRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the route set from fresh DNS answers.
    /// Each answer is (domain, direction, resolved IPs).
    /// Returns the IPs that were claimed by both directions (all forced VPN).
    pub fn update(&mut self, answers: &[(&str, Direction, &[&str])]) -> Vec<String> {
        let mut new: HashMap<String, Direction> = HashMap::new();
        let mut conflicts: Vec<String> = Vec::new();
        for (_, direction, ips) in answers {
            for ip in *ips {
                match new.get(*ip) {
                    Some(existing) if *existing != *direction => {
                        if !conflicts.contains(&ip.to_string()) {
                            conflicts.push(ip.to_string());
                        }
                    }
                    _ => {}
                }
                new.entry(ip.to_string()).or_insert(*direction);
            }
        }
        for ip in &conflicts {
            new.insert(ip.clone(), Direction::Vpn);
        }
        self.routes = new;
        conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_route_set() {
        let mut dr = DnsRoutes::new();
        let c = dr.update(&[
            ("a.corp.example", Direction::Vpn, &["10.9.0.1", "10.9.0.2"]),
            ("v.video.example", Direction::Direct, &["93.184.1.10"]),
        ]);
        assert!(c.is_empty());
        assert_eq!(dr.routes.get("10.9.0.1"), Some(&Direction::Vpn));
        assert_eq!(dr.routes.get("10.9.0.2"), Some(&Direction::Vpn));
        assert_eq!(dr.routes.get("93.184.1.10"), Some(&Direction::Direct));
    }

    #[test]
    fn ttl_refresh_drops_stale_and_adds_new() {
        let mut dr = DnsRoutes::new();
        dr.update(&[("a.corp.example", Direction::Vpn, &["10.9.0.1", "10.9.0.2"])]);
        dr.update(&[("a.corp.example", Direction::Vpn, &["10.9.0.1", "10.9.0.3"])]);
        assert_eq!(dr.routes.get("10.9.0.2"), None);
        assert_eq!(dr.routes.get("10.9.0.3"), Some(&Direction::Vpn));
    }

    #[test]
    fn shared_ip_conflict_forces_vpn() {
        let mut dr = DnsRoutes::new();
        let c = dr.update(&[
            ("a.corp.example", Direction::Vpn, &["203.0.113.5"]),
            ("v.video.example", Direction::Direct, &["203.0.113.5"]),
        ]);
        assert_eq!(c, vec!["203.0.113.5".to_string()]);
        assert_eq!(dr.routes.get("203.0.113.5"), Some(&Direction::Vpn));
    }
}
