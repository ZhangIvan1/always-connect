//! Session-local ownership of DNS-learned host routes (§48). A VPN observation
//! vetoes a dynamic direct route to the same IP, regardless of arrival order.
//! Explicit network routes remain a separate, deliberate IP-level exception.
use crate::dns_forwarder::SplitRules;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

const MAX_ASSOCIATIONS: usize = 8192;
#[derive(Default)]
struct Claims {
    current: Vec<(Ipv4Addr, bool)>,
    // Historical VPN addresses stay owned by their name. An explicit rule
    // change can release that name's veto, never another name's veto.
    vpn: HashSet<Ipv4Addr>,
}
#[derive(Default)]
pub struct SplitPolicy {
    names: HashMap<String, Claims>,
    saturated: bool,
}
impl SplitPolicy {
    pub fn observe(&mut self, name: String, addresses: &[Ipv4Addr], direct: &[Ipv4Addr]) -> bool {
        if self.saturated { return false; }
        let observation: Vec<_> = addresses.iter().map(|ip| (*ip, direct.contains(ip))).collect();
        if self.names.get(&name).is_some_and(|c| c.current == observation) { return false; }
        let claims = self.names.entry(name).or_default();
        claims.vpn.extend(addresses.iter().filter(|ip| !direct.contains(ip)).copied());
        claims.current = observation;
        self.enforce_limit();
        true
    }
    fn enforce_limit(&mut self) {
        // Never evict a VPN owner to make room for a new bypass.
        if self.names.len() > 4096
            || self.names.values().map(|c| c.current.len() + c.vpn.len()).sum::<usize>() > MAX_ASSOCIATIONS {
            self.names.clear();
            self.saturated = true;
        }
    }
    pub fn revalidate(&mut self, rules: &SplitRules) {
        for (name, claims) in &mut self.names {
            let domain_direct = rules.matches(name).is_some();
            claims.vpn.retain(|ip| !domain_direct && !rules.contains(*ip));
            for (ip, direct) in &mut claims.current {
                let keep = domain_direct || rules.contains(*ip);
                if *direct && !keep { claims.vpn.insert(*ip); }
                // New grants still require a fresh query through the right DNS.
                *direct &= keep;
            }
        }
        self.enforce_limit();
    }
    pub fn direct(&self) -> HashSet<String> {
        let mut wanted = HashSet::new();
        let mut vpn = HashSet::new();
        for claims in self.names.values() {
            for (ip, direct) in &claims.current {
                if *direct { wanted.insert(ip.to_string()); }
            }
            vpn.extend(claims.vpn.iter().map(ToString::to_string));
        }
        wanted.retain(|ip| !vpn.contains(ip));
        wanted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(n: u8) -> Ipv4Addr { Ipv4Addr::new(203, 0, 113, n) }
    #[test]
    fn removing_and_editing_rules_revokes_old_grants() {
        let mut p = SplitPolicy::default();
        p.observe("a.example".into(), &[ip(1), ip(2)], &[ip(1), ip(2)]);
        p.observe("b.example".into(), &[ip(1)], &[ip(1)]);
        p.revalidate(&SplitRules::new(&["b.example"]));
        assert!(!p.direct().contains(&ip(1).to_string()), "removed name becomes a VPN owner, shared IP must follow VPN");
        assert!(p.direct().is_empty());
    }
    #[test]
    fn shared_ip_is_vpn_in_both_arrival_orders() {
        for vpn_first in [false, true] {
            let mut p = SplitPolicy::default();
            if vpn_first { p.observe("vpn.example".into(), &[ip(1)], &[]); }
            p.observe("direct.example".into(), &[ip(1)], &[ip(1)]);
            if !vpn_first { p.observe("vpn.example".into(), &[ip(1)], &[]); }
            assert!(p.direct().is_empty());
        }
    }
    #[test]
    fn refresh_removes_stale_ip_but_preserves_other_direct_owner() {
        let mut p = SplitPolicy::default();
        p.observe("a.example".into(), &[ip(1), ip(2)], &[ip(1), ip(2)]);
        p.observe("b.example".into(), &[ip(1)], &[ip(1)]);
        p.observe("a.example".into(), &[ip(3)], &[ip(3)]);
        assert_eq!(p.direct(), [ip(1).to_string(), ip(3).to_string()].into_iter().collect());
    }
    #[test]
    fn vpn_veto_survives_dns_rotation_and_late_direct_refresh() {
        let mut p = SplitPolicy::default();
        p.observe("vpn.example".into(), &[ip(1)], &[]);
        p.observe("vpn.example".into(), &[ip(2)], &[]);
        p.observe("direct.example".into(), &[ip(1)], &[ip(1)]);
        assert!(p.direct().is_empty(), "old VPN connections must not move to direct after DNS rotation");
    }
    #[test]
    fn explicitly_changing_a_vpn_name_to_direct_clears_only_its_own_veto() {
        let mut p = SplitPolicy::default();
        p.observe("a.example".into(), &[ip(1)], &[]);
        p.revalidate(&SplitRules::new(&["a.example"]));
        p.observe("a.example".into(), &[ip(1)], &[ip(1)]);
        assert!(p.direct().contains(&ip(1).to_string()), "adding a direct rule must work in the current session");
        p.observe("other.example".into(), &[ip(1)], &[]);
        p.revalidate(&SplitRules::new(&["a.example"]));
        p.observe("a.example".into(), &[ip(1)], &[ip(1)]);
        assert!(p.direct().is_empty(), "another VPN name still vetoes the shared address");
    }
    #[test]
    fn empty_dns_answers_are_bounded_and_rule_revocation_cannot_expand_without_limit() {
        let mut empty = SplitPolicy::default();
        for n in 0..4097 { empty.observe(format!("{n}.example"), &[], &[]); }
        assert!(empty.saturated && empty.names.is_empty());
        let mut p = SplitPolicy::default();
        for n in 0..4096 { p.observe(format!("{n}.example"), &[ip(1), ip(2)], &[ip(1), ip(2)]); }
        assert!(!p.saturated);
        p.revalidate(&SplitRules::new::<&str>(&[]));
        assert!(p.saturated && p.names.is_empty());
    }
    #[test]
    fn saturation_revokes_instead_of_forgetting_vpn_conflicts() {
        let mut p = SplitPolicy::default();
        for n in 0..4097 { p.observe(format!("{n}.example"), &[ip(1)], &[ip(1)]); }
        assert!(p.direct().is_empty());
        p.observe("another.example".into(), &[ip(2)], &[ip(2)]);
        assert!(p.direct().is_empty());
        assert!(p.names.is_empty());
    }
}
