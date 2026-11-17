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
    permitted: HashSet<Ipv4Addr>,
    associations: usize,
}
impl SplitPolicy {
    /// True only when effective dynamic permissions change. A VPN-only
    /// observation still records its veto, without forcing route reconciliation.
    pub fn observe(&mut self, name: String, addresses: &[Ipv4Addr], direct: &[Ipv4Addr]) -> bool {
        if self.saturated { return false; }
        let observation: Vec<_> = addresses.iter().map(|ip| (*ip, direct.contains(ip) && crate::direct_routes::ordinary_unicast(*ip))).collect();
        if self.names.get(&name).is_some_and(|c| c.current == observation) { return false; }
        let claims = self.names.entry(name).or_default();
        let old_size=claims.current.len()+claims.vpn.len();
        let affected:HashSet<_>=claims.current.iter().chain(observation.iter()).filter(|(_,allowed)|*allowed).map(|(ip,_)|*ip).collect();
        claims.vpn.extend(addresses.iter().filter(|ip| !direct.contains(ip)).copied());
        claims.current=observation;
        self.associations=self.associations-old_size+claims.current.len()+claims.vpn.len();
        let mut changed=false;
        for ip in addresses.iter().filter(|ip|!direct.contains(ip)) {changed|=self.permitted.remove(ip);}
        if self.enforce_limit() {return true;}
        if self.saturated {return changed;}
        for ip in affected {
            let allowed=self.names.values().any(|c|c.current.iter().any(|(address,direct)|*address==ip&&*direct))
                && !self.names.values().any(|c|c.vpn.contains(&ip));
            changed|=if allowed {self.permitted.insert(ip)}else{self.permitted.remove(&ip)};
        }
        changed
    }
    fn enforce_limit(&mut self)->bool {
        // Never evict a VPN owner to make room for a new bypass.
        if self.names.len()>4096 || self.associations>MAX_ASSOCIATIONS {
            let changed=!self.permitted.is_empty();
            self.names.clear();self.permitted.clear();self.associations=0;self.saturated=true;
            return changed;
        }
        false
    }
    pub fn is_saturated(&self)->bool {self.saturated}
    pub fn allows(&self,ip:&Ipv4Addr)->bool {self.permitted.contains(ip)}
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
        self.associations=self.names.values().map(|c|c.current.len()+c.vpn.len()).sum();
        self.enforce_limit();
        if !self.saturated {
            let veto:HashSet<_>=self.names.values().flat_map(|c|c.vpn.iter().copied()).collect();
            self.permitted=self.names.values().flat_map(|c|c.current.iter()).filter(|(ip,direct)|*direct&&!veto.contains(ip)).map(|(ip,_)|*ip).collect();
        }
    }
    pub fn direct(&self) -> HashSet<String> {
        self.permitted.iter().map(ToString::to_string).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(n: u8) -> Ipv4Addr { Ipv4Addr::new(203, 0, 113, n) }
    #[test]
    fn mixed_special_and_unicast_answers_learn_only_ordinary_addresses() {
        let mut policy=SplitPolicy::default();
        let ips=[std::net::Ipv4Addr::LOCALHOST,std::net::Ipv4Addr::UNSPECIFIED,ip(9)];
        policy.observe("direct.example".into(),&ips,&ips);
        assert_eq!(policy.direct(),HashSet::from([ip(9).to_string()]));
    }

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
    #[test]
    fn vpn_only_observations_change_policy_only_when_they_revoke_a_direct_address() {
        let mut policy=SplitPolicy::default();
        assert!(!policy.observe("vpn.example".into(),&[ip(1)],&[]),"recording a veto alone does not change routing");
        assert!(policy.observe("direct.example".into(),&[ip(2)],&[ip(2)]));
        assert!(!policy.observe("unrelated.example".into(),&[ip(3)],&[]));
        assert!(policy.observe("shared.example".into(),&[ip(2)],&[]),"a shared IP must revoke an actual bypass");
        assert!(policy.direct().is_empty());
    }

}
