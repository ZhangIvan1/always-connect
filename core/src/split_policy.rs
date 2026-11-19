//! Session-local ownership of DNS-learned host routes (§48). A VPN observation
//! vetoes a dynamic direct route to the same IP, regardless of arrival order.
//! Explicit network routes remain a separate, deliberate IP-level exception.
use crate::dns_forwarder::SplitRules;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const MAX_ASSOCIATIONS: usize = 8192;
const MAX_NAMES: usize = 4096;
/// A name not looked up for this long may be forgotten to make room (§61.8).
/// Recently used VPN owners are never evicted for a new bypass.
const IDLE_EVICT: Duration = Duration::from_secs(3600);
struct Claims {
    current: Vec<(Ipv4Addr, bool)>,
    // Historical VPN addresses stay owned by their name. An explicit rule
    // change can release that name's veto, never another name's veto.
    vpn: HashSet<Ipv4Addr>,
    /// Last DNS answer for this name (monotonic; does not advance in sleep).
    seen: Instant,
}
impl Claims {
    /// Distinct addresses this name holds. A VPN answer's address sits in both
    /// `current` and `vpn`; counting it twice halved the budget (§61.3).
    fn size(&self) -> usize {
        self.vpn.len() + self.current.iter().filter(|(ip, _)| !self.vpn.contains(ip)).count()
    }
}
#[derive(Default)]
pub struct SplitPolicy {
    names: HashMap<String, Claims>,
    /// Emergency fallback when every record is recent: all dynamic bypasses
    /// withdrawn, resumed by itself after IDLE_EVICT (no reconnect needed).
    saturated: Option<Instant>,
    permitted: HashSet<Ipv4Addr>,
    associations: usize,
}
impl SplitPolicy {
    /// True only when effective dynamic permissions change. A VPN-only
    /// observation still records its veto, without forcing route reconciliation.
    pub fn observe(&mut self, name: String, addresses: &[Ipv4Addr], direct: &[Ipv4Addr]) -> bool {
        self.observe_at(name, addresses, direct, Instant::now())
    }
    pub(crate) fn observe_at(&mut self, name: String, addresses: &[Ipv4Addr], direct: &[Ipv4Addr], now: Instant) -> bool {
        if let Some(since) = self.saturated {
            // Everything was forgotten at `since`; once that is as old as any
            // record we would evict, resume normal learning.
            if now.saturating_duration_since(since) < IDLE_EVICT { return false; }
            self.saturated = None;
        }
        let observation: Vec<_> = addresses.iter().map(|ip| (*ip, direct.contains(ip) && crate::direct_routes::ordinary_unicast(*ip))).collect();
        match self.names.get_mut(&name) {
            Some(claims) if claims.current==observation => { claims.seen = now; return false; }
            None if observation.is_empty() => return false,
            _=>{},
        }
        // An address-free answer has no new ownership to retain. Existing
        // entries still retire their grants and keep historical VPN vetoes.
        let empty_name=observation.is_empty().then(||name.clone());
        let claims = self.names.entry(name).or_insert_with(|| Claims { current: Vec::new(), vpn: HashSet::new(), seen: now });
        claims.seen = now;
        let old_size=claims.size();
        let affected:HashSet<_>=claims.current.iter().chain(observation.iter()).filter(|(_,allowed)|*allowed).map(|(ip,_)|*ip).collect();
        claims.vpn.extend(addresses.iter().filter(|ip| !direct.contains(ip)).copied());
        claims.current=observation;
        self.associations=self.associations-old_size+claims.size();
        if claims.current.is_empty() && claims.vpn.is_empty() {
            if let Some(name)=empty_name {self.names.remove(&name);}
        }
        let mut changed=false;
        for ip in addresses.iter().filter(|ip|!direct.contains(ip)) {changed|=self.permitted.remove(ip);}
        if self.enforce_limit(now) {return true;}
        if self.saturated.is_some() {return changed;}
        for ip in affected {
            let allowed=self.names.values().any(|c|c.current.iter().any(|(address,direct)|*address==ip&&*direct))
                && !self.names.values().any(|c|c.vpn.contains(&ip));
            changed|=if allowed {self.permitted.insert(ip)}else{self.permitted.remove(&ip)};
        }
        changed
    }
    fn over_limit(&self)->bool { self.names.len()>MAX_NAMES || self.associations>MAX_ASSOCIATIONS }
    /// Make room by forgetting names unused for IDLE_EVICT, oldest first; a
    /// recently used VPN owner is never evicted for a new bypass. Only when
    /// every record is recent does the emergency fallback withdraw all bypasses.
    /// True when effective permissions changed.
    fn enforce_limit(&mut self, now: Instant)->bool {
        if !self.over_limit() { return false; }
        let mut idle: Vec<(Instant, String)> = self.names.iter()
            .filter(|(_, c)| now.saturating_duration_since(c.seen) >= IDLE_EVICT)
            .map(|(name, c)| (c.seen, name.clone())).collect();
        idle.sort_unstable();
        // Evict down to 7/8 of the limits so the scan runs once per batch of
        // new names, not on every DNS answer at the limit.
        let roomy = |p: &Self| p.names.len() <= MAX_NAMES * 7 / 8 && p.associations <= MAX_ASSOCIATIONS * 7 / 8;
        for (_, name) in idle {
            if roomy(self) { break; }
            if let Some(claims) = self.names.remove(&name) { self.associations -= claims.size(); }
        }
        if !self.over_limit() {
            let before = std::mem::take(&mut self.permitted);
            self.rebuild_permitted();
            return before != self.permitted;
        }
        let changed=!self.permitted.is_empty();
        self.names.clear();self.permitted.clear();self.associations=0;self.saturated=Some(now);
        changed
    }
    fn rebuild_permitted(&mut self) {
        let veto:HashSet<_>=self.names.values().flat_map(|c|c.vpn.iter().copied()).collect();
        self.permitted=self.names.values().flat_map(|c|c.current.iter()).filter(|(ip,direct)|*direct&&!veto.contains(ip)).map(|(ip,_)|*ip).collect();
    }
    pub fn is_saturated(&self)->bool {self.saturated.is_some()}
    pub fn allows(&self,ip:&Ipv4Addr)->bool {self.permitted.contains(ip)}
    pub fn direct_name(&self,ip:&Ipv4Addr)->Option<&str> {
        self.names.iter().filter(|(_,claims)|claims.current.iter().any(|(address,direct)|address==ip&&*direct))
            .map(|(name,_)|name.as_str()).min()
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
        self.names.retain(|_,claims|!claims.current.is_empty()||!claims.vpn.is_empty());
        self.associations=self.names.values().map(Claims::size).sum();
        self.enforce_limit(Instant::now());
        if self.saturated.is_none() { self.rebuild_permitted(); }
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
    fn vpn_answers_count_each_address_once_against_the_budget() {
        let mut p = SplitPolicy::default();
        p.observe("direct.example".into(), &[Ipv4Addr::new(198,51,100,1)], &[Ipv4Addr::new(198,51,100,1)]);
        // 4000 ordinary VPN names with two addresses each: 8000 distinct
        // addresses, below the 8192 budget once each is counted once.
        for n in 0..4000u32 {
            let ips: Vec<_> = (0..2).map(|k| Ipv4Addr::from(0x0a00_0000 + n * 4 + k)).collect();
            p.observe(format!("vpn{n}.example"), &ips, &[]);
        }
        assert!(!p.is_saturated(), "a VPN address must not be charged twice");
        assert!(p.direct().contains("198.51.100.1"));
        // Rotation still grows history, and the bound still holds.
        for n in 0..200u32 { p.observe("rotating.example".into(), &[Ipv4Addr::from(0x0b00_0000 + n)], &[]); }
        assert!(p.is_saturated() && p.direct().is_empty());
    }
    fn vpn_names(p: &mut SplitPolicy, from: u32, count: u32, at: Instant) {
        for n in from..from + count {
            p.observe_at(format!("vpn{n}.example"), &[Ipv4Addr::from(0x0a00_0000 + n * 2), Ipv4Addr::from(0x0a00_0000 + n * 2 + 1)], &[], at);
        }
    }
    #[test]
    fn long_sessions_forget_idle_names_instead_of_dropping_the_split() {
        let t0 = Instant::now();
        let mut p = SplitPolicy::default();
        vpn_names(&mut p, 0, 4000, t0);
        let later = t0 + IDLE_EVICT + Duration::from_secs(1);
        // A VPN name still in use keeps its veto; an idle one may be forgotten.
        p.observe_at("vpn0.example".into(), &[Ipv4Addr::from(0x0a00_0000), Ipv4Addr::from(0x0a00_0001)], &[], later);
        p.observe_at("direct.example".into(), &[ip(1)], &[ip(1)], later);
        vpn_names(&mut p, 10_000, 3000, later);
        assert!(!p.is_saturated(), "idle names make room; the split keeps working");
        assert!(p.direct().contains(&ip(1).to_string()));
        assert!(p.names.contains_key("vpn0.example"), "a refreshed VPN owner is not evicted");
        assert!(p.names.len() <= MAX_NAMES && p.associations <= MAX_ASSOCIATIONS);
        // The refreshed name still vetoes a direct claim on its address.
        p.observe_at("shared.direct.example".into(), &[Ipv4Addr::from(0x0a00_0000)], &[Ipv4Addr::from(0x0a00_0000)], later);
        assert!(!p.allows(&Ipv4Addr::from(0x0a00_0000)));
    }
    #[test]
    fn an_evicted_idle_veto_no_longer_blocks_a_current_direct_name() {
        let t0 = Instant::now();
        let mut p = SplitPolicy::default();
        p.observe_at("old-vpn.example".into(), &[ip(7)], &[], t0);
        vpn_names(&mut p, 0, 4000, t0);
        let later = t0 + IDLE_EVICT + Duration::from_secs(1);
        p.observe_at("direct.example".into(), &[ip(7)], &[ip(7)], later);
        assert!(!p.allows(&ip(7)), "the old VPN owner still vetoes before any eviction");
        vpn_names(&mut p, 10_000, 3000, later);
        assert!(p.allows(&ip(7)), "after an hour unused, the old VPN record may be forgotten");
    }
    #[test]
    fn when_every_record_is_recent_the_fallback_recovers_by_itself() {
        let t0 = Instant::now();
        let mut p = SplitPolicy::default();
        p.observe_at("direct.example".into(), &[ip(1)], &[ip(1)], t0);
        vpn_names(&mut p, 0, 4100, t0);
        assert!(p.is_saturated() && p.direct().is_empty(), "no recent VPN owner is evicted for a bypass");
        assert!(!p.observe_at("direct.example".into(), &[ip(1)], &[ip(1)], t0 + Duration::from_secs(60)));
        assert!(p.direct().is_empty());
        assert!(p.observe_at("direct.example".into(), &[ip(1)], &[ip(1)], t0 + IDLE_EVICT));
        assert!(!p.is_saturated() && p.direct().contains(&ip(1).to_string()), "learning resumes without reconnecting");
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
    fn empty_dns_answers_do_not_consume_address_ownership_capacity() {
        let mut empty = SplitPolicy::default();
        empty.observe("active.example".into(), &[ip(9)], &[ip(9)]);
        for n in 0..4097 { empty.observe(format!("{n}.example"), &[], &[]); }
        assert!(!empty.is_saturated(), "address-free answers must not force unrelated direct traffic back into VPN");
        assert_eq!(empty.names.len(),1);
        assert!(empty.allows(&ip(9)));
    }
    #[test]
    fn empty_refresh_retires_unused_claims_but_retains_historical_vpn_vetoes() {
        let mut p=SplitPolicy::default();
        p.observe("direct.example".into(),&[ip(1)],&[ip(1)]);
        assert!(p.observe("direct.example".into(),&[],&[]));
        assert!(p.names.is_empty());assert!(p.direct().is_empty());
        p.observe("vpn.example".into(),&[ip(2)],&[]);
        p.observe("vpn.example".into(),&[],&[]);
        p.observe("other-direct.example".into(),&[ip(2)],&[ip(2)]);
        assert!(!p.allows(&ip(2)),"empty refresh must not forget an earlier VPN conflict");
        assert!(p.names.contains_key("vpn.example"));
    }
    #[test]
    fn rule_revocation_cannot_expand_associations_without_limit() {
        let mut p = SplitPolicy::default();
        for n in 0..4096 { p.observe(format!("{n}.example"), &[ip(1), ip(2)], &[ip(1), ip(2)]); }
        assert!(!p.is_saturated());
        let before = p.associations;
        p.revalidate(&SplitRules::new::<&str>(&[]));
        // A revoked grant becomes that name's VPN veto: the same address, so
        // the distinct count (and the memory bound it implies) cannot grow.
        assert_eq!(p.associations, before);
        assert!(p.direct().is_empty() && !p.is_saturated());
        p.observe("one-more.example".into(), &[ip(3)], &[]);
        assert!(p.is_saturated() && p.names.is_empty(), "the bound still applies after revalidation");
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
