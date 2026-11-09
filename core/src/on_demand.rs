//! Pure on-demand policy and probe wire formats. System I/O stays in the App.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// One ordered rule: conditions are ANDed, values within a condition are ORed.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub network: String,
    pub ssids: Vec<String>,
    pub domains: Vec<String>,
    pub servers: Vec<String>,
    pub probe: Option<Probe>,
    pub action: String,
}
/// An optional physical-interface URL or DNS test, requested only when needed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Probe {
    pub kind: String,
    pub target: String,
}
/// One physical-network snapshot. Missing facts never match a required condition.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Facts {
    pub network: Option<String>,
    pub ssid: Option<String>,
    pub domains: Vec<String>,
    pub servers: Vec<String>,
    pub probes: HashMap<String, bool>,
}
/// Input to the first-match policy; disabled requests always return connect.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Request {
    pub enabled: bool,
    pub rules: Vec<Rule>,
    pub facts: Facts,
}
/// A final action and rule ID, or a request to run one probe and decide again.
#[derive(Debug, Serialize)]
pub struct Decision {
    pub action: String,
    pub rule_id: Option<String>,
    pub probe: Option<Probe>,
}
fn domain_match(p: &str, v: &str) -> bool {
    let p = p.trim_end_matches('.').to_ascii_lowercase();
    let v = v.trim_end_matches('.').to_ascii_lowercase();
    if let Some(s) = p.strip_prefix("*.") {
        !s.is_empty() && v.ends_with(&format!(".{s}")) && v.len() > s.len() + 1
    } else {
        !p.is_empty() && p == v
    }
}
fn any(expected: &[String], actual: &[String], matches: impl Fn(&str, &str) -> bool) -> bool {
    expected.is_empty()
        || expected
            .iter()
            .any(|p| actual.iter().any(|v| matches(p, v)))
}
/// Reject empty rules and malformed condition/probe syntax without doing I/O.
pub fn valid(r: &Rule) -> bool {
    !r.id.is_empty()
        && r.ssids.iter().all(|s| !s.is_empty())
        && r.domains
            .iter()
            .all(|s| dns_query(s.strip_prefix("*.").unwrap_or(s)).is_some())
        && r.servers
            .iter()
            .all(|s| s.parse::<std::net::IpAddr>().is_ok())
        && ["connect", "disconnect", "ignore"].contains(&r.action.as_str())
        && ["", "any", "wifi", "wired"].contains(&r.network.as_str())
        && (r.network == "wifi"
            || r.network == "wired"
            || !r.ssids.is_empty()
            || !r.domains.is_empty()
            || !r.servers.is_empty()
            || r.probe.is_some())
        && r.probe.as_ref().is_none_or(|p| probe_plan(p, 0).is_some())
}
/// Decide using offline facts first; return one probe request at a time.
pub fn decide(q: &Request) -> Decision {
    if q.enabled {
        for r in &q.rules {
            let f = &q.facts;
            if !valid(r)
                || (!r.network.is_empty()
                    && r.network != "any"
                    && f.network.as_deref() != Some(&r.network))
            {
                continue;
            }
            if !r.ssids.is_empty() && !f.ssid.as_ref().is_some_and(|s| r.ssids.contains(s)) {
                continue;
            }
            if !any(&r.domains, &f.domains, domain_match) {
                continue;
            }
            if !any(&r.servers, &f.servers, |p, v| {
                p.parse::<std::net::IpAddr>()
                    .ok()
                    .zip(v.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|(p, v)| p == v)
            }) {
                continue;
            }
            if let Some(p) = &r.probe {
                match f.probes.get(&r.id) {
                    None => {
                        return Decision {
                            action: "probe".into(),
                            rule_id: Some(r.id.clone()),
                            probe: Some(p.clone()),
                        }
                    }
                    Some(false) => continue,
                    Some(true) => (),
                }
            }
            return Decision {
                action: r.action.clone(),
                rule_id: Some(r.id.clone()),
                probe: None,
            };
        }
    }
    Decision {
        action: "connect".into(),
        rule_id: None,
        probe: None,
    }
}
/// Policy state carried between network/settings/manual events.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Runtime {
    /// Automatic connection entries are held by a disconnect rule.
    pub paused: bool,
    /// A session was active before pausing and should resume when allowed.
    pub resume: bool,
    /// The user overrode the rule until the next physical-network/settings event.
    pub manual: bool,
    /// The rule responsible for the retained pause (including an ignore action).
    pub rule_id: Option<String>,
}
/// An event plus current session/launch intent supplied by the system shell.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Transition {
    pub state: Runtime,
    pub event: String,
    pub action: String,
    pub rule_id: Option<String>,
    pub active: bool,
    pub auto_connect: bool,
}
/// Updated policy state and the single system effect to execute.
#[derive(Debug, Serialize)]
pub struct Effect {
    pub state: Runtime,
    pub effect: String,
}
/// Apply policy events; ignore preserves both the pause and its resume intent.
pub fn transition(t: Transition) -> Effect {
    let mut s = t.state;
    let mut effect = "none";
    match t.event.as_str() {
        "manual" => {
            s = Runtime {
                manual: true,
                ..Default::default()
            };
        }
        "network" | "settings" => {
            s.manual = false;
        }
        "decision" if !s.manual => match t.action.as_str() {
            "disconnect" => {
                s.resume |= t.active;
                s.paused = true;
                s.rule_id = t.rule_id;
                effect = "disconnect";
            }
            "connect" => {
                if (s.paused || (t.rule_id.is_some() && !t.active)) && (s.resume || t.auto_connect)
                {
                    effect = "connect";
                }
                s = Runtime::default();
            }
            _ => (),
        },
        _ => (),
    }
    Effect {
        state: s,
        effect: effect.into(),
    }
}
/// Bounded HTTP request and A/AAAA questions for a caller-supplied random ID.
#[derive(Debug, Serialize)]
pub struct ProbePlan {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub request: Vec<u8>,
    pub dns_query: Vec<u8>,
    pub dns_query_v6: Vec<u8>,
}
fn dns_query(host: &str) -> Option<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut q = vec![0x41, 0x43, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in host.split('.') {
        if l.is_empty()
            || l.len() > 63
            || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return None;
        }
        q.push(l.len() as u8);
        q.extend(l.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    Some(q)
}
/// Build probe wire data without I/O. The caller supplies a fresh random ID.
pub fn probe_plan(p: &Probe, transaction_id: u16) -> Option<ProbePlan> {
    let (host, port, tls, request) = match p.kind.as_str() {
        "dns" => (p.target.clone(), 53, false, Vec::new()),
        "url" => {
            let (tls, rest) = if let Some(s) = p.target.strip_prefix("https://") {
                (true, s)
            } else {
                (false, p.target.strip_prefix("http://")?)
            };
            if !rest.is_ascii()
                || rest.bytes().any(|b| b <= 32 || b == 127)
                || rest.contains(['@', '#'])
            {
                return None;
            }
            let at = rest.find(['/', '?']).unwrap_or(rest.len());
            let authority = &rest[..at];
            let (host, port) = match authority.split_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().ok()?),
                None => (authority, if tls { 443 } else { 80 }),
            };
            if port == 0 {
                return None;
            }
            let path = if at == rest.len() {
                "/".into()
            } else if rest.as_bytes()[at] == b'?' {
                format!("/{}", &rest[at..])
            } else {
                rest[at..].into()
            };
            (
                host.into(),
                port,
                tls,
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .into_bytes(),
            )
        }
        _ => return None,
    };
    let mut dns_query = dns_query(&host)?;
    dns_query[..2].copy_from_slice(&transaction_id.to_be_bytes());
    let mut dns_query_v6 = dns_query.clone();
    let n = dns_query_v6.len();
    dns_query_v6[n - 3] = 28;
    dns_query_v6[..2].copy_from_slice(&transaction_id.wrapping_add(1).to_be_bytes());
    Some(ProbePlan {
        dns_query,
        dns_query_v6,
        host,
        port,
        tls,
        request,
    })
}
/// A bounded DNS name decoder. Compression pointers must point backwards;
/// reserved label tags, oversized names and cycles are never accepted.
fn dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut at = start;
    let mut end = None;
    let mut seen = std::collections::HashSet::new();
    let mut labels = Vec::new();
    let mut expanded = 0;
    loop {
        if !seen.insert(at) || seen.len() > 128 {
            return None;
        }
        let size = *packet.get(at)?;
        if size & 0xc0 == 0xc0 {
            let next = *packet.get(at + 1)?;
            let target = ((size as usize & 0x3f) << 8) | next as usize;
            if target >= at {
                return None;
            }
            end.get_or_insert(at + 2);
            at = target;
        } else if size == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        } else {
            if size & 0xc0 != 0 {
                return None;
            }
            let label = packet.get(at + 1..at + 1 + size as usize)?;
            if !label
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            {
                return None;
            }
            expanded += size as usize + 1;
            if expanded > 254 {
                return None;
            }
            labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
            at += size as usize + 1;
        }
    }
}
fn dns_u16(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(packet.get(at..at + 2)?.try_into().ok()?))
}
fn dns_question(packet: &[u8]) -> Option<(String, u16, usize)> {
    if dns_u16(packet, 4)? != 1 {
        return None;
    }
    let (name, end) = dns_name(packet, 12)?;
    let kind = dns_u16(packet, end)?;
    if ![1, 28].contains(&kind) || dns_u16(packet, end + 2)? != 1 {
        return None;
    }
    Some((name, kind, end + 4))
}
/// Return addresses only for the exact outstanding query, following a unique
/// IN CNAME chain from its question. Malformed or unrelated replies fail closed.
fn dns_addresses(packet: &[u8], query: &[u8]) -> Option<Vec<String>> {
    let flags = dns_u16(packet, 2)?;
    if flags & 0x8000 == 0
        || flags & (0x7800 | 0x0200 | 0x000f) != 0
        || dns_u16(packet, 0)? != dns_u16(query, 0)?
    {
        return None;
    }
    if dns_u16(query, 2)? & 0xf800 != 0 {
        return None;
    }
    let (expected, qtype, query_end) = dns_question(query)?;
    if query_end != query.len() {
        return None;
    }
    let (name, kind, mut at) = dns_question(packet)?;
    if name != expected || kind != qtype {
        return None;
    }
    let answers = dns_u16(packet, 6)? as usize;
    let total = answers + dns_u16(packet, 8)? as usize + dns_u16(packet, 10)? as usize;
    let mut aliases = HashMap::<String, String>::new();
    let mut addresses = HashMap::<String, Vec<String>>::new();
    for index in 0..total {
        let (owner, end) = dns_name(packet, at)?;
        let rtype = dns_u16(packet, end)?;
        let class = dns_u16(packet, end + 2)?;
        let length = dns_u16(packet, end + 8)? as usize;
        let data = end + 10;
        let body = packet.get(data..data.checked_add(length)?)?;
        at = data + length;
        if index >= answers {
            continue;
        }
        if [1, 5, 28].contains(&rtype) && class != 1 {
            return None;
        }
        match rtype {
            5 => {
                let (target, name_end) = dns_name(packet, data)?;
                if name_end != at || target.is_empty() {
                    return None;
                }
                if aliases
                    .insert(owner, target.clone())
                    .is_some_and(|old| old != target)
                {
                    return None;
                }
            }
            1 | 28 => {
                let ip = match rtype {
                    1 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(body).ok()?).to_string(),
                    _ => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(body).ok()?).to_string(),
                };
                if rtype == qtype {
                    addresses.entry(owner).or_default().push(ip);
                }
            }
            _ => (),
        }
    }
    if at != packet.len() {
        return None;
    }
    let mut current = expected;
    let mut visited = std::collections::HashSet::new();
    while let Some(next) = aliases.get(&current) {
        if addresses.contains_key(&current) || !visited.insert(current.clone()) {
            return None;
        }
        current = next.clone();
    }
    if visited.contains(&current) {
        return None;
    }
    Some(addresses.remove(&current).unwrap_or_default())
}
/// Parse bounded probe replies. DNS requires the original query bytes (including
/// its random ID); HTTP matches only a 200 status and ignores `query`.
pub fn probe_reply(kind: &str, bytes: &[u8], query: &[u8]) -> serde_json::Value {
    if kind == "dns" {
        let addresses = dns_addresses(bytes, query).unwrap_or_default();
        serde_json::json!({"matched": !addresses.is_empty(), "addresses": addresses})
    } else {
        let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        let mut words = std::str::from_utf8(line).unwrap_or("").split_whitespace();
        let matched = ["HTTP/1.0", "HTTP/1.1"].contains(&words.next().unwrap_or(""))
            && words.next() == Some("200");
        serde_json::json!({"matched": matched})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn d(r: serde_json::Value, f: serde_json::Value) -> Decision {
        decide(
            &serde_json::from_value(serde_json::json!({"enabled":true,"rules":r,"facts":f}))
                .unwrap(),
        )
    }
    #[test]
    fn ordered_and_or_missing_default() {
        let r = serde_json::json!([{"id":"a","network":"wifi","ssids":["Office-WiFi","Lab"],"domains":["*.example.com","other.test"],"action":"disconnect"},{"id":"b","network":"wifi","action":"ignore"}]);
        assert_eq!(
            d(
                r.clone(),
                serde_json::json!({"network":"wifi","ssid":"Lab","domains":["CORP.Example.COM"]})
            )
            .rule_id
            .as_deref(),
            Some("a")
        );
        assert_eq!(
            d(
                r.clone(),
                serde_json::json!({"network":"wifi","ssid":"lab","domains":["corp.example.com"]})
            )
            .rule_id
            .as_deref(),
            Some("b")
        );
        assert_eq!(
            d(r.clone(), serde_json::json!({"network":"wifi"})).action,
            "ignore"
        );
        assert_eq!(d(r, serde_json::json!({})).action, "connect");
        assert!(!domain_match("*.example.com", "example.com"));
        assert!(!domain_match("*.example.com", "notexample.com"));
        assert!(domain_match("EXAMPLE.COM.", "example.com"));
        assert_eq!(decide(&Request::default()).action, "connect");
    }
    #[test]
    fn lazy_probes_and_invalid_empty() {
        let r = serde_json::json!([{"id":"a","ssids":["Office-WiFi"],"probe":{"kind":"dns","target":"intranet.example.com"},"action":"disconnect"},{"id":"b","servers":["10.0.0.53"],"action":"disconnect"}]);
        assert_eq!(d(r.clone(), serde_json::json!({})).action, "connect");
        assert_eq!(
            d(r.clone(), serde_json::json!({"ssid":"Office-WiFi"})).action,
            "probe"
        );
        assert_eq!(
            d(
                r.clone(),
                serde_json::json!({"ssid":"Office-WiFi","probes":{"a":false}})
            )
            .action,
            "connect"
        );
        assert_eq!(
            d(
                r.clone(),
                serde_json::json!({"ssid":"Office-WiFi","probes":{"a":true}})
            )
            .action,
            "disconnect"
        );
        assert_eq!(
            d(r, serde_json::json!({"servers":["10.0.0.53"]}))
                .rule_id
                .as_deref(),
            Some("b")
        );
        assert_eq!(
            d(
                serde_json::json!([{"id":"x","action":"disconnect"}]),
                serde_json::json!({})
            )
            .action,
            "connect"
        );
    }
    #[test]
    fn runtime_manual_ignore_resume() {
        let e = transition(Transition {
            event: "decision".into(),
            action: "disconnect".into(),
            active: true,
            ..Default::default()
        });
        assert!(e.state.paused);
        assert_eq!(e.effect, "disconnect");
        let e = transition(Transition {
            state: e.state,
            event: "decision".into(),
            action: "ignore".into(),
            ..Default::default()
        });
        assert!(e.state.paused);
        let e = transition(Transition {
            state: e.state,
            event: "decision".into(),
            action: "connect".into(),
            ..Default::default()
        });
        assert!(!e.state.paused);
        assert_eq!(e.effect, "connect");
        let e = transition(Transition {
            event: "manual".into(),
            ..Default::default()
        });
        let e = transition(Transition {
            state: e.state,
            event: "decision".into(),
            action: "disconnect".into(),
            ..Default::default()
        });
        assert!(!e.state.paused);
        assert!(
            !transition(Transition {
                state: e.state,
                event: "network".into(),
                ..Default::default()
            })
            .state
            .manual
        );
    }
    #[test]
    fn first_probe_precedes_later_rule_and_falls_through_on_failure() {
        let r = serde_json::json!([
            {"id":"a","network":"wired","probe":{"kind":"url","target":"https://intranet.example.com/"},"action":"ignore"},
            {"id":"b","network":"wired","action":"disconnect"}]);
        assert_eq!(
            d(r.clone(), serde_json::json!({"network":"wired"})).action,
            "probe"
        );
        assert_eq!(
            d(
                r.clone(),
                serde_json::json!({"network":"wired","probes":{"a":true}})
            )
            .action,
            "ignore"
        );
        assert_eq!(
            d(
                r,
                serde_json::json!({"network":"wired","probes":{"a":false}})
            )
            .rule_id
            .as_deref(),
            Some("b")
        );
    }
    #[test]
    fn dns_wire_addresses_and_errors() {
        let p = Probe {
            kind: "dns".into(),
            target: "intranet.example.com".into(),
        };
        let plan = probe_plan(&p, 0x4143).unwrap();
        let mut a = plan.dns_query.clone();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 53]);
        assert_eq!(
            probe_reply("dns", &a, &plan.dns_query)["addresses"][0],
            "10.0.0.53"
        );
        a[3] = 0x83;
        assert_eq!(probe_reply("dns", &a, &plan.dns_query)["matched"], false);
        let mut a = plan.dns_query_v6.clone();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a.extend([0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        a.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(
            probe_reply("dns", &a, &plan.dns_query_v6)["addresses"][0],
            "::1"
        );
        a[0] = 0;
        assert_eq!(probe_reply("dns", &a, &plan.dns_query_v6)["matched"], false);
    }
    #[test]
    fn invalid_conditions_are_not_disconnect_rules() {
        for r in [
            serde_json::json!({"id":"a","network":"any","action":"disconnect"}),
            serde_json::json!({"id":"a","servers":["invalid"],"action":"disconnect"}),
            serde_json::json!({"id":"a","domains":["*bad.example.com"],"action":"disconnect"}),
        ] {
            assert_eq!(
                d(serde_json::json!([r]), serde_json::json!({})).action,
                "connect"
            );
        }
    }
    #[test]
    fn disabled_never_requests_a_probe() {
        let r = Rule {
            id: "a".into(),
            probe: Some(Probe {
                kind: "dns".into(),
                target: "example.com".into(),
            }),
            action: "disconnect".into(),
            ..Default::default()
        };
        assert_eq!(
            decide(&Request {
                enabled: false,
                rules: vec![r],
                ..Default::default()
            })
            .action,
            "connect"
        );
    }
    #[test]
    fn auto_connect_resumes_and_idle_off_does_not() {
        for (auto, expected) in [(true, "connect"), (false, "none")] {
            let e = transition(Transition {
                state: Runtime {
                    paused: true,
                    ..Default::default()
                },
                event: "decision".into(),
                action: "connect".into(),
                auto_connect: auto,
                ..Default::default()
            });
            assert_eq!(e.effect, expected);
            assert!(!e.state.paused);
        }
    }
    fn packet_query() -> Vec<u8> {
        probe_plan(
            &Probe {
                kind: "dns".into(),
                target: "intranet.example.com".into(),
            },
            0x1234,
        )
        .unwrap()
        .dns_query
    }
    fn response(query: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = query.to_vec();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            packet.extend(record);
        }
        packet
    }
    fn wire_name(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }
    fn record(owner: &str, kind: u16, class: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = wire_name(owner);
        bytes.extend(kind.to_be_bytes());
        bytes.extend(class.to_be_bytes());
        bytes.extend(30u32.to_be_bytes());
        bytes.extend((body.len() as u16).to_be_bytes());
        bytes.extend(body);
        bytes
    }
    fn address(owner: &str) -> Vec<u8> {
        record(owner, 1, 1, &[10, 0, 0, 53])
    }
    fn matches(packet: &[u8], query: &[u8]) -> bool {
        probe_reply("dns", packet, query)["matched"] == true
    }

    #[test]
    fn dns_rejects_non_in_addresses() {
        let q = packet_query();
        let p = response(&q, &[record("intranet.example.com", 1, 3, &[10, 0, 0, 53])]);
        assert!(!matches(&p, &q));
        let plan = probe_plan(
            &Probe {
                kind: "dns".into(),
                target: "intranet.example.com".into(),
            },
            99,
        )
        .unwrap();
        let p = response(
            &plan.dns_query_v6,
            &[record("intranet.example.com", 28, 3, &[0; 16])],
        );
        assert!(!matches(&p, &plan.dns_query_v6));
    }
    #[test]
    fn dns_rejects_wrong_question_and_id() {
        let q = packet_query();
        let other = probe_plan(
            &Probe {
                kind: "dns".into(),
                target: "extranet.example.com".into(),
            },
            0x1234,
        )
        .unwrap();
        assert!(!matches(
            &response(&other.dns_query, &[address("extranet.example.com")]),
            &q
        ));
        assert!(!matches(
            &response(
                &other.dns_query_v6,
                &[record("extranet.example.com", 28, 1, &[0; 16])]
            ),
            &q
        ));
        let mut p = response(&q, &[address("intranet.example.com")]);
        p[0] ^= 0xff;
        assert!(!matches(&p, &q));
        let mut p = response(&q, &[address("intranet.example.com")]);
        p[q.len() - 1] = 3;
        assert!(!matches(&p, &q));
        let seeded = probe_plan(
            &Probe {
                kind: "dns".into(),
                target: "intranet.example.com".into(),
            },
            0x5678,
        )
        .unwrap();
        assert_ne!(q[..2], seeded.dns_query[..2]);
        assert_ne!(seeded.dns_query[..2], seeded.dns_query_v6[..2]);
    }
    #[test]
    fn dns_rejects_header_and_truncation_errors() {
        let q = packet_query();
        let good = response(&q, &[address("intranet.example.com")]);
        for (at, mask) in [(2, 0x80), (2, 0x08), (2, 0x02), (3, 0x03)] {
            let mut p = good.clone();
            p[at] ^= mask;
            assert!(!matches(&p, &q));
        }
        for count in [0u16, 2] {
            let mut p = good.clone();
            p[4..6].copy_from_slice(&count.to_be_bytes());
            assert!(!matches(&p, &q));
        }
        for length in 0..good.len() {
            assert!(!matches(&good[..length], &q));
        }
    }
    #[test]
    fn dns_rejects_compression_loops_and_reserved_labels() {
        let q = packet_query();
        let mut p = response(&q, &[address("intranet.example.com")]);
        p[12] = 0xc0;
        p[13] = 12;
        assert!(!matches(&p, &q));
        let mut rr = vec![0xc0, q.len() as u8];
        rr.extend([0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 53]);
        assert!(!matches(&response(&q, &[rr]), &q));
        let mut p = response(&q, &[address("intranet.example.com")]);
        p[12] = 0x40;
        assert!(!matches(&p, &q));
    }
    #[test]
    fn dns_accepts_only_addresses_on_a_valid_cname_chain() {
        let q = packet_query();
        let alias = record(
            "intranet.example.com",
            5,
            1,
            &wire_name("alias.example.com"),
        );
        assert!(matches(
            &response(&q, &[alias.clone(), address("alias.example.com")]),
            &q
        ));
        assert!(!matches(
            &response(&q, &[alias.clone(), address("unrelated.example.com")]),
            &q
        ));
        let unrelated = record(
            "other.example.com",
            5,
            1,
            &wire_name("unrelated.example.com"),
        );
        assert!(!matches(
            &response(&q, &[unrelated, address("unrelated.example.com")]),
            &q
        ));
        let cycle = record(
            "alias.example.com",
            5,
            1,
            &wire_name("intranet.example.com"),
        );
        assert!(!matches(&response(&q, &[alias.clone(), cycle]), &q));
        let conflict = record(
            "intranet.example.com",
            5,
            1,
            &wire_name("other.example.com"),
        );
        assert!(!matches(
            &response(&q, &[alias, conflict, address("other.example.com")]),
            &q
        ));
        assert!(!matches(
            &response(&q, &[address("unrelated.example.com")]),
            &q
        ));
    }
    #[test]
    fn wire_validation() {
        for t in [
            "https://intranet.example.com/check",
            "http://10.0.0.53/?a=b",
        ] {
            assert!(probe_plan(
                &Probe {
                    kind: "url".into(),
                    target: t.into()
                },
                7
            )
            .is_some());
        }
        for t in [
            "file:///etc/hosts",
            "https://user@host/",
            "http://x/\r\nx",
            "https://x:0/",
        ] {
            assert!(probe_plan(
                &Probe {
                    kind: "url".into(),
                    target: t.into()
                },
                7
            )
            .is_none());
        }
        assert_eq!(
            probe_reply("url", b"HTTP/1.1 200 OK\r\n", &[])["matched"],
            true
        );
        assert_eq!(
            probe_reply("url", b"HTTP/1.1 302 Found\r\n", &[])["matched"],
            false
        );
        assert_eq!(probe_reply("dns", b"bad", &[])["matched"], false);
    }
}
