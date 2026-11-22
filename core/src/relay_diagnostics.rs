//! Bounded local connection metadata and an allowlisted public projection.
//! Unknown fields are discarded even when a caller accidentally supplies them.
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Target,
    Dns,
    LocalTls,
    UpstreamTls,
    ServerTrust,
    Authentication,
    Backoff,
    Cancelled,
    Redirect,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Tls,
    Posix,
    Dns,
    Trust,
    Timeout,
    Unknown,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    System,
    Provided,
    Cache,
    Literal,
    PhysicalDns,
    Preflight,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    IdentityUnavailable,
    IdentityExpired,
    GatewayCertificate,
    TransportFailure,
    HandshakeTimeout,
    Capacity,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Event {
    pub session: String,
    pub attempt: u32,
    pub pair: u32,
    pub stage: Stage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_unsafe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_configured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Domain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_source: Option<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

impl Event {
    fn valid(&self) -> bool {
        self.session.len() == 36
            && self.session.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            && self.elapsed_ms.is_none_or(|n| n <= 3_600_000)
            && self.retry_after_ms.is_none_or(|n| n <= 60_000)
            && self.host.iter().chain(self.sni.iter()).all(|s| {
                !s.is_empty()
                    && s.len() <= 253
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            })
            && self
                .ip
                .as_ref()
                .is_none_or(|s| s.parse::<std::net::IpAddr>().is_ok())
    }

    fn public(mut self) -> Self {
        self.host = None;
        self.ip = None;
        self.sni = None;
        self.interface = self.interface.filter(|name| {
            name.len() <= 16
                && ["en", "lo", "utun", "bridge", "awdl", "llw"]
                    .iter()
                    .any(|prefix| {
                        name.strip_prefix(prefix)
                            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
                    })
        });
        self
    }
}

pub fn write(json: &str) {
    if json.len() > 4096 {
        return;
    }
    let Ok(event) = serde_json::from_str::<Event>(json) else {
        return;
    };
    if !event.valid() {
        return;
    }
    if let Ok(json) = serde_json::to_string(&event) {
        crate::relay_log::write(&format!("relay-event {json}"));
    }
}

pub fn project(text: &str) -> String {
    let events: Vec<_> = text
        .lines()
        .rev()
        .filter_map(|line| {
            // relay_log prepends exactly one UTC timestamp. Never copy arbitrary
            // trace text, gateway messages, or the local target fields.
            let (_, record) = line.split_once(' ')?;
            let json = record.strip_prefix("relay-event ")?;
            if json.len() > 4096 {
                return None;
            }
            let event = serde_json::from_str::<Event>(json).ok()?;
            event.valid().then(|| event.public())
        })
        .take(200)
        .collect();
    serde_json::to_string(&events.into_iter().rev().collect::<Vec<_>>())
        .unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_export_drops_targets_unknown_text_and_unbounded_fields() {
        let row = r#"{"session":"00000000-0000-4000-8000-000000000001","attempt":1,"pair":2,"stage":"upstream_tls","domain":"tls","code":-9816,"port":6443,"host":"vpn.example","ip":"198.51.100.7","sni":"vpn.example","interface":"personal-interface","password":"secret-value"}"#;
        let out = project(&format!(
            "2026-01-01T00:00:00Z relay-event {row}\nraw gateway secret-value\n"
        ));
        assert!(
            !out.contains("vpn.example")
                && !out.contains("198.51.100.7")
                && !out.contains("secret-value")
                && !out.contains("personal-interface")
        );
        assert!(out.contains("-9816") && out.contains("6443") && out.contains("upstream_tls"));
        assert_eq!(
            project(&format!(
                "stamp relay-event {}",
                row.replace("\"tls\"", "\"unknown-secret\"")
            )),
            "[]"
        );
    }
    #[test]
    fn only_last_two_hundred_valid_events_are_exported() {
        let text = (0..250).map(|pair| format!(r#"stamp relay-event {{"session":"00000000-0000-4000-8000-000000000001","attempt":0,"pair":{pair},"stage":"target"}}"#)).collect::<Vec<_>>().join("\n");
        let events: Vec<Event> = serde_json::from_str(&project(&text)).unwrap();
        assert_eq!(events.len(), 200);
        assert_eq!(events[0].pair, 50);
    }
}
