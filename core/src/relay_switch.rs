//! A relay handover is a one-shot transaction, never a user disconnect.
//! System adapters supply actual process/listener completion; elapsed time is
//! measured here, independently of timers or callbacks in either adapter.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Command {
    Preparing {
        session: String,
    },
    Status,
    Prepared {
        session: String,
    },
    Watch {
        session: String,
    },
    Expire {
        session: String,
        epoch: String,
    },
    Register {
        session: String,
        target: String,
        pin: String,
        allowed: Vec<String>,
    },
    Begin {
        session: String,
        attempt: u32,
        pin: String,
        source: String,
        location: String,
        status: u16,
        replay_unsafe: bool,
    },
    EngineStopped {
        ticket: String,
    },
    Commit {
        ticket: String,
        target: String,
        pin: String,
        listener_closed: bool,
    },
    Fail {
        session: String,
    },
    Cancel {
        session: String,
    },
    Reset,
}

#[derive(Debug, Serialize)]
pub struct Reply {
    pub ok: bool,
    pub code: &'static str,
    pub ticket: Option<String>,
    pub target: Option<String>,
    pub attempt: u32,
    pub epoch: Option<String>,
    pub remaining_ms: Option<u32>,
}

impl Reply {
    fn error(code: &'static str) -> Self {
        Self {
            ok: false,
            code,
            ticket: None,
            epoch: None,
            remaining_ms: None,
            target: None,
            attempt: 0,
        }
    }
}

#[derive(Default)]
enum Phase {
    #[default]
    Inactive,
    Preparing,
    Active,
    Stopping {
        ticket: String,
        target: String,
    },
    Ready {
        ticket: String,
        target: String,
    },
    Failed,
    TimedOut,
}

/// Only exact configured HTTPS authorities are eligible. No suffix matching,
/// domain inference, userinfo, query/fragment replay or path token copying.
fn endpoint(value: &str) -> Option<String> {
    let rest = value.strip_prefix("https://")?;
    if rest.bytes().any(|b| b <= 32 || b >= 127 || b == b'\\') {
        return None;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if !path.is_empty() || authority.contains(['@', '?', '#', '[', ']']) {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok().filter(|p| *p > 0)?),
        None => (authority, 443),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(format!("https://{}:{port}/", host.to_ascii_lowercase()))
}

pub struct Handover {
    phase: Phase,
    sequence: u64,
    session: String,
    target: String,
    pin: String,
    allowed: BTreeSet<String>,
    visited: BTreeSet<String>,
    attempt: u32,
    since: Instant,
    budget: Duration,
}

impl Default for Handover {
    fn default() -> Self {
        Self {
            phase: Phase::Inactive,
            sequence: 0,
            session: String::new(),
            target: String::new(),
            pin: String::new(),
            allowed: BTreeSet::new(),
            visited: BTreeSet::new(),
            attempt: 0,
            since: Instant::now(),
            budget: Duration::from_secs(60),
        }
    }
}

impl Handover {
    /// Shorter budgets are useful to adapters testing a missing callback.
    /// No caller can increase the production maximum.
    pub fn with_budget(milliseconds: u32) -> Self {
        Self {
            budget: Duration::from_millis(milliseconds.clamp(1, 60_000) as u64),
            ..Self::default()
        }
    }

    fn waiting(&self) -> bool {
        matches!(
            self.phase,
            Phase::Preparing | Phase::Stopping { .. } | Phase::Ready { .. } | Phase::TimedOut
        )
    }

    fn remaining_ms(&self, now: Instant) -> u32 {
        let remaining = self
            .budget
            .saturating_sub(now.saturating_duration_since(self.since));
        remaining.as_nanos().div_ceil(1_000_000) as u32
    }

    pub fn command(&mut self, command: Command) -> Reply {
        self.command_at(command, Instant::now())
    }

    fn command_at(&mut self, command: Command, now: Instant) -> Reply {
        match command {
            Command::Preparing { session } => {
                let Some(sequence) = self.sequence.checked_add(1) else {
                    self.phase = Phase::Failed;
                    return Reply::error("ticket_exhausted");
                };
                self.sequence = sequence;
                self.since = now;
                self.phase = Phase::Preparing;
                self.session = session;
                self.target = String::new();
                self.pin = String::new();
                self.allowed.clear();
                self.visited.clear();
                self.attempt = 0;
                Reply {
                    ok: true,
                    code: "preparing",
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: None,
                    attempt: 0,
                }
            }
            Command::Prepared { session } => {
                if self.session != session || !matches!(self.phase, Phase::Preparing) {
                    return Reply::error("stale_context");
                }
                if self.remaining_ms(now) == 0 {
                    self.phase = Phase::TimedOut;
                    return Reply::error("redirect_deadline");
                }
                self.command_at(Command::Cancel { session }, now)
            }
            Command::Watch { session } => {
                if self.session != session || !self.waiting() {
                    return Reply::error("stale_context");
                }
                let mut reply = Reply::error("watch_deadline");
                reply.ok = true;
                reply.epoch = Some(self.sequence.to_string());
                reply.remaining_ms = Some(self.remaining_ms(now));
                reply
            }
            Command::Expire { session, epoch } => {
                if self.session != session || self.sequence.to_string() != epoch || !self.waiting()
                {
                    return Reply::error("stale_context");
                }
                if self.remaining_ms(now) != 0 {
                    return Reply::error("deadline_not_reached");
                }
                self.phase = Phase::Failed;
                Reply::error("redirect_deadline")
            }
            Command::Status => {
                // Observing status must not consume the deadline notification.
                let code = if self.waiting() && self.remaining_ms(now) == 0 {
                    "expired"
                } else {
                    match &self.phase {
                        Phase::Inactive => "inactive",
                        Phase::Preparing => "preparing",
                        Phase::Active => "active",
                        Phase::Stopping { .. } => "stopping",
                        Phase::Ready { .. } => "ready",
                        Phase::Failed => "failed",
                        Phase::TimedOut => "expired",
                    }
                };

                Reply {
                    ok: true,
                    code,
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: None,
                    attempt: self.attempt,
                }
            }
            Command::Register {
                session,
                target,
                pin,
                allowed,
            } => {
                // Registering the prepared relay retains its original budget.
                let prepared = matches!(self.phase, Phase::Preparing) && self.session == session;
                if prepared && self.remaining_ms(now) == 0 {
                    self.phase = Phase::TimedOut;
                    return Reply::error("redirect_deadline");
                }
                // A new intent revokes the previous ticket even if malformed.
                self.phase = Phase::Inactive;
                if session.is_empty()
                    || session.len() > 128
                    || pin.is_empty()
                    || allowed.len() > 256
                {
                    return Reply::error("invalid_context");
                }
                let Some(target) = endpoint(&target) else {
                    return Reply::error("invalid_target");
                };
                let Some(allowed) = allowed
                    .iter()
                    .map(|s| endpoint(s))
                    .collect::<Option<BTreeSet<_>>>()
                else {
                    return Reply::error("invalid_allowlist");
                };
                if !allowed.contains(&target) {
                    return Reply::error("target_not_allowed");
                }
                self.session = session;
                self.target = target.clone();
                self.pin = pin;
                self.allowed = allowed;
                self.visited = BTreeSet::from([target.clone()]);
                self.attempt = 0;
                if !prepared {
                    self.since = now;
                }
                self.phase = Phase::Active;
                Reply {
                    ok: true,
                    code: "registered",
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: Some(target),
                    attempt: 0,
                }
            }
            Command::Begin {
                session,
                attempt,
                pin,
                source,
                location,
                status,
                replay_unsafe,
            } => {
                if session != self.session
                    || attempt != self.attempt
                    || pin != self.pin
                    || endpoint(&source).as_ref() != Some(&self.target)
                    || !matches!(self.phase, Phase::Active)
                {
                    return Reply::error("stale_context");
                }
                let rejection = if status != 302 {
                    Some("unsupported_redirect")
                } else if replay_unsafe {
                    Some("authentication_replay_unsafe")
                } else if now.saturating_duration_since(self.since) >= self.budget {
                    Some("redirect_deadline")
                } else if self.attempt >= 3 {
                    Some("redirect_limit")
                } else {
                    None
                };
                if let Some(code) = rejection {
                    self.phase = if code == "redirect_deadline" {
                        Phase::TimedOut
                    } else {
                        Phase::Failed
                    };
                    return Reply::error(code);
                }
                let Some(target) = endpoint(&location) else {
                    self.phase = Phase::Failed;
                    return Reply::error("unsupported_target");
                };
                if !self.allowed.contains(&target) {
                    self.phase = Phase::Failed;
                    return Reply::error("target_not_allowed");
                }
                if self.visited.contains(&target) {
                    self.phase = Phase::Failed;
                    return Reply::error("redirect_loop");
                }
                self.sequence = match self.sequence.checked_add(1) {
                    Some(n) => n,
                    None => {
                        self.phase = Phase::Failed;
                        return Reply::error("ticket_exhausted");
                    }
                };
                let ticket = format!("{}:{}:{}", self.session, self.attempt, self.sequence);
                self.phase = Phase::Stopping {
                    ticket: ticket.clone(),
                    target: target.clone(),
                };
                Reply {
                    ok: true,
                    code: "stop_engine",
                    ticket: Some(ticket),
                    epoch: None,
                    remaining_ms: None,
                    target: Some(target),
                    attempt: self.attempt,
                }
            }
            Command::EngineStopped { ticket } => {
                let Phase::Stopping {
                    ticket: expected,
                    target,
                } = &self.phase
                else {
                    return Reply::error("stale_ticket");
                };
                if *expected != ticket {
                    return Reply::error("stale_ticket");
                }
                if now.saturating_duration_since(self.since) >= self.budget {
                    self.phase = Phase::TimedOut;
                    return Reply::error("redirect_deadline");
                }
                let target = target.clone();
                self.phase = Phase::Ready {
                    ticket: ticket.clone(),
                    target: target.clone(),
                };
                Reply {
                    ok: true,
                    code: "stop_listener",
                    ticket: Some(ticket),
                    epoch: None,
                    remaining_ms: None,
                    target: Some(target),
                    attempt: self.attempt,
                }
            }
            Command::Commit {
                ticket,
                target,
                pin,
                listener_closed,
            } => {
                let Phase::Ready {
                    ticket: expected,
                    target: next,
                } = &self.phase
                else {
                    return Reply::error("stale_ticket");
                };
                if *expected != ticket || endpoint(&target).as_ref() != Some(next) {
                    return Reply::error("stale_ticket");
                }
                if !listener_closed || pin.is_empty() || pin == self.pin {
                    return Reply::error("relay_not_ready");
                }
                if now.saturating_duration_since(self.since) >= self.budget {
                    self.phase = Phase::TimedOut;
                    return Reply::error("redirect_deadline");
                }
                self.target = next.clone();
                self.visited.insert(self.target.clone());
                self.pin = pin;
                self.attempt += 1;
                self.phase = Phase::Active;
                Reply {
                    ok: true,
                    code: "start_engine",
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: Some(self.target.clone()),
                    attempt: self.attempt,
                }
            }
            Command::Fail { session } => {
                let mut reply = self.command_at(Command::Cancel { session }, now);
                if reply.ok {
                    self.phase = Phase::Failed;
                    reply.code = "failed";
                }
                reply
            }
            Command::Cancel { session } => {
                if session != self.session {
                    return Reply::error("stale_context");
                }
                self.phase = Phase::Inactive;
                self.session = String::new();
                self.target = String::new();
                self.pin = String::new();
                self.allowed.clear();
                self.visited.clear();
                Reply {
                    ok: true,
                    code: "cancelled",
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: None,
                    attempt: self.attempt,
                }
            }
            Command::Reset => {
                self.phase = Phase::Inactive;
                self.session = String::new();
                self.target = String::new();
                self.pin = String::new();
                self.allowed.clear();
                self.visited.clear();
                Reply {
                    ok: true,
                    code: "cancelled",
                    ticket: None,
                    epoch: None,
                    remaining_ms: None,
                    target: None,
                    attempt: self.attempt,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_covers_silent_preparation_and_each_handover_wait() {
        let now = Instant::now();
        for phase in 0..3 {
            let mut s = Handover::with_budget(100);
            if phase == 0 {
                s.command_at(
                    Command::Preparing {
                        session: "test-session".into(),
                    },
                    now,
                );
            } else {
                register(&mut s, now);
                let ticket = begin(&mut s, 1, now).ticket.unwrap();
                if phase == 2 {
                    assert!(s.command_at(Command::EngineStopped { ticket }, now).ok);
                }
            }
            let watch = s.command_at(
                Command::Watch {
                    session: "test-session".into(),
                },
                now,
            );
            assert_eq!(watch.remaining_ms, Some(100));
            let epoch = watch.epoch.unwrap();
            assert_eq!(
                s.command_at(
                    Command::Expire {
                        session: "test-session".into(),
                        epoch: epoch.clone()
                    },
                    now + Duration::from_millis(99)
                )
                .code,
                "deadline_not_reached"
            );
            // A status observation cannot eat the one-shot timeout delivery.
            assert_eq!(
                s.command_at(Command::Status, now + Duration::from_millis(100))
                    .code,
                "expired"
            );
            assert_eq!(
                s.command_at(
                    Command::Expire {
                        session: "test-session".into(),
                        epoch
                    },
                    now + Duration::from_millis(100)
                )
                .code,
                "redirect_deadline"
            );
            assert_eq!(
                s.command_at(Command::Status, now + Duration::from_millis(100))
                    .code,
                "failed"
            );
        }
    }

    #[test]
    fn relay_registration_or_direct_readiness_cannot_reset_an_expired_preparation() {
        let now = Instant::now();
        let mut s = Handover::with_budget(100);
        s.command_at(
            Command::Preparing {
                session: "test-session".into(),
            },
            now,
        );
        register(&mut s, now + Duration::from_millis(50));
        begin(&mut s, 1, now + Duration::from_millis(75));
        assert_eq!(
            s.command_at(
                Command::Watch {
                    session: "test-session".into()
                },
                now + Duration::from_millis(75)
            )
            .remaining_ms,
            Some(25)
        );
        let mut direct = Handover::with_budget(100);
        direct.command_at(
            Command::Preparing {
                session: "test-session".into(),
            },
            now,
        );
        assert_eq!(
            direct
                .command_at(
                    Command::Prepared {
                        session: "test-session".into()
                    },
                    now + Duration::from_millis(100)
                )
                .code,
            "redirect_deadline"
        );
        assert!(
            direct
                .command_at(
                    Command::Fail {
                        session: "test-session".into()
                    },
                    now
                )
                .ok
        );
        assert_eq!(direct.command_at(Command::Status, now).code, "failed");
    }

    #[test]
    fn late_commit_rejection_does_not_consume_the_cleanup_deadline() {
        let now = Instant::now();
        let mut s = Handover::with_budget(100);
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        let epoch = s
            .command_at(
                Command::Watch {
                    session: "test-session".into(),
                },
                now,
            )
            .epoch
            .unwrap();
        assert!(
            s.command_at(
                Command::EngineStopped {
                    ticket: ticket.clone()
                },
                now
            )
            .ok
        );
        let late = now + Duration::from_millis(100);
        assert_eq!(
            s.command_at(
                Command::Commit {
                    ticket,
                    target: target(1),
                    pin: "fresh".into(),
                    listener_closed: true
                },
                late
            )
            .code,
            "redirect_deadline"
        );
        assert_eq!(
            s.command_at(
                Command::Expire {
                    session: "test-session".into(),
                    epoch: epoch.clone()
                },
                late
            )
            .code,
            "redirect_deadline"
        );
        assert_eq!(
            s.command_at(
                Command::Expire {
                    session: "test-session".into(),
                    epoch
                },
                late
            )
            .code,
            "stale_context"
        );
    }

    #[test]
    fn stale_deadlines_never_cancel_a_new_intent_or_committed_engine() {
        let now = Instant::now();
        let mut s = Handover::with_budget(100);
        s.command_at(
            Command::Preparing {
                session: "test-session".into(),
            },
            now,
        );
        let old = s
            .command_at(
                Command::Watch {
                    session: "test-session".into(),
                },
                now,
            )
            .epoch
            .unwrap();
        s.command_at(
            Command::Preparing {
                session: "test-session".into(),
            },
            now + Duration::from_millis(50),
        );
        assert_eq!(
            s.command_at(
                Command::Expire {
                    session: "test-session".into(),
                    epoch: old
                },
                now + Duration::from_millis(100)
            )
            .code,
            "stale_context"
        );
        assert_eq!(
            s.command_at(Command::Status, now + Duration::from_millis(100))
                .code,
            "preparing"
        );
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        let epoch = s
            .command_at(
                Command::Watch {
                    session: "test-session".into(),
                },
                now,
            )
            .epoch
            .unwrap();
        assert!(
            s.command_at(
                Command::EngineStopped {
                    ticket: ticket.clone()
                },
                now
            )
            .ok
        );
        assert!(
            s.command_at(
                Command::Commit {
                    ticket,
                    target: target(1),
                    pin: "fresh".into(),
                    listener_closed: true
                },
                now
            )
            .ok
        );
        assert_eq!(
            s.command_at(
                Command::Expire {
                    session: "test-session".into(),
                    epoch
                },
                now + Duration::from_secs(1)
            )
            .code,
            "stale_context"
        );
        assert_eq!(
            s.command_at(Command::Status, now + Duration::from_secs(1))
                .code,
            "active"
        );
        assert!(Handover::with_budget(u32::MAX).budget <= Duration::from_secs(60));
    }

    fn target(n: u8) -> String {
        format!("https://vpn-{n}.example:6443/")
    }
    fn register(s: &mut Handover, now: Instant) {
        assert!(
            s.command_at(
                Command::Register {
                    session: "test-session".into(),
                    target: target(0),
                    pin: "pin0".into(),
                    allowed: (0..6).map(target).collect()
                },
                now
            )
            .ok
        );
    }
    fn begin(s: &mut Handover, n: u8, now: Instant) -> Reply {
        s.command_at(
            Command::Begin {
                session: "test-session".into(),
                attempt: s.attempt,
                pin: s.pin.clone(),
                source: s.target.clone(),
                location: target(n),
                status: 302,
                replay_unsafe: false,
            },
            now,
        )
    }
    fn commit(s: &mut Handover, ticket: &str, n: u8, now: Instant) -> Reply {
        s.command_at(
            Command::Commit {
                ticket: ticket.into(),
                target: target(n),
                pin: format!("pin{n}"),
                listener_closed: true,
            },
            now,
        )
    }
    #[test]
    fn process_and_listener_barriers_and_one_shot_commit() {
        let now = Instant::now();
        let mut s = Handover::default();
        register(&mut s, now);
        let grant = begin(&mut s, 1, now);
        let ticket = grant.ticket.unwrap();
        assert_eq!(commit(&mut s, &ticket, 1, now).code, "stale_ticket");
        assert!(
            s.command_at(
                Command::EngineStopped {
                    ticket: ticket.clone()
                },
                now
            )
            .ok
        );
        assert_eq!(
            s.command_at(
                Command::Commit {
                    ticket: ticket.clone(),
                    target: target(1),
                    pin: "pin1".into(),
                    listener_closed: false
                },
                now
            )
            .code,
            "relay_not_ready"
        );
        assert!(commit(&mut s, &ticket, 1, now).ok);
        assert_eq!(commit(&mut s, &ticket, 1, now).code, "stale_ticket");
    }
    #[test]
    fn cancellation_new_intent_and_wrong_ticket_cannot_revive() {
        let now = Instant::now();
        let mut s = Handover::default();
        register(&mut s, now);
        let old = begin(&mut s, 1, now).ticket.unwrap();
        s.command(Command::Cancel {
            session: "test-session".into(),
        });
        assert!(
            !s.command(Command::EngineStopped {
                ticket: old.clone()
            })
            .ok
        );
        register(&mut s, now);
        let new = begin(&mut s, 1, now).ticket.unwrap();
        assert_ne!(old, new);
        assert!(!s.command(Command::EngineStopped { ticket: old }).ok);
        assert!(s.command(Command::EngineStopped { ticket: new }).ok);
    }
    #[test]
    fn preparation_and_handover_suppress_orphan_recovery() {
        let mut s = Handover::default();
        s.command(Command::Preparing {
            session: "intent".into(),
        });
        assert_eq!(s.command(Command::Status).code, "preparing");
        let now = Instant::now();
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        assert_eq!(s.command(Command::Status).code, "stopping");
        s.command(Command::EngineStopped { ticket });
        assert_eq!(s.command(Command::Status).code, "ready");
    }

    #[test]
    fn normal_connect_reset_revokes_the_previous_session() {
        let now = Instant::now();
        let mut s = Handover::default();
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        s.command(Command::Reset);
        assert_eq!(
            s.command(Command::Cancel {
                session: "test-session".into()
            })
            .code,
            "stale_context"
        );
        assert_eq!(
            s.command(Command::EngineStopped { ticket }).code,
            "stale_ticket"
        );
        assert!(s.allowed.is_empty() && s.visited.is_empty());
    }

    #[test]
    fn loops_count_and_budget_are_enforced_at_every_barrier() {
        let now = Instant::now();
        let mut s = Handover::default();
        register(&mut s, now);
        for n in 1..=3 {
            let ticket = begin(&mut s, n, now).ticket.unwrap();
            s.command_at(
                Command::EngineStopped {
                    ticket: ticket.clone(),
                },
                now,
            );
            assert!(commit(&mut s, &ticket, n, now).ok);
        }
        assert_eq!(begin(&mut s, 4, now).code, "redirect_limit");
        register(&mut s, now);
        assert_eq!(begin(&mut s, 0, now).code, "redirect_loop");
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        let late = now + Duration::from_secs(60);
        assert_eq!(
            s.command_at(Command::EngineStopped { ticket }, late).code,
            "redirect_deadline"
        );
        register(&mut s, now);
        let ticket = begin(&mut s, 1, now).ticket.unwrap();
        s.command_at(
            Command::EngineStopped {
                ticket: ticket.clone(),
            },
            now,
        );
        assert_eq!(commit(&mut s, &ticket, 1, late).code, "redirect_deadline");
    }
    #[test]
    fn authentication_and_target_validation_fail_closed() {
        let now = Instant::now();
        let mut s = Handover::default();
        for location in [
            "http://vpn-1.example:6443/",
            "https://user@vpn-1.example:6443/",
            "https://vpn-1.example:6443/?token=x",
            "https://vpn-1.example:6443/auth/token",
            "https://other.example/",
            "https://vpn-1.example:443/",
        ] {
            register(&mut s, now);
            assert!(
                !s.command_at(
                    Command::Begin {
                        session: s.session.clone(),
                        attempt: 0,
                        pin: s.pin.clone(),
                        source: s.target.clone(),
                        location: location.into(),
                        status: 302,
                        replay_unsafe: false
                    },
                    now
                )
                .ok
            );
        }
        register(&mut s, now);
        assert_eq!(
            s.command_at(
                Command::Begin {
                    session: s.session.clone(),
                    attempt: 0,
                    pin: s.pin.clone(),
                    source: s.target.clone(),
                    location: target(1),
                    status: 302,
                    replay_unsafe: true
                },
                now
            )
            .code,
            "authentication_replay_unsafe"
        );
    }
}
