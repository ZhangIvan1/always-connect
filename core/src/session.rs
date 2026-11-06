//! Session driver (DESIGN.md §6): what to do after a drop, and what to do
//! when re-authentication needs the user.
//!
//! Verified ground this module stands on (corrected 2026-10-30):
//! - CORRECTION: an earlier version of these docs claimed the public C API
//!   had no cookie-injection setter, based on a secondary API summary that
//!   omitted it. That was wrong. The local 9.12 header itself declares it
//!   (`/usr/include/openconnect.h:669`):
//!   `int openconnect_set_cookie(struct openconnect_info *, const char *);`
//!   plus `openconnect_clear_cookie()` (:670). The header is authoritative;
//!   the summary was not. The binding lives in `openconnect.rs`
//!   (`VpnSession::set_cookie` / `clear_cookie`).
//! - Consequence, corrected: a fresh process CAN resume from a saved
//!   cookie through the library path (set_cookie, then connect) — the
//!   saved `SessionRecord` is usable by both the library route and the
//!   CLI/Helper route (--cookie-on-stdin). In-process recovery (live
//!   vpninfo, mainloop reconnect) is still the fastest path for a quick
//!   drop; a rejected or expired cookie falls back to full
//!   re-authentication, with approval wait when the gateway demands it.
//! - The driver never guesses cookie expiry: validity is proven only by
//!   the server's response to a reconnect attempt, never by a timer.
//!
//! State machine extensions (added here, tested below): the original
//! machine had no terminal path for a rejected authentication and no
//! manual-disconnect path from Connecting/Authenticating. Both are needed
//! by a user-facing driver, so `state_machine` gains `AuthRejected`
//! (Authenticating -> Disconnected) and ManualDisconnect from Connecting
//! and Authenticating.

use std::time::Duration;

use crate::backoff::{Backoff, XorShift64};
use crate::state_machine::{self, Event, SessionStatus};

/// How long to wait for the user to tap the phone approval before
/// re-initiating authentication (which re-pushes). A timeout never tears
/// down the session; it only retries. Two minutes is a default: long
/// enough to notice the phone and tap, short enough that a missed push
/// doesn't stall the reconnect indefinitely.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// A saved session, as persisted by the platform layer. The Rust core
/// defines the record and the gateway-match rule; the file format and the
/// storage belong to the platform (Swift: Codable + Keychain — a cookie is
/// a session credential and must never sit in a plaintext file).
/// The record is usable by both resume routes: the library route
/// (`VpnSession::set_cookie`, then connect) and the CLI/Helper route
/// (--cookie-on-stdin, --servercert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub cookie: String,
    pub gateway: String,
    pub server_fingerprint: String,
    pub saved_at_unix: u64,
}

impl SessionRecord {
    /// Usable only for the gateway it was issued by, and only if it
    /// actually carries a cookie. Age is deliberately NOT judged here:
    /// expiry is proven by the server's response, not by a clock.
    pub fn usable_for(&self, gateway: &str) -> bool {
        !self.cookie.is_empty() && self.gateway == gateway
    }
}

/// Outcome of one authentication attempt, as classified at the FFI
/// boundary (mapping libopenconnect's obtain_cookie result codes to these
/// variants is Phase 1 work, not done here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Cookie obtained, tunnel may proceed.
    Success,
    /// The gateway wants a fresh user approval (phone push).
    NeedsApproval,
    /// The server refused the credentials/session. Retrying the same
    /// credentials is futile; stop and surface to the user.
    Rejected,
    /// Network error, timeout, or other transient failure. Retry with
    /// backoff.
    Transient,
}

/// What the caller (the provider) should do next.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriverAction {
    /// Keep routes installed; retry the in-process data plane after `delay`.
    ReconnectInProcess { delay: Duration },
    /// Run full authentication again after `delay`.
    Reauthenticate { delay: Duration },
    /// Wait for the user to approve, or `timeout` (then call
    /// `on_approval_timeout`).
    WaitApproval { timeout: Duration },
    /// Stop automatic retries; surface the failure to the user.
    StopNeedsUser,
    /// Session torn down (user-initiated only).
    TornDown,
    /// State changed, no caller work needed.
    NoAction,
    /// Call didn't apply (wrong state); nothing changed.
    Ignored,
}

pub struct SessionDriver {
    pub state: SessionStatus,
    backoff: Backoff,
    rng: XorShift64,
}

impl SessionDriver {
    /// `seed` only affects backoff jitter, never correctness. Tests use
    /// fixed seeds; production passes something time-derived.
    pub fn new(seed: u64) -> Self {
        Self {
            state: SessionStatus::Disconnected,
            backoff: Backoff::new(),
            rng: XorShift64(seed),
        }
    }

    /// Begin a fresh connection: Disconnected -> Connecting.
    pub fn start(&mut self) -> DriverAction {
        if self.apply(Event::Connect) {
            DriverAction::NoAction
        } else {
            DriverAction::Ignored
        }
    }

    /// The tunnel layer reports the gateway handshake is done and
    /// authentication may begin: Connecting -> Authenticating.
    pub fn on_authenticated(&mut self) -> DriverAction {
        if self.apply(Event::Authenticated) {
            DriverAction::NoAction
        } else {
            DriverAction::Ignored
        }
    }

    /// The tunnel dropped from Connected.
    /// - `cookie_alive_in_process`: the vpninfo is still alive, so its
    ///   cookie is still in memory and the data plane can reconnect
    ///   without re-authenticating (the "session kept" case).
    /// - Otherwise the session is dead and full re-authentication is
    ///   needed (Connected -> Reconnecting -> Authenticating).
    pub fn on_drop(&mut self, cookie_alive_in_process: bool) -> DriverAction {
        if self.state != SessionStatus::Connected {
            return DriverAction::Ignored;
        }
        self.state = SessionStatus::Reconnecting;
        if cookie_alive_in_process {
            let delay = self.backoff.next(&mut self.rng);
            DriverAction::ReconnectInProcess { delay }
        } else {
            self.state = SessionStatus::Authenticating;
            let delay = self.backoff.next(&mut self.rng);
            DriverAction::Reauthenticate { delay }
        }
    }

    /// The in-process data plane reconnected: Reconnecting -> Connected.
    pub fn on_reconnected(&mut self) -> DriverAction {
        if self.apply(Event::Resumed) {
            self.backoff.reset();
            DriverAction::NoAction
        } else {
            DriverAction::Ignored
        }
    }

    /// One authentication attempt finished.
    pub fn on_auth_outcome(&mut self, outcome: AuthOutcome) -> DriverAction {
        match outcome {
            AuthOutcome::Success => {
                if self.apply(Event::AuthOk) {
                    self.backoff.reset();
                    DriverAction::NoAction
                } else {
                    DriverAction::Ignored
                }
            }
            AuthOutcome::NeedsApproval => {
                if self.apply(Event::NeedApproval) {
                    DriverAction::WaitApproval {
                        timeout: APPROVAL_TIMEOUT,
                    }
                } else {
                    DriverAction::Ignored
                }
            }
            AuthOutcome::Rejected => {
                if self.apply(Event::AuthRejected) {
                    DriverAction::StopNeedsUser
                } else {
                    DriverAction::Ignored
                }
            }
            AuthOutcome::Transient => {
                if self.state == SessionStatus::Authenticating {
                    let delay = self.backoff.next(&mut self.rng);
                    DriverAction::Reauthenticate { delay }
                } else {
                    DriverAction::Ignored
                }
            }
        }
    }

    /// The user tapped the phone approval: AwaitingApproval -> Connected.
    pub fn on_approved(&mut self) -> DriverAction {
        if self.apply(Event::Approved) {
            self.backoff.reset();
            DriverAction::NoAction
        } else {
            DriverAction::Ignored
        }
    }

    /// Approval wait expired: AwaitingApproval -> Authenticating, then
    /// re-initiate (which re-pushes), with backoff.
    pub fn on_approval_timeout(&mut self) -> DriverAction {
        if self.state != SessionStatus::AwaitingApproval {
            return DriverAction::Ignored;
        }
        self.state = SessionStatus::Authenticating;
        let delay = self.backoff.next(&mut self.rng);
        DriverAction::Reauthenticate { delay }
    }

    /// User-initiated disconnect, from any non-Disconnected state.
    /// Backoff resets; routes are torn down by the caller.
    pub fn on_manual_disconnect(&mut self) -> DriverAction {
        if self.state == SessionStatus::Disconnected {
            return DriverAction::Ignored;
        }
        self.state = SessionStatus::Disconnected;
        self.backoff.reset();
        DriverAction::TornDown
    }

    /// Apply a state-machine event. Returns true when the transition was
    /// legal (state moved), false otherwise (state untouched).
    fn apply(&mut self, event: Event) -> bool {
        match state_machine::transition(self.state, event) {
            Some(next) => {
                self.state = next;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_driver() -> SessionDriver {
        let mut d = SessionDriver::new(42);
        assert_eq!(d.start(), DriverAction::NoAction);
        assert_eq!(d.on_authenticated(), DriverAction::NoAction);
        assert_eq!(
            d.on_auth_outcome(AuthOutcome::Success),
            DriverAction::NoAction
        );
        assert_eq!(d.state, SessionStatus::Connected);
        d
    }

    #[test]
    fn drop_with_live_cookie_reconnects_in_process() {
        let mut d = connected_driver();
        match d.on_drop(true) {
            DriverAction::ReconnectInProcess { delay } => {
                assert!(delay < Duration::from_secs(2));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(d.state, SessionStatus::Reconnecting);
        assert_eq!(d.on_reconnected(), DriverAction::NoAction);
        assert_eq!(d.state, SessionStatus::Connected);
        assert_eq!(d.backoff.attempt, 0);
    }

    #[test]
    fn drop_with_dead_cookie_reauthenticates() {
        let mut d = connected_driver();
        match d.on_drop(false) {
            DriverAction::Reauthenticate { delay } => {
                assert!(delay < Duration::from_secs(2));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(d.state, SessionStatus::Authenticating);
    }

    #[test]
    fn approval_flow_then_approved() {
        let mut d = SessionDriver::new(7);
        d.start();
        d.on_authenticated();
        assert_eq!(
            d.on_auth_outcome(AuthOutcome::NeedsApproval),
            DriverAction::WaitApproval {
                timeout: APPROVAL_TIMEOUT
            }
        );
        assert_eq!(d.state, SessionStatus::AwaitingApproval);
        assert_eq!(d.on_approved(), DriverAction::NoAction);
        assert_eq!(d.state, SessionStatus::Connected);
    }

    #[test]
    fn approval_timeout_reinitiates_with_backoff() {
        let mut d = SessionDriver::new(7);
        d.start();
        d.on_authenticated();
        d.on_auth_outcome(AuthOutcome::NeedsApproval);
        match d.on_approval_timeout() {
            DriverAction::Reauthenticate { delay } => {
                assert!(delay < Duration::from_secs(2));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(d.state, SessionStatus::Authenticating);
        assert_eq!(d.backoff.attempt, 1);
    }

    #[test]
    fn rejected_auth_stops_and_disconnects() {
        let mut d = SessionDriver::new(7);
        d.start();
        d.on_authenticated();
        assert_eq!(
            d.on_auth_outcome(AuthOutcome::Rejected),
            DriverAction::StopNeedsUser
        );
        assert_eq!(d.state, SessionStatus::Disconnected);
    }

    #[test]
    fn transient_auth_retries_with_growing_backoff() {
        let mut d = SessionDriver::new(7);
        d.start();
        d.on_authenticated();
        let first = d.on_auth_outcome(AuthOutcome::Transient);
        let second = d.on_auth_outcome(AuthOutcome::Transient);
        assert_eq!(d.state, SessionStatus::Authenticating);
        match (first, second) {
            (
                DriverAction::Reauthenticate { delay: d0 },
                DriverAction::Reauthenticate { delay: d1 },
            ) => {
                assert!(d0 < Duration::from_secs(2));
                assert!(d1 >= Duration::from_secs(1));
            }
            _ => panic!("expected two reauthenticate actions"),
        }
    }

    #[test]
    fn manual_disconnect_from_connected_and_reconnecting() {
        let mut d = connected_driver();
        assert_eq!(d.on_manual_disconnect(), DriverAction::TornDown);
        assert_eq!(d.state, SessionStatus::Disconnected);

        let mut d = connected_driver();
        d.on_drop(true);
        assert_eq!(d.on_manual_disconnect(), DriverAction::TornDown);
        assert_eq!(d.state, SessionStatus::Disconnected);
        assert_eq!(d.backoff.attempt, 0);
    }

    #[test]
    fn wrong_state_calls_are_ignored() {
        let mut d = SessionDriver::new(1);
        assert_eq!(d.on_drop(true), DriverAction::Ignored);
        assert_eq!(d.state, SessionStatus::Disconnected);
        assert_eq!(d.on_approved(), DriverAction::Ignored);
        assert_eq!(d.on_approval_timeout(), DriverAction::Ignored);
        assert_eq!(d.on_manual_disconnect(), DriverAction::Ignored);
    }

    #[test]
    fn session_record_gateway_match() {
        let rec = SessionRecord {
            cookie: "abc".to_string(),
            gateway: "vpn.example.com".to_string(),
            server_fingerprint: "SHA1".to_string(),
            saved_at_unix: 1_700_000_000,
        };
        assert!(rec.usable_for("vpn.example.com"));
        assert!(!rec.usable_for("other.example.com"));
        let empty = SessionRecord {
            cookie: String::new(),
            ..rec
        };
        assert!(!empty.usable_for("vpn.example.com"));
    }

    #[test]
    fn full_driver_path_drop_approve_reconnect() {
        // Connected -> drop (dead cookie) -> re-auth -> approval ->
        // approved -> Connected.
        let mut d = connected_driver();
        assert!(matches!(
            d.on_drop(false),
            DriverAction::Reauthenticate { .. }
        ));
        assert!(matches!(
            d.on_auth_outcome(AuthOutcome::NeedsApproval),
            DriverAction::WaitApproval { .. }
        ));
        assert_eq!(d.on_approved(), DriverAction::NoAction);
        assert_eq!(d.state, SessionStatus::Connected);
        assert_eq!(d.backoff.attempt, 0);
    }
}
