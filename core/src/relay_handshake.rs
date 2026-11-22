//! Connection admission/backoff, before any upstream TLS socket is started.
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct Admission {
    pub allowed: bool,
    pub retry_after_ms: u32,
    pub notify: bool,
}

#[derive(Default)]
pub struct Budget {
    active: BTreeSet<u32>,
    failures: u32,
    retry_at: Option<Instant>,
    reported: bool,
}

impl Budget {
    pub fn admit(&mut self, pair: u32, now: Instant) -> Admission {
        let delay = self
            .retry_at
            .map(|at| at.saturating_duration_since(now))
            .unwrap_or_default();
        if !delay.is_zero() || self.active.len() >= 4 || self.active.contains(&pair) {
            let notify = !std::mem::replace(&mut self.reported, true);
            return Admission {
                allowed: false,
                retry_after_ms: delay.as_millis().min(u32::MAX as u128) as u32,
                notify,
            };
        }
        self.active.insert(pair);
        Admission {
            allowed: true,
            retry_after_ms: 0,
            notify: false,
        }
    }

    /// 0 = both TLS legs ready, 1 = upstream handshake failed, 2 = local
    /// rejection/stop/network change. A pair releases its lease only once.
    pub fn finish(&mut self, pair: u32, outcome: u32, now: Instant) {
        if !self.active.remove(&pair) {
            return;
        }
        self.reported = false;
        match outcome {
            0 => {
                self.failures = 0;
                self.retry_at = None;
            }
            1 => {
                self.failures = self.failures.saturating_add(1);
                let seconds = (1u64 << self.failures.saturating_sub(1).min(5)).min(30);
                self.retry_at = Some(now + Duration::from_secs(seconds));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_tls_is_bounded_and_backoff_resets_on_success() {
        let mut b = Budget::default();
        let mut now = Instant::now();
        for (pair, seconds) in (1..).zip([1, 2, 4, 8, 16, 30, 30]) {
            assert!(b.admit(pair, now).allowed);
            b.finish(pair, 1, now);
            let denied = b.admit(pair + 100, now);
            assert!(!denied.allowed && denied.notify);
            assert_eq!(denied.retry_after_ms, seconds * 1000);
            assert!(!b.admit(pair + 100, now).notify);
            now += Duration::from_secs(seconds as u64);
        }
        assert!(b.admit(90, now).allowed);
        b.finish(90, 0, now);
        assert!(b.admit(91, now).allowed);
        b.finish(91, 1, now);
        assert_eq!(b.admit(92, now).retry_after_ms, 1000);
    }
    #[test]
    fn local_rejection_does_not_penalize_the_gateway_or_release_twice() {
        let mut b = Budget::default();
        let now = Instant::now();
        for n in 1..=4 {
            assert!(b.admit(n, now).allowed);
        }
        assert!(!b.admit(5, now).allowed);
        b.finish(1, 2, now);
        b.finish(1, 1, now);
        assert!(b.admit(5, now).allowed);
        assert_eq!(b.failures, 0);
    }
}
