//! Reconnect backoff (DESIGN.md §6): 1s, 2s, 5s, 10s, 30s cap,
//! +/-20% jitter, reset on success. Never gives up.

use std::time::Duration;

const BASE: [u64; 5] = [1, 2, 5, 10, 30];

/// Minimal xorshift PRNG (no external deps). Deterministic under a fixed
/// seed, which keeps the tests reproducible.
pub struct XorShift64(pub u64);

impl XorShift64 {
    pub fn next_f64(&mut self) -> f64 {
        let mut x = self.0;
        if x == 0 {
            x = 0x9E3779B97F4A7C15;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[derive(Debug, Default)]
pub struct Backoff {
    pub attempt: usize,
}

impl Backoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next delay in seconds, with jitter. `rng` supplies [0, 1).
    pub fn next(&mut self, rng: &mut XorShift64) -> Duration {
        let base = BASE[self.attempt.min(BASE.len() - 1)] as f64;
        self.attempt += 1;
        let secs = base * (0.8 + rng.next_f64() * 0.4);
        Duration::from_secs_f64(secs)
    }

    /// Call on a successful (re)connect.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_then_caps() {
        let mut b = Backoff::new();
        let mut rng = XorShift64(42);
        let d0 = b.next(&mut rng);
        let mut last = d0;
        for _ in 0..8 {
            last = b.next(&mut rng);
        }
        assert!(d0 < Duration::from_secs(2));
        assert!(last <= Duration::from_secs(36));
        assert!(last >= Duration::from_secs(24));
    }

    #[test]
    fn reset_restarts_sequence() {
        let mut b = Backoff::new();
        let mut rng = XorShift64(7);
        for _ in 0..6 {
            b.next(&mut rng);
        }
        assert_eq!(b.attempt, 6);
        b.reset();
        assert_eq!(b.attempt, 0);
        let d = b.next(&mut rng);
        assert!(d < Duration::from_secs(2));
    }
}
