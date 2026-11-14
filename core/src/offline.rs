//! Event-driven physical-network gate. Offline never releases protection.

/// Effects executed by the engine; a deadline is one-shot, never a poll.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Deadline(u64),
    Cancel,
    Resume,
}

/// Wanted is independent of connectivity: a manual stop clears it permanently
/// until the next explicit start. Tokens discard stale debounce deadlines.
#[derive(Default)]
pub struct Gate {
    pub paused: bool,
    wanted: bool,
    pending: Option<u64>,
    generation: u64,
}

impl Gate {
    /// An explicit engine start makes later restoration eligible to connect.
    pub fn start(&mut self) {
        self.wanted = true;
    }
    /// Manual stop wins over all future physical-network restoration events.
    pub fn stop(&mut self) {
        self.wanted = false;
    }
    /// Consume a fresh, read-only physical-route fact.
    pub fn observe(&mut self, available: bool) -> Vec<Action> {
        if available {
            self.pending = None;
            if std::mem::take(&mut self.paused) && self.wanted {
                return vec![Action::Resume];
            }
        } else if !self.paused && self.pending.is_none() {
            self.generation = self.generation.wrapping_add(1);
            self.pending = Some(self.generation);
            return vec![Action::Deadline(self.generation)];
        }
        vec![]
    }
    /// Called after two seconds, with a fresh system fact. A lost route event
    /// cannot make a recovered network pause at the old deadline.
    pub fn deadline(&mut self, token: u64, available: bool) -> Vec<Action> {
        if self.pending != Some(token) {
            return vec![];
        }
        if available {
            return self.observe(true);
        }
        self.pending = None;
        self.paused = true;
        if self.wanted {
            vec![Action::Cancel]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loss_debounces_then_cancels_and_restoration_resumes() {
        let mut gate = Gate::default();
        gate.start();
        assert_eq!(gate.observe(false), vec![Action::Deadline(1)]);
        assert!(!gate.paused);
        assert!(gate.observe(false).is_empty());
        assert_eq!(gate.deadline(1, false), vec![Action::Cancel]);
        assert!(gate.paused);
        assert_eq!(gate.observe(true), vec![Action::Resume]);
        assert!(!gate.paused);
    }
    #[test]
    fn manual_stop_offline_never_reconnects() {
        let mut gate = Gate::default();
        gate.start();
        gate.observe(false);
        gate.deadline(1, false);
        gate.stop();
        assert!(gate.observe(true).is_empty());
    }
    #[test]
    fn flap_and_stale_deadlines_do_nothing() {
        let mut gate = Gate::default();
        gate.start();
        gate.observe(false);
        gate.observe(true);
        gate.observe(false);
        assert!(gate.deadline(1, false).is_empty());
        assert!(gate.deadline(2, true).is_empty());
        assert!(!gate.paused);
    }
}
