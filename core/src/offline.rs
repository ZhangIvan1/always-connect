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
    /// A live session absorbed this loss (own connection only): no pause
    /// while it lasts; its exit while still offline pauses at once.
    held: bool,
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
            self.held = false;
            if std::mem::take(&mut self.paused) && self.wanted {
                return vec![Action::Resume];
            }
        } else if !self.paused && !self.held && self.pending.is_none() {
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
    /// The engine kept a live session instead of cancelling: undo the pause
    /// (nothing is cancelled) until that session ends or the network returns.
    pub fn hold(&mut self) {
        self.paused = false;
        self.held = true;
    }
    pub fn held(&self) -> bool {
        self.held
    }
    /// The held session ended while still offline: pause without a new
    /// debounce, so restoration resumes exactly once.
    pub fn release_hold(&mut self) {
        if std::mem::take(&mut self.held) {
            self.paused = true;
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
    fn held_session_pauses_only_when_it_ends_offline() {
        let mut gate = Gate::default();
        gate.start();
        gate.observe(false);
        assert_eq!(gate.deadline(1, false), vec![Action::Cancel]);
        gate.hold();
        assert!(!gate.paused && gate.held());
        // Further loss events while held schedule nothing.
        assert!(gate.observe(false).is_empty());
        gate.release_hold();
        assert!(gate.paused && !gate.held());
        assert_eq!(gate.observe(true), vec![Action::Resume]);
        // Restoration while still held clears it without a resume.
        gate.observe(false);
        gate.deadline(2, false);
        gate.hold();
        assert!(gate.observe(true).is_empty());
        assert!(!gate.held() && !gate.paused);
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
