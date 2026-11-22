//! A timed-out process stop is not proof that cleanup completed.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Default)]
pub struct Owner(AtomicU64);

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Ignore = 0,
    Start = 1,
    Cancelled = 2,
    TimedOut = 3,
}

pub struct Ticket {
    owner: Arc<Owner>,
    generation: u64,
    replied: bool,
}

impl Owner {
    pub fn cancel(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    pub fn begin(self: &Arc<Self>) -> Ticket {
        Ticket {
            owner: Arc::clone(self),
            generation: self.0.fetch_add(1, Ordering::SeqCst).wrapping_add(1),
            replied: false,
        }
    }
}

impl Ticket {
    pub fn complete(&mut self, actually_stopped: bool) -> Action {
        if std::mem::replace(&mut self.replied, true) {
            return Action::Ignore;
        }
        if self.owner.0.load(Ordering::SeqCst) != self.generation {
            return Action::Cancelled;
        }
        if actually_stopped {
            Action::Start
        } else {
            Action::TimedOut
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timeout_never_starts_and_late_stop_is_not_replayed() {
        let owner = Arc::new(Owner::default());
        let mut ticket = owner.begin();
        assert_eq!(ticket.complete(false), Action::TimedOut);
        assert_eq!(ticket.complete(true), Action::Ignore);
    }
    #[test]
    fn newer_intent_and_cancel_revoke_old_callbacks() {
        let owner = Arc::new(Owner::default());
        let mut old = owner.begin();
        let mut new = owner.begin();
        assert_eq!(old.complete(true), Action::Cancelled);
        assert_eq!(new.complete(true), Action::Start);
        assert_eq!(new.complete(false), Action::Ignore);
        let mut cancelled = owner.begin();
        owner.cancel();
        assert_eq!(cancelled.complete(true), Action::Cancelled);
    }
    #[test]
    fn old_timeout_cannot_fail_a_new_intent() {
        let owner = Arc::new(Owner::default());
        let mut old = owner.begin();
        let mut new = owner.begin();
        assert_eq!(old.complete(false), Action::Cancelled);
        assert_eq!(new.complete(true), Action::Start);
    }
}
