//! Reconnect state machine (DESIGN.md §6). The critical distinction:
//! an unexpected drop keeps routes installed (fail closed) while a manual
//! disconnect restores the local network.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Disconnected,
    Connecting,
    Authenticating,
    AwaitingApproval,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Connect,
    Authenticated,
    AuthOk,
    NeedApproval,
    Approved,
    AuthTimeout,
    Drop,
    Resumed,
    SessionDead,
    ManualDisconnect,
    /// The server refused the credentials/session (added for the session
    /// driver: the original machine had no terminal path for a rejected
    /// authentication).
    AuthRejected,
}

/// Returns the next state, or `None` for an illegal transition.
pub fn transition(state: SessionStatus, event: Event) -> Option<SessionStatus> {
    use Event::*;
    use SessionStatus::*;
    match (state, event) {
        (Disconnected, Connect) => Some(Connecting),
        (Connecting, Authenticated) => Some(Authenticating),
        (Authenticating, NeedApproval) => Some(AwaitingApproval),
        (Authenticating, AuthOk) => Some(Connected),
        (AwaitingApproval, Approved) => Some(Connected),
        (AwaitingApproval, AuthTimeout) => Some(Authenticating),
        (Connected, Drop) => Some(Reconnecting),
        (Reconnecting, Resumed) => Some(Connected),
        (Reconnecting, SessionDead) => Some(Authenticating),
        (Reconnecting, ManualDisconnect) => Some(Disconnected),
        (AwaitingApproval, ManualDisconnect) => Some(Disconnected),
        (Connected, ManualDisconnect) => Some(Disconnected),
        // Driver extensions: rejected auth ends the attempt (the user must
        // fix credentials and reconnect explicitly), and a manual
        // disconnect is honored from every non-terminal state.
        (Authenticating, AuthRejected) => Some(Disconnected),
        (Connecting, ManualDisconnect) => Some(Disconnected),
        (Authenticating, ManualDisconnect) => Some(Disconnected),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_keeps_reconnecting() {
        assert_eq!(
            transition(SessionStatus::Connected, Event::Drop),
            Some(SessionStatus::Reconnecting)
        );
    }

    #[test]
    fn manual_disconnect_restores_from_any_waiting_state() {
        assert_eq!(
            transition(SessionStatus::Reconnecting, Event::ManualDisconnect),
            Some(SessionStatus::Disconnected)
        );
        assert_eq!(
            transition(SessionStatus::AwaitingApproval, Event::ManualDisconnect),
            Some(SessionStatus::Disconnected)
        );
    }

    #[test]
    fn approval_timeout_loops_back_to_auth() {
        assert_eq!(
            transition(SessionStatus::AwaitingApproval, Event::AuthTimeout),
            Some(SessionStatus::Authenticating)
        );
    }

    #[test]
    fn illegal_transition_rejected() {
        assert_eq!(
            transition(SessionStatus::Disconnected, Event::Resumed),
            None
        );
    }

    #[test]
    fn driver_extensions() {
        // Rejected auth ends the attempt.
        assert_eq!(
            transition(SessionStatus::Authenticating, Event::AuthRejected),
            Some(SessionStatus::Disconnected)
        );
        // Manual disconnect honored mid-connect and mid-auth.
        assert_eq!(
            transition(SessionStatus::Connecting, Event::ManualDisconnect),
            Some(SessionStatus::Disconnected)
        );
        assert_eq!(
            transition(SessionStatus::Authenticating, Event::ManualDisconnect),
            Some(SessionStatus::Disconnected)
        );
        // ...but not from Disconnected itself.
        assert_eq!(
            transition(SessionStatus::Disconnected, Event::ManualDisconnect),
            None
        );
    }

    #[test]
    fn full_fail_closed_path() {
        let mut s = SessionStatus::Connected;
        for ev in [
            Event::Drop,
            Event::SessionDead,
            Event::NeedApproval,
            Event::Approved,
        ] {
            s = transition(s, ev).expect("legal transition");
        }
        assert_eq!(s, SessionStatus::Connected);
    }
}
