//! Real worker/CLI regressions for cancellation spanning preparation.
use super::*;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        // Atomic allocation: concurrent fixtures can share a clock tick.
        let mut template = std::env::temp_dir()
            .join("ac-intent-XXXXXX")
            .as_os_str()
            .as_bytes()
            .to_vec();
        template.push(0);
        let allocated = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(!allocated.is_null(), "{}", std::io::Error::last_os_error());
        let bytes = unsafe { std::ffi::CStr::from_ptr(allocated) }
            .to_bytes()
            .to_vec();
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    engine: Engine,
    dir: Scratch,
    available: Arc<AtomicBool>,
    calls: Arc<AtomicU32>,
    terminals: Arc<AtomicU32>,
    entered: mpsc::Receiver<()>,
    second: mpsc::Receiver<()>,
    release: Sender<()>,
    done: mpsc::Receiver<()>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_cli(None)
    }
    fn with_cli(cli_override: Option<&str>) -> Self {
        let dir = Scratch::new();
        let cli = dir.0.join("vpn");
        std::fs::write(
            &cli,
            r#"#!/bin/sh
case "$1" in
state) echo '>> state: Disconnected';;
-s) touch "$(dirname "$0")/login";;
disconnect) touch "$(dirname "$0")/cancel"; echo cancel >> "$(dirname "$0")/cancellations";;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let available = Arc::new(AtomicBool::new(true));
        let net = available.clone();
        let calls = Arc::new(AtomicU32::new(0));
        let credentials_calls = calls.clone();
        let terminals = Arc::new(AtomicU32::new(0));
        let terminal_events = terminals.clone();
        let (entered_tx, entered) = mpsc::channel();
        let (second_tx, second) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let (done_tx, done) = mpsc::channel();
        let engine = Engine::new(
            Config {
                cli: cli_override
                    .map(str::to_owned)
                    .unwrap_or_else(|| cli.to_string_lossy().into()),
                approval_timeout_minimum: Duration::from_secs(20),
                monitor: MONITOR,
            },
            Hooks {
                state: Box::new(|_, _| {}),
                terminal: Box::new(move |_| {
                    terminal_events.fetch_add(1, Ordering::SeqCst);
                }),
                kill_switch: Box::new(|_, _, _| {}),
                credentials: Box::new(move || {
                    if credentials_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Some(Credentials {
                            entry: "VPN-A".into(),
                            username: "u".into(),
                            password: "p".into(),
                        })
                    } else {
                        let _ = second_tx.send(());
                        None
                    }
                }),
                profile_hosts: Box::new(Vec::new),
                network_available: Box::new(move || net.load(Ordering::SeqCst)),
                before_login: Box::new(move || {
                    entered_tx.send(()).unwrap();
                    released.lock().unwrap().recv().unwrap();
                }),
                owned: Box::new(|_| {}),
                log: Box::new(|_| {}),
                disconnected: Box::new(move || {
                    let _ = done_tx.send(());
                }),
            },
        );
        Self {
            engine,
            dir,
            available,
            calls,
            terminals,
            entered,
            second,
            release,
            done,
        }
    }
    fn start(&self) {
        self.engine.connect();
        self.entered.recv_timeout(Duration::from_secs(10)).unwrap();
    }
    fn barrier(&self) {
        let (sent, done) = mpsc::channel();
        self.engine.tx.send(Command_::Barrier(sent)).unwrap();
        done.recv_timeout(Duration::from_secs(10)).unwrap();
    }
    fn finish(&self) {
        self.engine.disconnect();
        self.done.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}

#[test]
fn offline_recovery_must_not_submit_cancelled_preparation() {
    let f = Fixture::new();
    f.start();
    f.available.store(false, Ordering::SeqCst);
    f.engine.network_changed();
    let preparation_intent = f.engine.shared.current_intent();
    // Use the production two-second deadline while the worker is blocked.
    let until = Instant::now() + Duration::from_secs(5);
    while f.engine.shared.current_intent() == preparation_intent && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_ne!(f.engine.shared.current_intent(), preparation_intent);
    f.available.store(true, Ordering::SeqCst);
    f.engine.network_changed();
    f.release.send(()).unwrap();
    f.second.recv_timeout(Duration::from_secs(10)).unwrap();
    f.barrier();
    f.finish();
    assert!(
        !f.dir.0.join("login").exists(),
        "cancelled preparation must never submit a login"
    );
    assert!(f.dir.0.join("cancel").exists());
}

#[test]
fn rapid_stop_start_must_not_submit_cancelled_preparation() {
    let f = Fixture::new();
    f.start();
    f.engine.disconnect();
    f.engine.connect();
    f.release.send(()).unwrap();
    f.second.recv_timeout(Duration::from_secs(10)).unwrap();
    f.done.recv_timeout(Duration::from_secs(10)).unwrap();
    f.barrier();
    let stale_terminals = f.terminals.load(Ordering::SeqCst);
    f.finish();
    assert!(
        !f.dir.0.join("login").exists(),
        "cancelled preparation must never submit a login"
    );
    assert_eq!(
        stale_terminals, 0,
        "old stop must not publish a terminal for the new start"
    );
}

#[test]
fn queued_network_recovery_cannot_adopt_a_newer_intent() {
    let f = Fixture::new();
    f.start();
    f.engine.disconnect();
    f.engine.connect();
    f.engine
        .tx
        .send(Command_::Network {
            available: false,
            intent: 0,
        })
        .unwrap();
    f.engine
        .tx
        .send(Command_::Network {
            available: true,
            intent: 0,
        })
        .unwrap();
    f.release.send(()).unwrap();
    f.second.recv_timeout(Duration::from_secs(10)).unwrap();
    f.done.recv_timeout(Duration::from_secs(10)).unwrap();
    f.barrier();
    let calls = f.calls.load(Ordering::SeqCst);
    f.finish();
    assert_eq!(
        std::fs::read_to_string(f.dir.0.join("cancellations"))
            .unwrap()
            .lines()
            .count(),
        2,
        "stale queued pause must not submit a disconnect"
    );
    assert_eq!(
        calls, 2,
        "stale queued recovery must not create a third preparation"
    );
}

#[test]
fn production_threshold_uses_response_time_not_reaping_time() {
    // Model a 19s response whose process is finally reaped after 25s.
    let pushed = Instant::now() - Duration::from_secs(25);
    let threshold = Duration::from_secs(20);
    let failure = "  >> Login failed.";
    assert!(!approval_expired_at_response(
        failure,
        Some(pushed),
        Some(pushed + Duration::from_secs(19)),
        threshold
    ));
    assert!(approval_expired_at_response(
        failure,
        Some(pushed),
        Some(pushed + Duration::from_secs(21)),
        threshold
    ));
    assert!(!approval_expired_at_response(
        "Login error",
        Some(pushed),
        Some(pushed + Duration::from_secs(21)),
        threshold
    ));
    assert!(!approval_expired_at_response(
        failure,
        Some(pushed),
        None,
        threshold
    ));
}

#[test]
fn diagnostics_ffi_remains_readable_during_blocked_preparation() {
    let f = Fixture::new();
    f.start();
    let started = Instant::now();
    let raw = crate::ffi::ac_cisco_timeline(&f.engine);
    assert!(!raw.is_null());
    let during = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    crate::ffi::ac_string_free(raw);
    let elapsed = started.elapsed();
    f.engine.disconnect();
    let cancelled = f.engine.timeline_text();
    f.release.send(()).unwrap();
    f.done.recv_timeout(Duration::from_secs(10)).unwrap();
    f.barrier();
    f.finish();
    assert!(elapsed < Duration::from_secs(1));
    assert!(during.contains("credentials End"));
    assert!(during.contains("gui-wait Start"));
    assert!(!during.contains("gui-wait End"));
    assert!(cancelled.contains("Cancel Cancelled"));
    assert!(!during.contains("VPN-A"));
}

#[test]
fn observed_cli_reports_timeout_term_kill_and_closed_output_without_secrets() {
    // Use the trusted shell directly: launching a newly-written executable
    // can be delayed by platform checks before its TERM trap is installed.
    let f = Fixture::with_cli(Some("/bin/sh"));
    let script = r#"trap '' TERM
printf '>> state: Connected\n'
printf '>> error: vpn.private.example account-secret 198.51.100.88 suspended longer than the allotted time limit requires re-authentication\n'
exec 1>&- 2>&-
while :; do sleep 0.05; done
"#;
    let result = f.engine.shared.cli(
        0,
        &["-c", script],
        None,
        Duration::from_millis(500),
        &mut |_| {},
    );
    let text = f.engine.timeline_text();
    f.finish();
    assert_ne!(result.status, 0);
    for outcome in ["Timeout", "Term", "Kill", "OutputClosed"] {
        assert!(text.contains(outcome), "{outcome}: {text}");
    }
    assert!(text.contains("SuspendedSessionTimeout"));
    assert!(text.contains("state=Connected"));
    for secret in [
        "vpn.private.example",
        "account-secret",
        "198.51.100.88",
        "allotted time limit",
    ] {
        assert!(!text.contains(secret));
    }
}

#[test]
fn network_recovery_preserves_approval_rate_limit_but_resets_ordinary_backoff() {
    let f = Fixture::new();
    // No credentials: test the recovery decision without submitting a login.
    f.calls.store(1, Ordering::SeqCst);
    f.engine.shared.managing.store(true, Ordering::SeqCst);
    let unanswered = Instant::now() - Duration::from_secs(100);
    let mut st = State {
        intent: 0,
        wanted: true,
        ever_connected: false,
        tunnel_if: String::new(),
        monitor_at: None,
        retry_at: None,
        backoff_index: 4,
        push_backoff_index: 3,
        unanswered_since: Some(unanswered),
        last_kill_switch: None,
        last_tick: None,
    };
    f.engine.shared.command(
        &mut st,
        Command_::Network {
            available: true,
            intent: 0,
        },
    );
    f.finish();
    assert_eq!(st.backoff_index, 0);
    assert_eq!(st.push_backoff_index, 3);
    assert_eq!(st.unanswered_since, Some(unanswered));
}
