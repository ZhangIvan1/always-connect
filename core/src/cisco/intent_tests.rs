//! Real worker/CLI regressions for cancellation spanning preparation.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ac-intent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
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
    entered: mpsc::Receiver<()>,
    second: mpsc::Receiver<()>,
    release: Sender<()>,
    done: mpsc::Receiver<()>,
}
impl Fixture {
    fn new() -> Self {
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
        let (entered_tx, entered) = mpsc::channel();
        let (second_tx, second) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let (done_tx, done) = mpsc::channel();
        let engine = Engine::new(
            Config {
                cli: cli.to_string_lossy().into(),
                approval_timeout_minimum: Duration::from_secs(20),
                monitor: MONITOR,
            },
            Hooks {
                state: Box::new(|_, _| {}),
                terminal: Box::new(|_| {}),
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
    // Use the production two-second deadline while the worker is blocked.
    let until = Instant::now() + Duration::from_secs(5);
    while f.engine.shared.current_intent() == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_ne!(f.engine.shared.current_intent(), 0);
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
    f.finish();
    assert!(
        !f.dir.0.join("login").exists(),
        "cancelled preparation must never submit a login"
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

