//! Multiple physical-network flaps through the real queue and child readers.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    engine: Engine,
    dir: PathBuf,
    available: Arc<AtomicBool>,
    stopped: Receiver<()>,
}
fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ac-flaps-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let cli = dir.join("openconnect");
        std::fs::write(
            &cli,
            r#"#!/bin/sh
root=$(dirname "$0")
read -r credential
if mkdir "$root/first" 2>/dev/null; then
    trap '' TERM
    touch "$root/ready"
    while [ ! -f "$root/exit" ]; do sleep 0.01; done
else
    printf 'AC_HOOK connect tun=utun99 gateway=198.51.100.7\n'
    printf 'SECOND_CHILD_OUTPUT\n'
    while [ ! -f "$root/finish" ]; do sleep 0.01; done
fi
"#,
        )
        .unwrap();
        let pfctl = dir.join("pfctl");
        std::fs::write(
            &pfctl,
            "#!/bin/sh\ncat >/dev/null\necho 'Token : 123' >&2\n",
        )
        .unwrap();
        for file in [&cli, &pfctl] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let guard = Arc::new(Guard::new(network_guard::Settings {
            support_dir: dir.clone(),
            boot: Some("test".into()),
            grace: Duration::from_secs(120),
            pfctl: Some(pfctl.to_string_lossy().into()),
        }));
        guard.owner_attached();
        let available = Arc::new(AtomicBool::new(true));
        let network = available.clone();
        let (stopped_tx, stopped) = mpsc::channel();
        let engine = Engine::new(
            Config {
                no_routes: true,
                test_active: true,
                test_openconnect: Some(cli.to_string_lossy().into()),
                script_path: "/usr/bin/true".into(),
                support_dir: dir.to_string_lossy().into(),
                cookie_store_path: dir.join("cookie.json").to_string_lossy().into(),
                physical_if: "en0".into(),
                drop_protection: true,
                password: "p".into(),
                server: "https://vpn.example".into(),
                ..Config::default()
            },
            Hooks {
                state: Box::new(|_, _| {}),
                terminal: Box::new(|_| {}),
                physical_network: Box::new(|_| None),
                network_available: Box::new(move || network.load(Ordering::SeqCst)),
                local_dns: Box::new(|_| vec![]),
                system_roots: Box::new(|| None),
                stopped: Box::new(move || {
                    let _ = stopped_tx.send(());
                }),
            },
            guard,
        );
        Self {
            engine,
            dir,
            available,
            stopped,
        }
    }
    fn barrier(&self) {
        let (sent, done) = mpsc::channel();
        self.engine.send(Event::Barrier(sent));
        done.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    fn network(&self, available: bool, deadline: Option<u64>) {
        self.available.store(available, Ordering::SeqCst);
        self.engine.send(Event::Availability(available));
        if let Some(token) = deadline {
            self.engine.send(Event::OfflineDeadline(token));
        }
        self.barrier();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("exit"), "");
        let _ = std::fs::write(self.dir.join("finish"), "");
        if !self.engine.shared.core.lock().unwrap().finished {
            self.engine.stop(false, true);
            let _ = self.stopped.recv_timeout(Duration::from_secs(5));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn double_flap_consumes_exit_intent_and_processes_new_child_output() {
    let f = Fixture::new();
    f.engine.start();
    assert!(wait_until(|| f.dir.join("ready").exists()));
    let old_generation = f.engine.shared.core.lock().unwrap().generation;
    f.network(false, Some(1));
    f.network(true, None);
    assert!(f.engine.shared.core.lock().unwrap().resume_after_exit);
    f.network(false, Some(2));
    std::fs::write(f.dir.join("exit"), "").unwrap();
    assert!(wait_until(|| f
        .engine
        .shared
        .core
        .lock()
        .unwrap()
        .child
        .is_none()));
    let stale_after_exit = f.engine.shared.core.lock().unwrap().resume_after_exit;
    f.network(true, None);
    let output_received = wait_until(|| {
        f.engine
            .shared
            .core
            .lock()
            .unwrap()
            .tail
            .iter()
            .any(|line| line == "SECOND_CHILD_OUTPUT")
    });
    let core = f.engine.shared.core.lock().unwrap();
    let new_generation = core.generation;
    let hook_fired = core.hook_fired;
    let stale_on_new_child = core.resume_after_exit;
    let held = f.engine.shared.guard.held().is_some();
    drop(core);
    // Cleanup also runs on any assertion failure, including negative controls.
    drop(f);
    assert!(
        output_received && hook_fired,
        "real child Output/AC_HOOK events must reach the new generation"
    );

    assert!(
        !stale_after_exit,
        "old exit intent must be consumed even while paused"
    );
    assert!(new_generation > old_generation);
    assert!(
        !stale_on_new_child,
        "new generation must not inherit output suppression"
    );
    assert!(
        held,
        "new hook must install protection through the fake guard"
    );
}

#[test]
fn paused_split_recovery_preserves_blocking_until_restoration() {
    let f = Fixture::new();
    let shared = &f.engine.shared;
    let inputs = Inputs {
        tunnel_if: "utun99".into(),
        gateway_ips: vec!["198.51.100.7".into()],
        physical_if: "en0".into(),
        direct_table: true,
        strict_dns: true,
        block_direct: true,
        ..Inputs::default()
    };
    assert!(shared.guard.apply(&shared.holder, false, &inputs).is_none());
    let (blocked_while_paused, rearmed_after_restore, no_spawn, terminal_retired) = {
        let mut c = shared.core.lock().unwrap();
        c.network.start();
        c.network.observe(false);
        c.network.deadline(1, false);
        c.last_pf = Some((inputs.tunnel_if.clone(), inputs.gateway_ips.clone()));
        c.last_allow_direct_egress = false;
        c.pf_needs_load = true;
        // Upstream mandatory recovery must remain usable during a pause.
        assert!(shared.apply_base_pf(&mut c));
        assert!(!c.pf_needs_load);
        // Reinstall an upstream split base, as a route/PF retry would do.
        assert!(shared.guard.apply(&shared.holder, false, &inputs).is_none());
        assert!(shared.rearm_direct_after_sync(&mut c));
        let blocked = shared.guard.held().unwrap().1.block_direct;
        shared.spawn_next(&mut c);
        let no_spawn = c.attempts == 0;
        c.network.observe(true);
        assert!(shared.rearm_direct_after_sync(&mut c));
        let rearmed = !shared.guard.held().unwrap().1.block_direct;
        shared.guard.own_engine_started(&shared.holder);
        assert!(shared.guard.bootstrap_context().is_some());
        shared.finish_terminal(&mut c, Terminal::AuthFailure, "fixture terminal");
        c.network.paused = true;
        let terminal_retired =
            shared.guard.bootstrap_context().is_none() && c.network.observe(true).is_empty();
        (blocked, rearmed, no_spawn, terminal_retired)
    };
    drop(f);
    assert!(
        blocked_while_paused,
        "split recovery must not reopen bypasses during offline pause"
    );
    assert!(
        rearmed_after_restore,
        "restoration must retain upstream split recovery"
    );
    assert!(
        no_spawn,
        "mandatory recovery cannot respawn an offline engine"
    );
    assert!(
        terminal_retired,
        "terminal cleanup must retire both guard and network intent"
    );
}

#[test]
fn paused_engine_does_not_reconfirm_a_stopping_childs_interface() {
    let f = Fixture::new();
    let (paused, restored) = {
        let shared = &f.engine.shared;
        let mut c = shared.core.lock().unwrap();
        c.network.start();
        c.network.observe(false);
        c.network.deadline(1, false);
        c.hook_fired = true;
        c.child = Some(Child {
            pid: i32::MAX, // State-only fixture; never use a process-group signal target.
            generation: c.generation,
            alive: Arc::new(AtomicBool::new(true)),
        });
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        c.tunnel_lease = Some(TunnelLease {
            name: name.into(),
            index: interface_index(name).unwrap(),
            generation: c.generation,
        });
        let paused = shared.reconfirm_tunnel(&mut c);
        c.tunnel_if = None;
        c.network.observe(true);
        let restored = shared.reconfirm_tunnel(&mut c);
        c.child = None;
        c.finished = true;
        (paused, restored)
    };
    drop(f);
    assert!(
        !paused,
        "offline refresh must not reconfirm the child being cancelled"
    );
    assert!(
        restored,
        "restoration still permits upstream exact-interface reconfirmation"
    );
}
