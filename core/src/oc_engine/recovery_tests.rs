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
        Self::with_physical_facts(false)
    }
    fn with_physical_facts(stable: bool) -> Self {
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
                physical_network: Box::new(move |_| {
                    stable.then(|| ("192.168.1.1".into(), "en0".into()))
                }),
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

// F12: use the same Availability + NetWatch queue pair as the route watcher.
fn mandatory_retry_via_watcher(stable_facts: bool) {
    let f = Fixture::with_physical_facts(stable_facts);
    let shared = &f.engine.shared;
    let inputs = Inputs {
        tunnel_if: "utun99".into(),
        gateway_ips: vec!["198.51.100.7".into()],
        physical_if: "en0".into(),
        ..Inputs::default()
    };
    assert!(shared.guard.apply(&shared.holder, true, &inputs).is_none());
    std::fs::write(
        f.dir.join("pfctl"),
        r#"#!/bin/sh
root=$(dirname "$0")
cat >/dev/null
if [ -f "$root/fail" ]; then exit 1; fi
echo 'Token : 123' >&2
"#,
    )
    .unwrap();
    {
        let mut c = shared.core.lock().unwrap();
        c.network.start();
        c.watching = true;
        c.physical_gateway = stable_facts.then(|| "192.168.1.1".into());
        c.last_pf = Some((inputs.tunnel_if.clone(), inputs.gateway_ips.clone()));
        c.last_allow_direct_egress = true;
    }
    std::fs::write(f.dir.join("fail"), "").unwrap();
    f.network(false, Some(1));
    let initial_pending = shared.core.lock().unwrap().pf_needs_load;
    std::fs::remove_file(f.dir.join("fail")).unwrap();
    f.network(false, None);
    shared.send(Event::Fire {
        timer: Timer::NetWatch,
        token: u64::MAX,
    });
    f.barrier();
    let (pending, paused, attempts) = {
        let mut c = shared.core.lock().unwrap();
        let result = (c.pf_needs_load, c.network.paused, c.attempts);
        c.finished = true;
        result
    };
    let record: network_guard::Record =
        serde_json::from_slice(&std::fs::read(f.dir.join("guard.json")).unwrap()).unwrap();
    drop(f);
    assert!(initial_pending && paused);
    assert_eq!(
        attempts, 0,
        "mandatory retry must not respawn while offline"
    );
    assert!(!pending && !record.connected,
        "offline watcher must retry mandatory blocking even with unchanged or absent physical facts");
}
#[test]
fn offline_watcher_retries_failed_blocking_load() {
    mandatory_retry_via_watcher(true);
}
#[test]
fn offline_watcher_retries_blocking_without_physical_facts() {
    mandatory_retry_via_watcher(false);
}

#[test]
fn restored_watcher_never_reconfirms_a_live_cancelled_child() {
    let f = Fixture::with_physical_facts(true);
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    std::fs::write(
        f.dir.join("openconnect"),
        format!(
            r#"#!/bin/sh
root=$(dirname "$0")
read -r credential
trap '' TERM
printf 'AC_HOOK connect tun={} gateway=198.51.100.7 dns=10.8.0.1\n'
touch "$root/ready"
while [ ! -f "$root/exit" ]; do sleep 0.01; done
"#,
            name
        ),
    )
    .unwrap();
    f.engine.start();
    assert!(wait_until(|| f
        .engine
        .shared
        .core
        .lock()
        .unwrap()
        .hook_fired));
    let epoch = {
        let mut c = f.engine.shared.core.lock().unwrap();
        c.watching = true;
        c.physical_gateway = None;
        c.forwarder = Some(Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            53,
            Duration::from_millis(50),
            vec![],
            Upstreams {
                tunnel: c.tunnel_dns.clone(),
                local: vec![],
                physical_if: None,
                tunnel_if: c.tunnel_if.clone(),
            },
            None,
        ));
        f.engine.shared.update_forwarder(&c);
        assert_eq!(
            c.forwarder
                .as_ref()
                .unwrap()
                .bound_tunnel_interface()
                .as_deref(),
            Some(name)
        );
        c.forwarder.as_ref().unwrap().epoch()
    };
    f.network(false, Some(1));
    let (retired_on_cancel, stale_epoch) = {
        let c = f.engine.shared.core.lock().unwrap();
        let forwarder = c.forwarder.as_ref().unwrap();
        (
            forwarder.bound_tunnel_interface().is_none(),
            !forwarder.is_current(epoch),
        )
    };
    // Exercise upstream refresh too, rather than directly mutating the lease.
    f.engine.send(Event::NetworkChanged);
    f.barrier();
    assert!(f.engine.shared.core.lock().unwrap().tunnel_if.is_none());
    f.network(true, None);
    f.engine.send(Event::Fire {
        timer: Timer::NetWatch,
        token: u64::MAX,
    });
    f.barrier();
    let (waiting, tunnel, alive, bound) = {
        let c = f.engine.shared.core.lock().unwrap();
        (
            c.resume_after_exit,
            c.tunnel_if.clone(),
            c.child_alive(),
            c.forwarder.as_ref().unwrap().bound_tunnel_interface(),
        )
    };
    drop(f);
    assert!(
        alive && waiting,
        "fixture must still be waiting for a TERM-ignoring child"
    );
    assert!(
        tunnel.is_none(),
        "watcher must not reconfirm a live but cancelled child"
    );
    assert!(
        retired_on_cancel && stale_epoch && bound.is_none(),
        "cancel must retire the forwarder binding and its outstanding DNS epoch"
    );
}

#[test]
fn cancelled_child_cannot_rearm_bypasses_or_ack_current_epoch_dns() {
    let f = Fixture::new();
    let shared = &f.engine.shared;
    let inputs = Inputs {
        tunnel_if: "utun99".into(),
        gateway_ips: vec!["198.51.100.7".into()],
        physical_if: "en0".into(),
        direct_table: true,
        block_direct: true,
        ..Inputs::default()
    };
    assert!(shared.guard.apply(&shared.holder, false, &inputs).is_none());
    let (epoch, remained_blocked) = {
        let mut c = shared.core.lock().unwrap();
        c.resume_after_exit = true;
        c.forwarder = Some(Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            53,
            Duration::from_millis(50),
            vec![],
            Upstreams {
                tunnel: vec![],
                local: vec![],
                physical_if: None,
                tunnel_if: None,
            },
            None,
        ));
        shared.rearm_direct_after_sync(&mut c);
        (
            c.forwarder.as_ref().unwrap().epoch(),
            shared.guard.held().unwrap().1.block_direct,
        )
    };
    let (reply, answer) = mpsc::channel();
    shared.send(Event::DnsAnswer(
        dns_forwarder::Observation {
            epoch,
            name: "direct.example".into(),
            entry: Some("direct.example".into()),
            addresses: vec![Ipv4Addr::new(203, 0, 113, 9)],
            direct: vec![Ipv4Addr::new(203, 0, 113, 9)],
        },
        reply,
    ));
    let acknowledged = answer.recv_timeout(Duration::from_secs(5)).unwrap();
    f.barrier();
    let claimed = shared.core.lock().unwrap().split_policy.direct();
    {
        let mut c = shared.core.lock().unwrap();
        c.finished = true;
    }
    drop(f);
    assert!(
        remained_blocked,
        "cancel wait must keep optional rearm blocked"
    );
    assert!(
        !acknowledged && claimed.is_empty(),
        "cancel wait must reject even current-epoch DNS work"
    );
}

#[test]
fn suspended_rule_events_retire_routes_without_adding_optional_bypasses() {
    let f = Fixture::new();
    let shared = &f.engine.shared;
    let old = "203.0.113.9".to_string();
    let new = "203.0.113.10".to_string();
    let network = "198.18.0.0/24".to_string();
    assert!(shared
        .routes
        .add(&[old.clone(), network.clone()], "192.168.1.1"));
    let inputs = Inputs {
        tunnel_if: "utun99".into(),
        gateway_ips: vec!["198.51.100.7".into()],
        physical_if: "en0".into(),
        direct_table: true,
        block_direct: true,
        ..Inputs::default()
    };
    assert!(shared.guard.apply(&shared.holder, false, &inputs).is_none());
    assert!(shared.guard.add_direct(std::slice::from_ref(&old)));
    {
        let mut c = shared.core.lock().unwrap();
        c.network.start();
        c.config.allow_networks = vec![network];
        c.watching = true;
        c.last_pf = Some((inputs.tunnel_if.clone(), inputs.gateway_ips.clone()));
        c.routes_need_repoint = true; // No gateway fact; must not block retirement.
        c.forwarder = Some(Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            53,
            Duration::from_millis(50),
            vec!["old.example".into(), "new.example".into()],
            Upstreams {
                tunnel: vec![],
                local: vec![],
                physical_if: None,
                tunnel_if: None,
            },
            None,
        ));
        c.split_policy.observe(
            "old.example".into(),
            &[old.parse().unwrap()],
            &[old.parse().unwrap()],
        );
        c.split_policy.observe(
            "new.example".into(),
            &[new.parse().unwrap()],
            &[new.parse().unwrap()],
        );
    }
    f.network(false, Some(1));
    shared.send(Event::DirectDomains(vec!["new.example".into()]));
    shared.send(Event::AllowNetworks(vec![]));
    shared.send(Event::Availability(false));
    shared.send(Event::Fire {
        timer: Timer::NetWatch,
        token: u64::MAX,
    });
    f.barrier();
    let (paused, pending, attempts) = {
        let mut c = shared.core.lock().unwrap();
        let result = (c.network.paused, c.split_needs_sync, c.attempts);
        c.finished = true;
        result
    };
    let routes = shared.routes.addresses();
    let direct = shared.guard.direct_addresses();
    let blocked = shared.guard.held().unwrap().1.block_direct;
    drop(f);
    assert!(paused && pending && attempts == 0);
    assert!(routes.is_empty() && direct.is_empty(),
        "suspended rule events must retire revoked routes/table entries without adding replacements");
    assert!(blocked, "retirement must not rearm optional bypasses");
}

#[test]
fn queued_respawn_waits_for_exit_event_after_process_is_reaped() {
    let f = Fixture::new();
    {
        let mut c = f.engine.shared.core.lock().unwrap();
        c.network.start();
        c.resume_after_exit = true;
        c.child = Some(Child {
            pid: i32::MAX,
            generation: c.generation,
            alive: Arc::new(AtomicBool::new(false)),
        });
    }
    f.engine.shared.send(Event::Respawn);
    f.barrier();
    let attempts = {
        let mut c = f.engine.shared.core.lock().unwrap();
        let attempts = c.attempts;
        if attempts == 0 {
            c.child = None;
        }
        attempts
    };
    drop(f);
    assert_eq!(
        attempts, 0,
        "queued respawn must wait for the old Exited event to consume its intent"
    );
}
