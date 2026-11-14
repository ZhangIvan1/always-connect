//! The Cisco engine (DESIGN.md §二十一, §21.6, §21.19, §25.4; moved from
//! Swift to Rust in §32.11): Cisco Secure Client runs the tunnel; this
//! drives it through Cisco's own CLI, run in the user's session (only
//! there can Cisco present the keychain certificate).
//!
//! - Log in with the stored password, watch Cisco's state (on every
//!   routing change, else every 15 s),
//!   re-establish a lost session forever (backoff 1, 2, 5, 10, 30 s with
//!   jitter), map everything onto the App's six states.
//! - The kill switch is asked of the background service through
//!   `kill_switch(mode, tunnel, gateways)`: 1 = connected set while the
//!   tunnel is up, 2 = blocking set the moment it is lost.
//! - "Login error." = rejected: never retried on our own (anti-lockout).
//!   "Login failed." at least `approval_timeout_minimum` after the
//!   password went in = the phone approval expired untapped: asked again
//!   after 30 s, 1, 2, 5 min, and after an hour of unanswered approvals
//!   only every 15 minutes (§21.19).
//! - Only a session this App started is managed (§25.4); `owned` is told
//!   to the App, which persists it.
//!
//! One engine thread does everything, as the Swift queue did; it waits
//! on a channel with a deadline (next monitor tick or retry), so an idle
//! engine wakes for nothing. A login blocks it (up to 180 s) exactly as
//! before; a disconnect invalidates the login intent immediately. The CLI reader
//! observes cancellation within its existing 200 ms read wait.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DISCONNECTED: i32 = 0;
pub const CONNECTING: i32 = 1;
pub const AUTHENTICATING: i32 = 2;
pub const AWAITING_APPROVAL: i32 = 3;
pub const CONNECTED: i32 = 4;
pub const RECONNECTING: i32 = 5;

const BACKOFF: [f64; 5] = [1.0, 2.0, 5.0, 10.0, 30.0];
/// After an attempt that got as far as the password (the phone was
/// pushed): an unanswered phone is not pushed every 30 s (§21.6).
const PUSH_BACKOFF: [f64; 4] = [30.0, 60.0, 120.0, 300.0];
const QUIET_AFTER: Duration = Duration::from_secs(3600);
const QUIET_INTERVAL: f64 = 900.0;
/// Cisco's state is asked when the routing table changes (a tunnel
/// coming or going always does) and otherwise every 15 s (§32.15; it was
/// every 4 s, one `vpn` process each time).
pub const MONITOR: Duration = Duration::from_secs(15);
const CHANGE_DEBOUNCE: Duration = Duration::from_secs(2);

// MARK: - The CLI

pub struct RunResult {
    pub status: i32,
    pub output: String,
}

/// Runs the Cisco CLI to completion (stdout and stderr together),
/// streaming lines to `on_line` — prompts, which end without a newline
/// (": " or "] "), too. `on_start` gets the child's pid.
pub fn run(
    cli: &str,
    args: &[&str],
    input: Option<&str>,
    timeout: Duration,
    on_start: &mut dyn FnMut(u32),
    on_line: &mut dyn FnMut(&str),
) -> RunResult {
    run_interruptible(cli, args, input, timeout, on_start, on_line, &|| false)
}

fn run_interruptible(
    cli: &str,
    args: &[&str],
    input: Option<&str>,
    timeout: Duration,
    on_start: &mut dyn FnMut(u32),
    on_line: &mut dyn FnMut(&str),
    cancelled: &dyn Fn() -> bool,
) -> RunResult {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return RunResult {
            status: -1,
            output: String::new(),
        };
    }
    for fd in fds {
        // Only the child's stdout/stderr may hold the write end: a stray
        // copy kept the pipe open past the CLI's exit.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let Ok(err_end) = write_end.try_clone() else {
        return RunResult {
            status: -1,
            output: String::new(),
        };
    };
    let mut cmd = Command::new(cli);
    crate::reset_child_signals(&mut cmd);
    let child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(write_end))
        .stderr(Stdio::from(err_end))
        .spawn();
    // The command holds our copies of the pipe's write end: gone now, or
    // the CLI's exit would never read as end-of-output.
    drop(cmd);
    let Ok(mut child) = child else {
        return RunResult {
            status: -1,
            output: String::new(),
        };
    };
    on_start(child.id());
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(input) = input {
            let _ = stdin.write_all(input.as_bytes());
        }
        // Dropped: closed, so a second prompt reads EOF.
    }
    let mut file = std::fs::File::from(read_end);
    let deadline = Instant::now() + timeout;
    let mut output: Vec<u8> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut killed = false;
    let mut kill_started = None;
    let mut forced = false;
    let mut exited = false;
    let mut output_closed = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if (left.is_zero() || cancelled()) && !killed {
            let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            killed = true;
            kill_started = Some(Instant::now());
        }
        // A CLI ignoring TERM must not hold up the queued daemon disconnect.
        if !exited
            && !forced
            && kill_started.is_some_and(|at| at.elapsed() >= Duration::from_secs(2))
        {
            unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
            forced = true;
        }
        // The CLI's exit ends the run, as before, even if something it
        // started still holds the pipe: check it at least every 200 ms.
        if !exited && matches!(child.try_wait(), Ok(Some(_))) {
            exited = true;
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        }
        if exited && output_closed {
            break;
        }
        let wait_ms = if exited {
            0
        } else if killed {
            200
        } else {
            left.as_millis().clamp(1, 200) as i32
        };
        let mut p = libc::pollfd {
            fd: if output_closed { -1 } else { file.as_raw_fd() },
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut p, 1, wait_ms) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            output_closed = true;
            continue;
        }
        if ready == 0 {
            if exited {
                break; // drained
            }
            continue;
        }
        let n = match file.read(&mut buffer) {
            Ok(0) => {
                output_closed = true;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) if exited => break,
            Err(_) => {
                output_closed = true;
                continue;
            }
            Ok(n) => n,
        };
        output.extend_from_slice(&buffer[..n]);
        pending.extend_from_slice(&buffer[..n]);
        while let Some(i) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=i).collect();
            on_line(&String::from_utf8_lossy(&line[..line.len() - 1]));
        }
        if pending.ends_with(b": ") || pending.ends_with(b"] ") {
            on_line(&String::from_utf8_lossy(&pending));
            pending.clear();
        }
    }
    let status = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
    RunResult {
        status,
        output: String::from_utf8_lossy(&output).into_owned(),
    }
}

/// The last `>> state: X` the CLI printed.
pub fn parse_state(output: &str) -> Option<String> {
    output.lines().filter_map(|l| l.split_once(">> state: ").map(|(_, s)| s.trim().to_string())).last()
}

/// `vpn stats` "Server Address:" value, when it is an IP literal.
pub fn parse_server_address(stats: &str) -> Option<String> {
    stats.lines().filter(|l| l.contains("Server Address:")).find_map(|l| {
        let value = l.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
        value.chars().next().filter(|c| c.is_ascii_digit()).map(|_| value.to_string())
    })
}

/// The last `>> error:` line, without the prefix.
pub fn last_error(output: &str) -> Option<String> {
    output.lines().filter_map(|l| l.split_once(">> error: ").map(|(_, e)| e.trim().to_string())).last()
}

pub fn host_part(address: &str) -> String {
    let mut host = address;
    if let Some(i) = host.find("://") {
        host = &host[i + 3..];
    }
    if let Some(i) = host.find('/') {
        host = &host[..i];
    }
    if !host.contains(']') {
        if let Some(i) = host.rfind(':') {
            host = &host[..i];
        }
    }
    host.to_string()
}

/// The host's IPv4 addresses, in the resolver's order.
pub fn resolve(host: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if host.is_empty() {
        return out;
    }
    if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
        for a in addrs {
            if let std::net::SocketAddr::V4(v4) = a {
                let ip = v4.ip().to_string();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// The tunnel interface holding the default route, or None.
pub fn default_route_tunnel() -> Option<String> {
    crate::connections::default_route_interface().filter(|n| n.starts_with("utun"))
}

/// Classify the gateway response when observed, independently of EOF/reaping.
/// Missing timing stays a rejection rather than scheduling another phone push.
fn approval_expired_at_response(
    output: &str,
    pushed: Option<Instant>,
    failed_at: Option<Instant>,
    minimum: Duration,
) -> bool {
    output.contains("Login failed")
        && !output.contains("Login error")
        && pushed
            .zip(failed_at)
            .is_some_and(|(start, response)| response.saturating_duration_since(start) >= minimum)
}

// MARK: - The engine

pub struct Credentials {
    pub entry: String,
    pub username: String,
    pub password: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        // Best effort: no copy of the password outlives the attempt.
        unsafe {
            for b in self.password.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

pub struct Hooks {
    /// (state, detail). The App moves it to its main queue.
    pub state: Box<dyn Fn(i32, &str) + Send + Sync>,
    /// 1 = manual, 2 = rejected.
    pub terminal: Box<dyn Fn(i32) + Send + Sync>,
    pub kill_switch: Box<dyn Fn(i32, &str, &[String]) + Send + Sync>,
    /// Fresh for every (re)connect: the keychain is the only long-term store.
    pub credentials: Box<dyn Fn() -> Option<Credentials> + Send + Sync>,
    /// Every gateway host the Cisco profiles name, plus the selected entry's.
    pub profile_hosts: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    /// A fresh, read-only physical-route fact for change/deadline events.
    pub network_available: Box<dyn Fn() -> bool + Send + Sync>,
    /// Before a CLI login: ask Cisco's window app to quit (it holds the
    /// connect capability).
    pub before_login: Box<dyn Fn() + Send + Sync>,
    /// The App started (true) or let go of (false) the Cisco session.
    pub owned: Box<dyn Fn(bool) + Send + Sync>,
    pub log: Box<dyn Fn(&str) + Send + Sync>,
    /// A disconnect() finished.
    pub disconnected: Box<dyn Fn() + Send + Sync>,
}

pub struct Config {
    pub cli: String,
    /// A "Login failed" this soon after the password cannot be an
    /// expired approval; it counts as a rejection.
    pub approval_timeout_minimum: Duration,
    /// The fallback check interval (MONITOR; the harness shortens it).
    pub monitor: Duration,
}

enum Command_ {
    Connect(u32),
    Disconnect(u32),
    Rearm,
    Refresh(u32),
    /// The routing table changed.
    Changed,
    Network { available: bool, intent: u32 },
    #[cfg(test)]
    Barrier(Sender<()>),
}

struct Shared {
    config: Config,
    hooks: Hooks,
    stop_requested: AtomicBool,
    cancel_generation: AtomicU32,
    managing: AtomicBool,
    episode_retries: AtomicU32,
    reported: AtomicI32,
    offline: AtomicBool,
    network: Mutex<crate::offline::Gate>,
}

pub struct Engine {
    shared: Arc<Shared>,
    tx: Sender<Command_>,
}

struct State {
    intent: u32,
    wanted: bool,
    ever_connected: bool,
    tunnel_if: String,
    monitor_at: Option<Instant>,
    retry_at: Option<Instant>,
    backoff_index: usize,
    push_backoff_index: usize,
    unanswered_since: Option<Instant>,
    last_kill_switch: Option<(i32, String, Vec<String>)>,
    last_tick: Option<Instant>,
}

fn jitter() -> f64 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    0.8 + (nanos % 1_000_000) as f64 / 1_000_000.0 * 0.4
}

impl Engine {
    pub fn new(config: Config, hooks: Hooks) -> Engine {
        let shared = Arc::new(Shared {
            config,
            hooks,
            stop_requested: AtomicBool::new(false),
            cancel_generation: AtomicU32::new(0),
            managing: AtomicBool::new(false),
            episode_retries: AtomicU32::new(0),
            reported: AtomicI32::new(DISCONNECTED),
            offline: AtomicBool::new(false),
            network: Mutex::new(crate::offline::Gate::default()),
        });
        let (tx, rx) = mpsc::channel::<Command_>();
        let s = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ac-cisco".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut st = State {
                    intent: 0,
                    wanted: false,
                    ever_connected: false,
                    tunnel_if: String::new(),
                    monitor_at: None,
                    retry_at: None,
                    backoff_index: 0,
                    push_backoff_index: 0,
                    unanswered_since: None,
                    last_kill_switch: None,
                    last_tick: None,
                };
                loop {
                    let next = [st.monitor_at, st.retry_at].into_iter().flatten().min();
                    let received = match next {
                        Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
                        None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                    };
                    match received {
                        Ok(cmd) => s.command(&mut st, cmd),
                        Err(RecvTimeoutError::Disconnected) => return,
                        Err(RecvTimeoutError::Timeout) => {
                            let now = Instant::now();
                            if st.retry_at.is_some_and(|t| t <= now) {
                                st.retry_at = None;
                                s.attempt(&mut st);
                            }
                            if st.monitor_at.is_some_and(|t| t <= Instant::now()) {
                                st.monitor_at = Some(Instant::now() + s.config.monitor);
                                s.tick(&mut st);
                            }
                        }
                    }
                }
            })
            .expect("cisco engine thread");
        // Routing changes wake the watch at once instead of waiting for
        // the next 15 s check.
        let route_tx = tx.clone();
        let route_shared = Arc::clone(&shared);
        let _ = std::thread::Builder::new().name("ac-cisco-routes".into()).stack_size(64 * 1024).spawn(move || {
            let Some(watch) = crate::route_watch::RouteWatch::new() else { return };
            loop {
                if let crate::route_watch::Wake::Changed = watch.wait(Duration::from_secs(3600), Duration::from_millis(300), None) {
                    route_shared.observe_network(&route_tx, None);
                    if route_tx.send(Command_::Changed).is_err() {
                        return;
                    }
                }
            }
        });
        Engine { shared, tx }
    }

    pub fn connect(&self) {
        // Serialize intent publication with stop/network actions. A cancelled
        // queued start cannot adopt the epoch of a later recovery.
        {
            let mut gate = self.shared.network.lock().unwrap();
            self.shared.stop_requested.store(false, Ordering::SeqCst);
            self.shared.set_owned(true);
            gate.start();
            let intent = self.shared.current_intent();
            let _ = self.tx.send(Command_::Connect(intent));
        }
        self.shared.observe_network(&self.tx, None);
    }

    pub fn disconnect(&self) {
        let intent;
        {
            let mut gate = self.shared.network.lock().unwrap();
            gate.stop();
            self.shared.stop_requested.store(true, Ordering::SeqCst);
            intent = self
                .shared
                .cancel_generation
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1);
            self.shared.set_owned(false);
            let _ = self.tx.send(Command_::Disconnect(intent));
        }
        (self.shared.hooks.log)("disconnect requested");
        if self.shared.is_current(intent) {
            self.shared.post(DISCONNECTED, "正在断开…");
        }
    }

    /// The background service restarted: send it the current kill switch again.
    pub fn rearm(&self) {
        let _ = self.tx.send(Command_::Rearm);
    }

    /// Launch / panel open with the App's stored "owned" flag set: adopt a
    /// tunnel Cisco already has up.
    pub fn refresh(&self) {
        {
            let mut gate = self.shared.network.lock().unwrap();
            self.shared.managing.store(true, Ordering::SeqCst);
            gate.start();
            let _ = self
                .tx
                .send(Command_::Refresh(self.shared.current_intent()));
        }
        self.shared.observe_network(&self.tx, None);
    }

    /// A system path event (also used by the fake-CLI wiring harness).
    pub fn network_changed(&self) {
        self.shared.observe_network(&self.tx, None);
        let _ = self.tx.send(Command_::Changed);
    }

    pub fn is_managing(&self) -> bool {
        self.shared.managing.load(Ordering::SeqCst)
    }

    pub fn episode_retries(&self) -> u32 {
        self.shared.episode_retries.load(Ordering::SeqCst)
    }
}

impl Shared {
    /// Reuses routing events and one debounce deadline, independently of the
    /// worker which may be blocked inside Cisco's connect CLI.
    fn observe_network(self: &Arc<Self>, tx: &Sender<Command_>, deadline: Option<u64>) {
        let available = (self.hooks.network_available)();
        let mut gate = self.network.lock().unwrap();
        let actions = match deadline {
            Some(token) => gate.deadline(token, available),
            None => gate.observe(available),
        };
        self.offline.store(gate.paused, Ordering::SeqCst);
        for action in actions {
            match action {
                crate::offline::Action::Deadline(token) => {
                    let weak = Arc::downgrade(self);
                    let tx = tx.clone();
                    let _ = std::thread::Builder::new()
                        .name("ac-offline-debounce".into())
                        .stack_size(32 * 1024)
                        .spawn(move || {
                            std::thread::sleep(Duration::from_secs(2));
                            if let Some(shared) = weak.upgrade() {
                                shared.observe_network(&tx, Some(token));
                            }
                        });
                }
                crate::offline::Action::Cancel => {
                    let intent = self
                        .cancel_generation
                        .fetch_add(1, Ordering::SeqCst)
                        .wrapping_add(1);
                    let _ = tx.send(Command_::Network {
                        available: false,
                        intent,
                    });
                }
                crate::offline::Action::Resume => {
                    let _ = tx.send(Command_::Network {
                        available: true,
                        intent: self.current_intent(),
                    });
                }
            }
        }
    }

    fn set_owned(&self, owned: bool) {
        self.managing.store(owned, Ordering::SeqCst);
        (self.hooks.owned)(owned);
    }

    fn stopped(&self) -> bool {
        self.stop_requested.load(Ordering::SeqCst) || self.offline.load(Ordering::SeqCst)
    }

    fn current_intent(&self) -> u32 {
        self.cancel_generation.load(Ordering::SeqCst)
    }

    fn is_current(&self, intent: u32) -> bool {
        self.current_intent() == intent
    }

    fn permits_attempt(&self, intent: u32) -> bool {
        self.is_current(intent) && !self.stopped()
    }

    fn cli(
        &self,
        intent: u32,
        args: &[&str],
        input: Option<&str>,
        timeout: Duration,
        on_line: &mut dyn FnMut(&str),
    ) -> RunResult {
        let cancelled = || args != ["disconnect"] && !self.permits_attempt(intent);
        if cancelled() {
            return RunResult {
                status: -1,
                output: String::new(),
            };
        }
        let mut on_start = |pid: u32| {
            // The child is unreaped here. Never keep a PID across a wait/reap:
            // the cancellation predicate instead follows the login intent.
            if cancelled() {
                unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            }
        };
        let mut current_line = |line: &str| {
            if !cancelled() {
                on_line(line);
            }
        };
        let mut result = run_interruptible(
            &self.config.cli,
            args,
            input,
            timeout,
            &mut on_start,
            &mut current_line,
            &cancelled,
        );
        if cancelled() {
            result.status = -1;
            result.output.clear();
        }
        result
    }

    fn state_now(&self, intent: u32) -> Option<String> {
        parse_state(
            &self
                .cli(
                    intent,
                    &["state"],
                    None,
                    Duration::from_secs(30),
                    &mut |_| {},
                )
                .output,
        )
    }

    fn post(&self, state: i32, detail: &str) {
        if state != DISCONNECTED && self.stop_requested.load(Ordering::SeqCst) { return; }
        if state != DISCONNECTED && self.offline.load(Ordering::SeqCst) && detail != "等待网络恢复" { return; }
        (self.hooks.state)(state, detail);
    }

    fn report(&self, state: i32, detail: &str) {
        self.reported.store(state, Ordering::SeqCst);
        (self.hooks.log)(&format!("state={state} {detail}"));
        self.post(state, detail);
    }

    fn reported(&self) -> i32 {
        self.reported.load(Ordering::SeqCst)
    }

    fn send_kill_switch(&self, st: &mut State, mode: i32, tun: &str, gateways: Vec<String>) {
        if !self.is_current(st.intent) || self.stop_requested.load(Ordering::SeqCst) {
            return;
        }
        (self.hooks.log)(&format!(
            "killswitch mode={mode} gateways={}",
            gateways.len()
        ));
        let last = st.last_kill_switch.take();
        let keep_tun = if tun.is_empty() {
            last.as_ref().map(|l| l.1.clone()).unwrap_or_default()
        } else {
            tun.to_string()
        };
        let keep_gw = if gateways.is_empty() {
            last.map(|l| l.2).unwrap_or_default()
        } else {
            gateways.clone()
        };
        st.last_kill_switch = Some((mode, keep_tun, keep_gw));
        (self.hooks.kill_switch)(mode, tun, &gateways);
    }

    fn command(&self, st: &mut State, cmd: Command_) {
        match cmd {
            Command_::Connect(intent) => {
                if !self.is_current(intent) || self.stop_requested.load(Ordering::SeqCst) {
                    return;
                }
                st.intent = intent;
                st.wanted = true;
                if self.offline.load(Ordering::SeqCst) {
                    self.report(RECONNECTING, "等待网络恢复");
                    return;
                }
                st.backoff_index = 0;
                st.push_backoff_index = 0;
                st.unanswered_since = None;
                if self.state_now(st.intent).as_deref() == Some("Connected") {
                    self.adopt_connected(st);
                } else {
                    self.attempt(st);
                }
                if self.permits_attempt(intent) && st.monitor_at.is_none() {
                    st.monitor_at = Some(Instant::now() + self.config.monitor);
                }
            }
            Command_::Network { available, intent } => {
                if !self.is_current(intent)
                    || !self.managing.load(Ordering::SeqCst)
                    || self.stop_requested.load(Ordering::SeqCst)
                {
                    return;
                }
                // The desired start may itself have been superseded while queued.
                st.intent = intent;
                st.wanted = true;
                st.retry_at = None;
                st.monitor_at = None;
                if !available {
                    // Keep ownership and the held set. Never use manual-stop's
                    // release path for an unavailable physical network.
                    if st.last_kill_switch.is_some() {
                        self.send_kill_switch(st, 2, "", Vec::new());
                    }
                    self.cli(
                        st.intent,
                        &["disconnect"],
                        None,
                        Duration::from_secs(30),
                        &mut |_| {},
                    );
                    if self.is_current(intent) {
                        self.report(RECONNECTING, "等待网络恢复");
                    }
                } else if !self.stopped() {
                    st.backoff_index = 0;
                    st.monitor_at = Some(Instant::now() + self.config.monitor);
                    self.attempt(st);
                }
            }
            Command_::Disconnect(intent) => {
                st.intent = intent;
                st.wanted = false;
                st.retry_at = None;
                st.last_kill_switch = None;
                st.monitor_at = None;
                self.cli(
                    st.intent,
                    &["disconnect"],
                    None,
                    Duration::from_secs(30),
                    &mut |_| {},
                );
                st.ever_connected = false;
                self.episode_retries.store(0, Ordering::SeqCst);
                if self.is_current(intent) {
                    self.report(DISCONNECTED, "manual disconnect");
                    (self.hooks.terminal)(1);
                }
                // Every stop still acknowledges its FIFO cleanup barrier.
                (self.hooks.disconnected)();
            }
            #[cfg(test)]
            Command_::Barrier(done) => {
                let _ = done.send(());
            }
            Command_::Rearm => {
                if let Some((mode, tun, gateways)) = st.last_kill_switch.clone() {
                    self.send_kill_switch(st, mode, &tun, gateways);
                }
            }
            Command_::Changed => {
                let recent = st.last_tick.is_some_and(|t| t.elapsed() < CHANGE_DEBOUNCE);
                if st.monitor_at.is_some() && !recent {
                    st.monitor_at = Some(Instant::now() + self.config.monitor);
                    self.tick(st);
                }
            }
            Command_::Refresh(intent) => {
                if !self.permits_attempt(intent) {
                    return;
                }
                st.intent = intent;
                let state = self.state_now(intent);
                if state.as_deref() == Some("Connected") && self.reported() != CONNECTED {
                    st.wanted = true;
                    self.adopt_connected(st);
                    if st.monitor_at.is_none() {
                        st.monitor_at = Some(Instant::now() + self.config.monitor);
                    }
                } else if state.as_deref() == Some("Disconnected") && !st.wanted {
                    // Ours once, gone since, not being brought back: forget it.
                    self.set_owned(false);
                }
            }
        }
    }

    fn attempt(&self, st: &mut State) {
        let intent = st.intent;
        st.retry_at = None;
        if !st.wanted || !self.permits_attempt(intent) {
            return;
        }
        let credentials = (self.hooks.credentials)();
        if !self.permits_attempt(intent) {
            return;
        }
        let Some(credentials) = credentials else {
            self.report(DISCONNECTED, "未设置凭据");
            return;
        };
        (self.hooks.before_login)();
        // Credentials / quitting the Cisco window can block. A stop during
        // either operation must not start a new CLI login afterwards.
        if !self.permits_attempt(intent) {
            return;
        }
        if st.ever_connected && st.last_kill_switch.as_ref().is_some_and(|k| k.0 == 2) {
            // Resolved now, through the DNS the blocking set lets out.
            let gateways = self.gateway_addresses(st, None);
            self.send_kill_switch(st, 2, "", gateways);
        }
        if !self.permits_attempt(intent) {
            return;
        }
        self.report(
            if st.ever_connected {
                RECONNECTING
            } else {
                AUTHENTICATING
            },
            &format!("正在登录 {}", credentials.entry),
        );
        let mut input = format!(
            "connect {}\n{}\n{}\n",
            credentials.entry, credentials.username, credentials.password
        );
        let mut pushed: Option<Instant> = None;
        let mut failed_at: Option<Instant> = None;
        let result = self.cli(
            intent,
            &["-s"],
            Some(&input),
            Duration::from_secs(180),
            &mut |line: &str| {
                if !self.permits_attempt(intent) {
                    return;
                }
                if line.contains("Login failed") || line.contains("Login error") {
                    failed_at.get_or_insert_with(Instant::now);
                }
                if line.contains(">> ") && !line.contains("Username") {
                    (self.hooks.log)(&format!("cisco: {}", line.trim()));
                }
                if line.contains("Username:") {
                    // The password goes in right after; the gateway then
                    // pushes an approval and waits for it silently.
                    if pushed.is_none() {
                        pushed = Some(Instant::now());
                    }
                    self.post(AWAITING_APPROVAL, "已提交密码，等你在手机上确认登录");
                } else if line.contains(">> notice: Establishing VPN") {
                    self.post(CONNECTING, &line.replace("  >> notice: ", ""));
                }
            },
        );
        unsafe {
            for b in input.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
        drop(credentials);
        if !self.permits_attempt(intent) {
            return;
        }
        let output = result.output;
        if parse_state(&output).as_deref() == Some("Connected")
            || output.contains(">> state: Connected")
        {
            self.adopt_connected(st);
            return;
        }
        let approval_expired = approval_expired_at_response(
            &output,
            pushed,
            failed_at,
            self.config.approval_timeout_minimum,
        );
        if approval_expired {
            // Nobody tapped approve in time: ask again later, more and
            // more slowly.
            if st.unanswered_since.is_none() {
                st.unanswered_since = Some(Instant::now());
            }
            self.schedule_retry(st, "手机上的批准已超时", true, true);
            return;
        }
        if output.contains("Login error") || output.contains("Login failed") {
            // Anti-lockout: never retry a rejected login on our own. The
            // session is no longer ours (§25.4).
            self.set_owned(false);
            st.wanted = false;
            st.monitor_at = None;
            self.report(DISCONNECTED, "账号或密码被拒绝，请检查凭据");
            (self.hooks.terminal)(2);
            return;
        }
        let error = last_error(&output).unwrap_or_else(|| "连接未完成".into());
        self.schedule_retry(st, &error, pushed.is_some(), false);
    }

    fn schedule_retry(&self, st: &mut State, error: &str, pushed: bool, approval_expired: bool) {
        if !st.wanted || !self.permits_attempt(st.intent) || st.retry_at.is_some() {
            return;
        }
        let mut base;
        if pushed {
            base = PUSH_BACKOFF[st.push_backoff_index.min(PUSH_BACKOFF.len() - 1)];
            st.push_backoff_index += 1;
            if st
                .unanswered_since
                .is_some_and(|t| t.elapsed() >= QUIET_AFTER)
            {
                base = QUIET_INTERVAL;
            }
        } else {
            base = BACKOFF[st.backoff_index.min(BACKOFF.len() - 1)];
            st.backoff_index += 1;
        }
        let delay = base * jitter();
        if st.ever_connected {
            self.episode_retries.fetch_add(1, Ordering::SeqCst);
        }
        let wait = delay.round() as u64;
        let when = if wait >= 120 {
            format!("{} 分钟", wait / 60)
        } else {
            format!("{wait} 秒")
        };
        let detail = if approval_expired {
            format!("{error}，{when}后重新发起批准")
        } else {
            format!("{error}；{when}后重试")
        };
        self.report(
            if st.ever_connected {
                RECONNECTING
            } else {
                AUTHENTICATING
            },
            &detail,
        );
        st.retry_at = Some(Instant::now() + Duration::from_secs_f64(delay));
    }

    /// Every address a Cisco login may use: the live session's server,
    /// every IP of every gateway in the Cisco profiles (one name has
    /// several, and Cisco may pick another or a backup, §21.10), and the
    /// ones already let through.
    fn gateway_addresses(&self, st: &State, server: Option<String>) -> Vec<String> {
        let mut gateways: Vec<String> = server.into_iter().collect();
        let mut hosts: Vec<String> = (self.hooks.profile_hosts)().iter().map(|h| host_part(h)).collect();
        hosts.sort();
        hosts.dedup();
        for host in hosts {
            for ip in resolve(&host) {
                if !gateways.contains(&ip) {
                    gateways.push(ip);
                }
            }
        }
        if let Some((_, _, last)) = &st.last_kill_switch {
            for ip in last {
                if !gateways.contains(ip) {
                    gateways.push(ip.clone());
                }
            }
        }
        gateways
    }

    fn adopt_connected(&self, st: &mut State) {
        let stats = self
            .cli(
                st.intent,
                &["stats"],
                None,
                Duration::from_secs(30),
                &mut |_| {},
            )
            .output;
        if !self.permits_attempt(st.intent) {
            return;
        }
        st.tunnel_if = default_route_tunnel().unwrap_or_else(|| st.tunnel_if.clone());
        let gateways = self.gateway_addresses(st, parse_server_address(&stats));
        if !self.permits_attempt(st.intent) {
            return;
        }
        st.ever_connected = true;
        self.episode_retries.store(0, Ordering::SeqCst);
        st.backoff_index = 0;
        st.push_backoff_index = 0;
        st.unanswered_since = None;
        st.retry_at = None;
        let tun = st.tunnel_if.clone();
        self.send_kill_switch(st, 1, &tun, gateways);
        self.report(CONNECTED, "已连接（经 Cisco）");
    }

    fn tick(&self, st: &mut State) {
        // A disconnect the user asked for may be waiting behind this
        // check: a "Disconnected" now is that, not a drop to block and
        // retry (2026-11-06: switching to the own connection disconnects
        // Cisco, the routing change woke this check first).
        if !st.wanted || !self.permits_attempt(st.intent) {
            return;
        }
        st.last_tick = Some(Instant::now());
        let state = self.state_now(st.intent);
        if !self.permits_attempt(st.intent) {
            return;
        }
        match state.as_deref() {
            Some("Connected") => {
                let tun = default_route_tunnel().unwrap_or_else(|| st.tunnel_if.clone());
                if self.reported() != CONNECTED || tun != st.tunnel_if {
                    self.adopt_connected(st);
                }
            }
            Some("Reconnecting") => {
                // Cisco is resuming its own session: hold the line.
                if self.reported() == CONNECTED {
                    self.send_kill_switch(st, 2, "", Vec::new());
                    self.report(RECONNECTING, "Cisco 正在重连，网络已拦截");
                }
            }
            Some("Disconnected") => {
                // A session that was up is gone: block, then log in again.
                if !st.ever_connected {
                    return;
                }
                let reported = self.reported();
                if reported == CONNECTED
                    || (reported == RECONNECTING
                        && st.last_kill_switch.as_ref().map(|k| k.0) != Some(2))
                {
                    self.send_kill_switch(st, 2, "", Vec::new());
                    self.report(RECONNECTING, "已断开，网络已拦截，正在重连");
                }
                self.schedule_retry(st, "会话已断开", false, false);
            }
            _ => {}
        }
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_during_login_preparation_never_starts_cli_or_retries() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ac-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let cli = dir.join("vpn");
        std::fs::write(&cli, "#!/bin/sh\ncase \"$1\" in\nstate) echo '>> state: Disconnected';;\n-s) touch \"$(dirname \"$0\")/login\";;\ndisconnect) touch \"$(dirname \"$0\")/cancel\";;\nesac\n").unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (entered, wait_entered) = mpsc::channel();
        let (release, wait_release) = mpsc::channel();
        let wait_release = Mutex::new(wait_release);
        let (done, wait_done) = mpsc::channel();
        let engine = Engine::new(
            Config {
                cli: cli.to_str().unwrap().into(),
                approval_timeout_minimum: Duration::from_secs(20),
                monitor: MONITOR,
            },
            Hooks {
                state: Box::new(|_, _| {}),
                terminal: Box::new(|_| {}),
                kill_switch: Box::new(|_, _, _| {}),
                credentials: Box::new(|| {
                    Some(Credentials {
                        entry: "VPN-A".into(),
                        username: "u".into(),
                        password: "p".into(),
                    })
                }),
                profile_hosts: Box::new(Vec::new),
                network_available: Box::new(|| true),
                before_login: Box::new(move || {
                    entered.send(()).unwrap();
                    wait_release.lock().unwrap().recv().unwrap();
                }),
                owned: Box::new(|_| {}),
                log: Box::new(|_| {}),
                disconnected: Box::new(move || {
                    let _ = done.send(());
                }),
            },
        );
        engine.connect();
        wait_entered.recv_timeout(Duration::from_secs(15)).unwrap();
        engine.disconnect();
        release.send(()).unwrap();
        wait_done.recv_timeout(Duration::from_secs(15)).unwrap();
        assert!(
            !dir.join("login").exists(),
            "cancelled preparation must never submit a login"
        );
        assert!(
            dir.join("cancel").exists(),
            "Cisco daemon must receive disconnect, not just CLI termination"
        );
        assert!(!engine.is_managing());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parsing() {
        let out = "  >> state: Connecting\n  >> notice: x\n  >> state: Connected\n";
        assert_eq!(parse_state(out).as_deref(), Some("Connected"));
        assert_eq!(parse_state("nothing"), None);
        assert_eq!(
            parse_state("\r  >> state: Unknown\n\r  >> state: Disconnected\nVPN> ").as_deref(),
            Some("Disconnected")
        );
        assert_eq!(parse_server_address("  Server Address:   198.51.100.9\n").as_deref(), Some("198.51.100.9"));
        assert_eq!(parse_server_address("  Server Address: gw.example\n"), None);
        assert_eq!(last_error("  >> error: one\n  >> error: two \n").as_deref(), Some("two"));
        assert_eq!(host_part("https://gw.example:8443/group"), "gw.example");
        assert_eq!(host_part("gw.example"), "gw.example");
        assert_eq!(resolve("127.0.0.1"), vec!["127.0.0.1"]);
    }

    #[test]
    fn term_ignoring_cli_has_a_bounded_shutdown() {
        for script in [
            "trap '' TERM; exec sleep 30",
            "exec 1>&- 2>&-; trap '' TERM; exec sleep 30",
        ] {
            let start = Instant::now();
            let result = run(
                "/bin/sh",
                &["-c", script],
                None,
                Duration::from_millis(300),
                &mut |_| {},
                &mut |_| {},
            );
            assert_ne!(result.status, 0);
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "TERM refusal or closed output must not wedge the engine"
            );
        }
    }

    #[test]
    fn run_streams_lines_and_prompts() {
        let mut lines = Vec::new();
        let r = run("/bin/sh", &["-c", "printf 'a\\nUsername: '; read x; printf '\\nb\\n'; exit 3"], Some("u\n"),
                    Duration::from_secs(5), &mut |_| {}, &mut |l| lines.push(l.to_string()));
        assert_eq!(r.status, 3);
        // Whether the newline after the prompt comes as its own (empty)
        // line depends on how the reads split the output: ignore it.
        lines.retain(|l| !l.is_empty());
        assert_eq!(lines, vec!["a", "Username: ", "b"]);
        let t = Instant::now();
        let r = run("/bin/sleep", &["10"], None, Duration::from_millis(300), &mut |_| {}, &mut |_| {});
        assert!(t.elapsed() < Duration::from_secs(3) && r.status != 0, "timed out and ended");
    }
}

#[cfg(test)]
mod intent_tests;
