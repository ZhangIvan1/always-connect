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
//! before; a disconnect kills the CLI from the caller's thread at once.

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
pub fn run(cli: &str, args: &[&str], input: Option<&str>, timeout: Duration,
           on_start: &mut dyn FnMut(u32), on_line: &mut dyn FnMut(&str)) -> RunResult {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return RunResult { status: -1, output: String::new() };
    }
    for fd in fds {
        // Only the child's stdout/stderr may hold the write end: a stray
        // copy kept the pipe open past the CLI's exit.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let Ok(err_end) = write_end.try_clone() else { return RunResult { status: -1, output: String::new() } };
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
    let Ok(mut child) = child else { return RunResult { status: -1, output: String::new() } };
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
    let mut exited = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() && !killed {
            let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            killed = true;
        }
        // The CLI's exit ends the run, as before, even if something it
        // started still holds the pipe: check it at least every 200 ms.
        if !exited && matches!(child.try_wait(), Ok(Some(_))) {
            exited = true;
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        }
        let wait_ms = if exited { 0 } else { left.as_millis().clamp(1, 200) as i32 };
        let mut p = libc::pollfd { fd: file.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut p, 1, wait_ms) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 {
            if exited {
                break; // drained
            }
            continue;
        }
        let n = match file.read(&mut buffer) {
            Ok(0) | Err(_) => break,
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
    RunResult { status, output: String::from_utf8_lossy(&output).into_owned() }
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
    Connect,
    Disconnect,
    Rearm,
    Refresh,
    /// The routing table changed.
    Changed,
}

struct Shared {
    config: Config,
    hooks: Hooks,
    stop_requested: AtomicBool,
    active_pid: Mutex<Option<u32>>,
    managing: AtomicBool,
    episode_retries: AtomicU32,
    reported: AtomicI32,
}

pub struct Engine {
    shared: Arc<Shared>,
    tx: Sender<Command_>,
}

struct State {
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
            active_pid: Mutex::new(None),
            managing: AtomicBool::new(false),
            episode_retries: AtomicU32::new(0),
            reported: AtomicI32::new(DISCONNECTED),
        });
        let (tx, rx) = mpsc::channel::<Command_>();
        let s = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ac-cisco".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut st = State {
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
        let _ = std::thread::Builder::new().name("ac-cisco-routes".into()).stack_size(64 * 1024).spawn(move || {
            let Some(watch) = crate::route_watch::RouteWatch::new() else { return };
            loop {
                if let crate::route_watch::Wake::Changed = watch.wait(Duration::from_secs(3600), Duration::from_millis(300), None) {
                    if route_tx.send(Command_::Changed).is_err() {
                        return;
                    }
                }
            }
        });
        Engine { shared, tx }
    }

    pub fn connect(&self) {
        self.shared.stop_requested.store(false, Ordering::SeqCst);
        self.shared.set_owned(true);
        let _ = self.tx.send(Command_::Connect);
    }

    pub fn disconnect(&self) {
        self.shared.set_owned(false);
        self.shared.stop_requested.store(true, Ordering::SeqCst);
        if let Some(pid) = *self.shared.active_pid.lock().unwrap() {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
        (self.shared.hooks.log)("disconnect requested");
        // Answer the click at once; Cisco may take a while to wind down
        // a login that was still trying.
        self.shared.post(DISCONNECTED, "正在断开…");
        let _ = self.tx.send(Command_::Disconnect);
    }

    /// The background service restarted: send it the current kill switch again.
    pub fn rearm(&self) {
        let _ = self.tx.send(Command_::Rearm);
    }

    /// Launch / panel open with the App's stored "owned" flag set: adopt a
    /// tunnel Cisco already has up.
    pub fn refresh(&self) {
        self.shared.managing.store(true, Ordering::SeqCst);
        let _ = self.tx.send(Command_::Refresh);
    }

    pub fn is_managing(&self) -> bool {
        self.shared.managing.load(Ordering::SeqCst)
    }

    pub fn episode_retries(&self) -> u32 {
        self.shared.episode_retries.load(Ordering::SeqCst)
    }
}

impl Shared {
    fn set_owned(&self, owned: bool) {
        self.managing.store(owned, Ordering::SeqCst);
        (self.hooks.owned)(owned);
    }

    fn stopped(&self) -> bool {
        self.stop_requested.load(Ordering::SeqCst)
    }

    fn cli(&self, args: &[&str], input: Option<&str>, timeout: Duration, on_line: &mut dyn FnMut(&str)) -> RunResult {
        let mut on_start = |pid: u32| *self.active_pid.lock().unwrap() = Some(pid);
        let result = run(&self.config.cli, args, input, timeout, &mut on_start, on_line);
        *self.active_pid.lock().unwrap() = None;
        result
    }

    fn state_now(&self) -> Option<String> {
        parse_state(&self.cli(&["state"], None, Duration::from_secs(30), &mut |_| {}).output)
    }

    fn post(&self, state: i32, detail: &str) {
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
        (self.hooks.log)(&format!("killswitch mode={mode} gateways={}", gateways.len()));
        let last = st.last_kill_switch.take();
        let keep_tun = if tun.is_empty() { last.as_ref().map(|l| l.1.clone()).unwrap_or_default() } else { tun.to_string() };
        let keep_gw = if gateways.is_empty() { last.map(|l| l.2).unwrap_or_default() } else { gateways.clone() };
        st.last_kill_switch = Some((mode, keep_tun, keep_gw));
        (self.hooks.kill_switch)(mode, tun, &gateways);
    }

    fn command(&self, st: &mut State, cmd: Command_) {
        match cmd {
            Command_::Connect => {
                st.wanted = true;
                st.backoff_index = 0;
                st.push_backoff_index = 0;
                st.unanswered_since = None;
                if self.state_now().as_deref() == Some("Connected") {
                    self.adopt_connected(st);
                } else {
                    self.attempt(st);
                }
                if st.monitor_at.is_none() {
                    st.monitor_at = Some(Instant::now() + self.config.monitor);
                }
            }
            Command_::Disconnect => {
                st.wanted = false;
                st.retry_at = None;
                st.last_kill_switch = None;
                st.monitor_at = None;
                self.cli(&["disconnect"], None, Duration::from_secs(30), &mut |_| {});
                st.ever_connected = false;
                self.episode_retries.store(0, Ordering::SeqCst);
                self.report(DISCONNECTED, "manual disconnect");
                (self.hooks.terminal)(1);
                (self.hooks.disconnected)();
            }
            Command_::Rearm => {
                if let Some((mode, tun, gateways)) = st.last_kill_switch.clone() {
                    (self.hooks.kill_switch)(mode, &tun, &gateways);
                }
            }
            Command_::Changed => {
                let recent = st.last_tick.is_some_and(|t| t.elapsed() < CHANGE_DEBOUNCE);
                if st.monitor_at.is_some() && !recent {
                    st.monitor_at = Some(Instant::now() + self.config.monitor);
                    self.tick(st);
                }
            }
            Command_::Refresh => {
                let state = self.state_now();
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
        st.retry_at = None;
        if !st.wanted || self.stopped() {
            return;
        }
        let Some(credentials) = (self.hooks.credentials)() else {
            self.report(DISCONNECTED, "未设置凭据");
            return;
        };
        (self.hooks.before_login)();
        if st.ever_connected && st.last_kill_switch.as_ref().is_some_and(|k| k.0 == 2) {
            // Resolved now, through the DNS the blocking set lets out.
            let gateways = self.gateway_addresses(st, None);
            self.send_kill_switch(st, 2, "", gateways);
        }
        self.report(if st.ever_connected { RECONNECTING } else { AUTHENTICATING },
                    &format!("正在登录 {}", credentials.entry));
        let mut input = format!("connect {}\n{}\n{}\n", credentials.entry, credentials.username, credentials.password);
        let mut pushed: Option<Instant> = None;
        let result = self.cli(&["-s"], Some(&input), Duration::from_secs(180), &mut |line: &str| {
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
        });
        unsafe {
            for b in input.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
        drop(credentials);
        if self.stopped() {
            return;
        }
        let output = result.output;
        if parse_state(&output).as_deref() == Some("Connected") || output.contains(">> state: Connected") {
            self.adopt_connected(st);
            return;
        }
        let approval_expired = output.contains("Login failed")
            && !output.contains("Login error")
            && pushed.is_some_and(|t| t.elapsed() >= self.config.approval_timeout_minimum);
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
        if !st.wanted || self.stopped() || st.retry_at.is_some() {
            return;
        }
        let mut base;
        if pushed {
            base = PUSH_BACKOFF[st.push_backoff_index.min(PUSH_BACKOFF.len() - 1)];
            st.push_backoff_index += 1;
            if st.unanswered_since.is_some_and(|t| t.elapsed() >= QUIET_AFTER) {
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
        let when = if wait >= 120 { format!("{} 分钟", wait / 60) } else { format!("{wait} 秒") };
        let detail = if approval_expired { format!("{error}，{when}后重新发起批准") } else { format!("{error}；{when}后重试") };
        self.report(if st.ever_connected { RECONNECTING } else { AUTHENTICATING }, &detail);
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
        let stats = self.cli(&["stats"], None, Duration::from_secs(30), &mut |_| {}).output;
        st.tunnel_if = default_route_tunnel().unwrap_or_else(|| st.tunnel_if.clone());
        let gateways = self.gateway_addresses(st, parse_server_address(&stats));
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
        if !st.wanted || self.stopped() {
            return;
        }
        st.last_tick = Some(Instant::now());
        let state = self.state_now();
        if self.stopped() {
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
                    || (reported == RECONNECTING && st.last_kill_switch.as_ref().map(|k| k.0) != Some(2))
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
    fn parsing() {
        let out = "  >> state: Connecting\n  >> notice: x\n  >> state: Connected\n";
        assert_eq!(parse_state(out).as_deref(), Some("Connected"));
        assert_eq!(parse_state("nothing"), None);
        assert_eq!(parse_server_address("  Server Address:   198.51.100.9\n").as_deref(), Some("198.51.100.9"));
        assert_eq!(parse_server_address("  Server Address: gw.example\n"), None);
        assert_eq!(last_error("  >> error: one\n  >> error: two \n").as_deref(), Some("two"));
        assert_eq!(host_part("https://gw.example:8443/group"), "gw.example");
        assert_eq!(host_part("gw.example"), "gw.example");
        assert_eq!(resolve("127.0.0.1"), vec!["127.0.0.1"]);
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
