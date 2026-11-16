//! The openconnect engine (DESIGN.md §15–§16, §20, §23, §25–§30; moved
//! from Swift to Rust in §32.13): one session's lifecycle. It spawns the
//! openconnect CLI, feeds the credential over stdin, watches its output,
//! classifies the child's exit and drives the session driver
//! (crate::session) for state and retry decisions. It never guesses:
//! classification uses only observed facts — the stop flag, the
//! vpnc-script's `AC_HOOK connect`, which credential was fed, and the
//! measured output lines.
//!
//! Credentials: a usable stored cookie first (--cookie-on-stdin), else
//! the password (--passwd-on-stdin), held in memory only. The tunnel
//! cookie is captured from `--dump-http-traffic`: the CSTP CONNECT's
//! `Cookie: webvpn=` request header (Set-Cookie values are elided by
//! openconnect). A cookie run that ends without a connect hook drops the
//! record and falls back to the password once. "Login failed." soon after
//! the password = rejected: stop, never retry (anti-lockout); long after
//! = the phone approval expired: ask again, slower and slower (§30.9).
//!
//! Fail-closed: pf (through the network gate, the only pf writer) is
//! loaded on the connect hook and reloaded blocking on a drop; only a
//! manual stop releases it, with the script's restore. With drop
//! protection off, a drop gives the local network back while retrying.
//!
//! The child's output is never logged raw: `redact` masks webvpn=,
//! webvpncontext= and the <password> element, resuming each search after
//! the masked value.
//!
//! One event thread owns the state; openconnect's two output pipes have
//! reader threads, its exit a waiter thread; timers are short sleeping
//! threads that post an event. Idle between sessions it wakes for nothing
//! but routing changes (the physical-network follow of a split session).

use crate::dns_forwarder::{self, Forwarder, Upstreams};
use crate::direct_routes::{self, DirectRoutes};
use crate::network_guard::{self, Guard, Inputs, CISCO_HOLDER};
use crate::session::{AuthOutcome, DriverAction, SessionDriver};
use crate::state_machine::SessionStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// MARK: - Configuration and hooks

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct RelayConfig {
    pub gateway_ip: String,
    /// openconnect arguments for a run through the relay.
    pub arguments: Vec<String>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub server: String,
    pub group: String,
    pub username: String,
    pub password: String,
    pub openconnect_path: Option<String>,
    pub cafile: Option<String>,
    pub script_path: String,
    pub cookie_store_path: String,
    pub physical_if: String,
    pub allow_networks: Vec<String>,
    pub max_attempts: Option<u32>,
    pub allow_direct_egress_when_connected: bool,
    pub no_routes: bool,
    pub support_dir: String,
    pub debug_child_output: bool,
    pub relay: Option<RelayConfig>,
    pub direct_domains: Option<Vec<String>>,
    pub drop_protection: bool,
    /// The session harness's scratch root is in use (TestSeam).
    pub test_active: bool,
    /// TestSeam's stand-in openconnect, when test_active.
    pub test_openconnect: Option<String>,
    pub boot_session: String,
    pub approval_quiet_secs: f64,
    pub approval_expiry_minimum: f64,
    pub push_backoff: Vec<f64>,
}

pub const QUIET_AFTER: f64 = 3600.0;
pub const QUIET_INTERVAL: f64 = 900.0;
/// After a quick failed phone confirmation, ask once more after this
/// (±20%; the first push backoff when configured) before giving up (§43).
pub const DECLINED_RETRY: f64 = 30.0;

pub struct Hooks {
    /// (state code 0-5, detail).
    pub state: Box<dyn Fn(i32, &str) + Send + Sync>,
    /// 0 = manual stop, 1 = auth failure, 2 = attempts exhausted.
    pub terminal: Box<dyn Fn(i32) + Send + Sync>,
    /// The physical network now (configd): (router, interface).
    pub physical_network: Box<dyn Fn(&str) -> Option<(String, String)> + Send + Sync>,
    /// The local network's DNS servers for an interface (configd).
    pub local_dns: Box<dyn Fn(&str) -> Vec<String> + Send + Sync>,
    /// macOS's root certificates as a PEM path (Security), or None.
    pub system_roots: Box<dyn Fn() -> Option<String> + Send + Sync>,
    /// A stop() asked to be told: openconnect is gone, routes and pf restored.
    pub stopped: Box<dyn Fn() + Send + Sync>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Terminal {
    StoppedManual = 0,
    AuthFailure = 1,
    AttemptsExhausted = 2,
    ComponentMissing = 3,
    /// The gateway took the password and waited for the phone, then the
    /// confirmation failed quickly twice in a row (§43): declined on the
    /// phone, or the phone could not reach its service.
    ApprovalDeclined = 4,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Credential {
    Password,
    Cookie,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Timer {
    ForceKill,
    ApprovalProbe,
    ApprovalTimeout,
    NetWatch,
}

enum Event {
    Start,
    Stop { keep_session: bool, notify: bool },
    Output { generation: u64, stdout: bool, bytes: Vec<u8> },
    Exited { generation: u64 },
    Fire { timer: Timer, token: u64 },
    StopKill { pid: i32, generation: u64 },
    NetworkChanged,
    DirectDomains(Vec<String>),
    DropProtection(bool),
    AllowNetworks(Vec<String>),
    DnsAnswer(dns_forwarder::Observation, Sender<bool>),
    /// A scheduled retry: spawn again unless a manual stop landed first.
    Respawn,
    Release,
}

// MARK: - Helpers (pure)

/// Masks webvpn=, webvpncontext= values and <password> content; each
/// search resumes after the mask (the key stays in the string).
pub fn redact(line: &str) -> String {
    let mut out = line.to_string();
    for key in ["webvpncontext=", "webvpn="] {
        let mut from = 0;
        while let Some(i) = out[from..].find(key) {
            let start = from + i + key.len();
            let end = out[start..].find([';', ' ', '\t']).map(|e| start + e).unwrap_or(out.len());
            out.replace_range(start..end, "***");
            from = start + 3;
        }
    }
    let mut from = 0;
    while let Some(i) = out[from..].find("<password>") {
        let open_end = from + i + "<password>".len();
        let Some(j) = out[open_end..].find("</password>") else { break };
        out.replace_range(open_end..open_end + j, "***");
        from = open_end + 3;
    }
    out
}

/// The CSTP CONNECT's `Cookie: webvpn=<value>`; never "<elided>".
pub fn capture_cookie(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("Cookie: webvpn=")?;
    let value = rest.split(';').next().unwrap_or("").trim();
    (!value.is_empty() && value != "<elided>").then(|| value.to_string())
}

/// One shell word, for openconnect's --script command line.
pub fn shell_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn is_ipv4(s: &str) -> bool {
    dns_forwarder::ipv4(s).is_some()
}

pub const BUNDLED_DIR: &str = "/Library/PrivilegedHelperTools/AlwaysConnect-openconnect";

/// The bundled openconnect, run as root only when root owns it and
/// nobody else can write it or any ancestor. Symlinks are refused.
pub fn bundled_is_trusted(file: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(file);
    if !path.is_absolute() || !path.starts_with(BUNDLED_DIR) {
        return false;
    }
    for cursor in path.ancestors() {
        let Ok(meta) = std::fs::symlink_metadata(cursor) else { return false };
        if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return false;
        }
    }
    is_executable(file)
}

fn is_executable(path: &str) -> bool {
    std::ffi::CString::new(path).map(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0).unwrap_or(false)
        && Path::new(path).is_file()
}

pub fn route_state_path(support: &Path) -> PathBuf {
    support.join("route-state")
}

/// `<script> <reason>` against this session's route-state journal.
pub fn run_script(reason: &str, script: &str, support: &Path, no_routes: bool, test_active: bool) -> bool {
    let mut cmd = Command::new(script);
    crate::reset_child_signals(&mut cmd);
    cmd.arg(reason).env("ALWAYSCONNECT_ROUTE_STATE_PATH", route_state_path(support)).stdout(Stdio::null());
    if no_routes || test_active {
        cmd.env("ALWAYSCONNECT_NO_ROUTES", "1");
    }
    let success=cmd.status().is_ok_and(|status|status.success());
    if !success { network_guard::log("CLIOrchestrator: route operation did not complete"); }
    success
}

/// "The local network is still held closed": the gate holds a set, or
/// the script changed routes and no restore has undone them yet.
pub fn local_network_held(support: &Path) -> bool {
    network_guard::shared().is_some_and(|g| g.is_holding()) || route_state_path(support).exists() || support.join("direct-routes").exists()
}

/// Daemon start (§26.3): a route-state journal from this boot is
/// restored, one from another boot dropped. "none", "dropped", "restored".
pub fn undo_journal_at_start(script: &str, support: &Path, boot: Option<&str>, test_active: bool) -> String {
    let path = route_state_path(support);
    let Ok(text) = std::fs::read_to_string(&path) else { return "none".into() };
    let recorded = text.lines().find_map(|l| l.strip_prefix("AC_BOOT="));
    let current = matches!((recorded, boot), (Some(r), Some(b)) if r == b);
    if !current {
        let _ = std::fs::remove_file(&path);
        return "dropped".into();
    }
    if run_script("restore", script, support, false, test_active) {"restored".into()} else {"pending".into()}
}

/// Release with no engine running (§20.4, §25.2, §30.1): the gate, the
/// split's routes of the session that left the set, and — only when an
/// own session changed routes — the script's restore.
pub fn restore_without_engine(script: &str, reason: &str, support: &Path, boot: Option<&str>, test_active: bool) {
    if let Some(g) = network_guard::shared() {
        g.release(None, reason);
    }
    let direct = direct_routes::undo_at_start(&support.join("direct-routes"), boot, test_active);
    if direct != "none" {
        network_guard::log(&format!("direct routes on release: {direct}"));
    }
    if route_state_path(support).exists() {
        run_script("restore", script, support, false, test_active);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CookieRecord {
    cookie: String,
    gateway: String,
    server_fingerprint: String,
    saved_at_unix: i64,
}

fn cookie_load(path: &str, gateway: &str) -> Option<String> {
    let record: CookieRecord = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    (record.gateway == gateway && !record.cookie.is_empty()).then_some(record.cookie)
}

fn cookie_save(path: &str, cookie: &str, gateway: &str) {
    use std::os::unix::fs::PermissionsExt;
    let record = CookieRecord {
        cookie: cookie.to_string(),
        gateway: gateway.to_string(),
        server_fingerprint: String::new(),
        saved_at_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
    };
    let p = Path::new(path);
    let ok = (|| -> std::io::Result<()> {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&record)?)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, p)
    })();
    if ok.is_err() {
        network_guard::log("CookieStore: save failed, continuing without cache");
    }
}

fn jitter() -> f64 {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    0.8 + (n % 1_000_000) as f64 / 1_000_000.0 * 0.4
}

fn state_code(s: SessionStatus) -> i32 {
    match s {
        SessionStatus::Disconnected => 0,
        SessionStatus::Connecting => 1,
        SessionStatus::Authenticating => 2,
        SessionStatus::AwaitingApproval => 3,
        SessionStatus::Connected => 4,
        SessionStatus::Reconnecting => 5,
    }
}

// MARK: - The engine

/// Read by the service between events (diagnostics, the panel).
#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub tunnel_if: Option<String>,
    pub gateway_ips: Vec<String>,
    pub physical_if: String,
    pub tunnel_dns: Vec<String>,
    pub episode_retries: u32,
    pub last_error: Option<String>,
    pub pf_error: Option<String>,
    pub last_terminal: Option<i32>,
    pub split_running: bool,
    pub split_hits: Vec<String>,
    pub split_addresses: usize,
    pub direct_networks: Vec<String>,
    pub tail: Vec<String>,
}

struct Child {
    pid: i32,
    generation: u64,
    alive: Arc<AtomicBool>,
}

#[derive(Clone)]
struct TunnelLease { name: String, index: u32, generation: u64 }
const TUNNEL_RECONFIRM_ERROR: &str = "VPN 接口已变化，请重新连接；断线保护保持";
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

struct Core {
    config: Config,
    driver: SessionDriver,
    child: Option<Child>,
    generation: u64,
    stop_requested: bool,
    hook_fired: bool,
    saw_login_failed: bool,
    fed: Credential,
    cookie_fallback_used: bool,
    attempts: u32,
    tokens: [u64; 4],
    manual_flag_installed: bool,
    out_buffer: Vec<u8>,
    err_buffer: Vec<u8>,
    tail: Vec<String>,
    credential_sent_at: Option<Instant>,
    last_credential_wait: f64,
    unanswered_since: Option<Instant>,
    expired_approvals: usize,
    /// This password attempt was held for the phone (the gateway took
    /// the password: it was right).
    approval_waited: bool,
    /// Quick confirmation failures in a row (§43).
    declined_approvals: usize,
    in_drop_episode: bool,
    episode_retries: u32,
    last_terminal: Option<Terminal>,
    last_error: Option<String>,
    pf_error: Option<String>,
    forwarder: Option<Forwarder>,
    physical_gateway: Option<String>,
    local_dns: Vec<String>,
    routed_networks: HashSet<String>,
    split_hits: Vec<String>,
    split_addresses: HashSet<String>,
    last_pf: Option<(String, Vec<String>)>,
    last_allow_direct_egress: bool,
    tunnel_dns: Vec<String>,
    tunnel_if: Option<String>,
    tunnel_lease: Option<TunnelLease>,
    split_policy: crate::split_policy::SplitPolicy,
    split_needs_sync: bool,
    tunnel_retrying: bool,
    gateway_lan_excludes: Vec<String>,
    watching: bool,
    /// Writing to this ends the network watcher's thread.
    watch_stop: Option<std::os::fd::OwnedFd>,
    pending_stop_notices: usize,
    finished: bool,
    released: bool,
}

pub struct Shared {
    core: Mutex<Core>,
    hooks: Hooks,
    guard: Arc<Guard>,
    routes: DirectRoutes,
    holder: String,
    tx: Mutex<Sender<Event>>,
    /// The running child, for kill_child from another thread.
    child_pid: Mutex<Option<(i32, Arc<AtomicBool>)>>,
    timer_seq: AtomicU64,
    /// What the service reads, published before every callback: the
    /// callbacks may read it, and must never wait for the core.
    info: Mutex<Info>,
}

pub struct Engine {
    shared: Arc<Shared>,
}

impl Engine {
    pub fn new(config: Config, hooks: Hooks, guard: Arc<Guard>) -> Engine {
        let support = PathBuf::from(&config.support_dir);
        let routes = DirectRoutes::new(support.join("direct-routes"), config.boot_session.clone(), config.no_routes);
        let holder = guard.new_own_holder();
        let (tx, rx) = mpsc::channel();
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(1);
        let shared = Arc::new(Shared {
            core: Mutex::new(Core {
                driver: SessionDriver::new(seed),
                config,
                child: None,
                generation: 0,
                stop_requested: false,
                hook_fired: false,
                saw_login_failed: false,
                fed: Credential::Password,
                cookie_fallback_used: false,
                attempts: 0,
                tokens: [0; 4],
                manual_flag_installed: false,
                out_buffer: Vec::new(),
                err_buffer: Vec::new(),
                tail: Vec::new(),
                credential_sent_at: None,
                last_credential_wait: 0.0,
                unanswered_since: None,
                expired_approvals: 0,
                approval_waited: false,
                declined_approvals: 0,
                in_drop_episode: false,
                episode_retries: 0,
                last_terminal: None,
                last_error: None,
                pf_error: None,
                forwarder: None,
                physical_gateway: None,
                local_dns: Vec::new(),
                routed_networks: HashSet::new(),
                split_hits: Vec::new(),
                split_addresses: HashSet::new(),
                last_pf: None,
                last_allow_direct_egress: false,
                tunnel_dns: Vec::new(),
                tunnel_if: None,
                tunnel_lease: None,
                split_policy: crate::split_policy::SplitPolicy::default(),
                split_needs_sync: false,
                tunnel_retrying: false,
                gateway_lan_excludes: Vec::new(),
                watching: false,
                watch_stop: None,
                pending_stop_notices: 0,
                finished: false,
                released: false,
            }),
            hooks,
            guard,
            routes,
            holder,
            tx: Mutex::new(tx),
            child_pid: Mutex::new(None),
            timer_seq: AtomicU64::new(0),
            info: Mutex::new(Info::default()),
        });
        let s = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ac-engine".into())
            .stack_size(512 * 1024)
            .spawn(move || s.run(rx))
            .expect("engine thread");
        Engine { shared }
    }

    fn send(&self, e: Event) {
        self.shared.send(e);
    }

    pub fn holder(&self) -> String {
        self.shared.holder.clone()
    }
    pub fn start(&self) {
        self.send(Event::Start);
    }
    /// `notify`: call the `stopped` hook once openconnect is gone and
    /// routes and pf are restored. `keep_session`: SIGHUP (no log-off).
    pub fn stop(&self, keep_session: bool, notify: bool) {
        self.send(Event::Stop { keep_session, notify });
    }
    pub fn network_changed(&self) { self.send(Event::NetworkChanged); }

    pub fn update_direct_domains(&self, d: Vec<String>) {
        self.send(Event::DirectDomains(d));
    }
    pub fn update_drop_protection(&self, on: bool) {
        self.send(Event::DropProtection(on));
    }
    pub fn update_allow_networks(&self, n: Vec<String>) {
        self.send(Event::AllowNetworks(n));
    }

    /// Daemon shutdown: the child must not outlive the daemon. SIGHUP (no
    /// log-off, the saved cookie still works), SIGKILL after 2 s.
    pub fn kill_child(&self) {
        let Some((pid, alive)) = self.shared.child_pid.lock().unwrap().clone() else { return };
        if !alive.load(Ordering::SeqCst) {
            return;
        }
        unsafe { libc::kill(pid, libc::SIGHUP) };
        for _ in 0..20 {
            if !alive.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if alive.load(Ordering::SeqCst) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }

    pub fn info(&self) -> Info {
        self.shared.info.lock().unwrap().clone()
    }

    fn check_expected(&self) -> crate::network_check::Expected {
        let c = self.shared.core.lock().unwrap();
        crate::network_check::Expected {
            tunnel: c.last_pf.as_ref().map(|p| p.0.clone()), dns_interface: c.forwarder.as_ref().and_then(|f| f.bound_tunnel_interface()),
            physical: c.config.physical_if.clone(), gateway: c.physical_gateway.clone(),
            vpn_gateways: c.last_pf.as_ref().map(|p| p.1.clone()).unwrap_or_default(),
            dns: c.tunnel_dns.clone(), split: c.forwarder.is_some(), protection: c.config.drop_protection,
            rules: self.shared.guard.expected_rules(), direct: self.shared.guard.direct_addresses(),
            routes: self.shared.routes.addresses(), error: c.pf_error.clone(),
            epoch: c.forwarder.as_ref().map(|f| f.epoch()).unwrap_or(c.generation),
        }
    }
    pub fn run_network_check(&self) -> String {
        self.run_network_check_with(crate::network_check::run)
    }
    fn run_network_check_with(&self, collect: impl FnOnce(&crate::network_check::Expected) -> Vec<crate::network_check::Item>) -> String {
        let expected = self.check_expected();
        let mut items = collect(&expected);
        if expected != self.check_expected() {
            for item in &mut items { item.passed = false; item.informational = false; item.detail = "检查期间连接状态已变化，请重新检查".into(); }
        }
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
    }

    /// The connections page for this session (§28.7).
    pub fn connections_json(&self, fallback_gateways: &[String]) -> String {
        let c = self.shared.core.lock().unwrap();
        let mut gateways = c.last_pf.as_ref().map(|p| p.1.clone()).unwrap_or_default();
        if gateways.is_empty() {
            gateways = fallback_gateways.to_vec();
        }
        let context = crate::connections::Context {
            gateway_ips: gateways,
            direct_addresses: self.shared.routes.addresses(),
            direct_networks: c.direct_networks(),
            names: c.forwarder.as_ref(),
        };
        crate::connections::to_json(&crate::connections::list(&context))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // The engine thread finishes what it was doing (a stop in
        // progress above all) and ends once the session is over.
        self.send(Event::Release);
    }
}

impl Core {
    fn direct_networks(&self) -> Vec<String> {
        let mut out = self.config.allow_networks.clone();
        for n in &self.gateway_lan_excludes {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    fn support(&self) -> PathBuf {
        PathBuf::from(&self.config.support_dir)
    }

    fn manual_flag_path(&self) -> PathBuf {
        self.support().join("manual-disconnect")
    }

    fn child_alive(&self) -> bool {
        self.child.as_ref().is_some_and(|c| c.alive.load(Ordering::SeqCst))
    }
}

impl Shared {
    fn publish(&self, c: &Core) {
        let info = Info {
            tunnel_if: c.last_pf.as_ref().map(|p| p.0.clone()),
            gateway_ips: c.last_pf.as_ref().map(|p| p.1.clone()).unwrap_or_default(),
            physical_if: c.config.physical_if.clone(),
            tunnel_dns: c.tunnel_dns.clone(),
            episode_retries: c.episode_retries,
            last_error: c.last_error.clone(),
            pf_error: c.pf_error.clone(),
            last_terminal: c.last_terminal.map(|t| t as i32),
            split_running: c.forwarder.is_some(),
            split_hits: if c.forwarder.is_some() { c.split_hits.clone() } else { Vec::new() },
            split_addresses: if c.forwarder.is_some() { c.split_addresses.len() } else { 0 },
            direct_networks: c.direct_networks(),
            tail: c.tail.clone(),
        };
        *self.info.lock().unwrap() = info;
    }

    fn send(&self, e: Event) {
        let _ = self.tx.lock().unwrap().send(e);
    }

    fn timer(self: &Arc<Self>, c: &mut Core, timer: Timer, after: f64) {
        let token = self.timer_seq.fetch_add(1, Ordering::SeqCst) + 1;
        c.tokens[timer as usize] = token;
        self.after(after, Event::Fire { timer, token });
    }

    fn cancel(c: &mut Core, timer: Timer) {
        c.tokens[timer as usize] = 0;
    }

    fn after(self: &Arc<Self>, secs: f64, event: Event) {
        let tx = self.tx.lock().unwrap().clone();
        let _ = std::thread::Builder::new().name("ac-engine-timer".into()).stack_size(32 * 1024).spawn(move || {
            std::thread::sleep(Duration::from_secs_f64(secs.max(0.0)));
            let _ = tx.send(event);
        });
    }

    fn run(self: Arc<Self>, rx: Receiver<Event>) {
        while let Ok(event) = rx.recv() {
            let mut c = self.core.lock().unwrap();
            match event {
                Event::Start => self.begin(&mut c),
                Event::Stop { keep_session, notify } => self.stop(&mut c, keep_session, notify),
                Event::Output { generation, stdout, bytes } => {
                    if generation == c.generation && c.child.is_some() {
                        self.consume(&mut c, stdout, &bytes);
                    }
                }
                Event::Exited { generation } => {
                    if generation == c.generation && c.child.is_some() {
                        self.child_exited(&mut c);
                    }
                }
                Event::Fire { timer: Timer::NetWatch, .. } => self.fire(&mut c, Timer::NetWatch),
                Event::Fire { timer, token } => {
                    if c.tokens[timer as usize] == token {
                        c.tokens[timer as usize] = 0;
                        self.fire(&mut c, timer);
                    }
                }
                Event::StopKill { pid, generation } => {
                    if c.child.as_ref().is_some_and(|ch| ch.generation == generation && ch.pid == pid) && c.child_alive() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
                Event::NetworkChanged => {
                    if c.watching && !c.stop_requested { self.refresh_network(&mut c); }
                }
                Event::DirectDomains(d) => {
                    if let Some(f) = &c.forwarder {
                        f.set_rules(&d);
                    }
                    c.split_policy.revalidate(&dns_forwarder::SplitRules::new(&d));
                    self.sync_split_routes(&mut c);
                    c.config.direct_domains = Some(d);
                }
                Event::DropProtection(on) => self.update_drop_protection(&mut c, on),
                Event::AllowNetworks(n) => {
                    c.config.allow_networks = n.iter().map(|x| x.trim().to_string()).filter(|x| crate::kill_switch::is_cidr(x)).collect();
                    self.sync_split_routes(&mut c);
                    self.route_networks_direct(&mut c);
                    if let Some((tun, gws)) = c.last_pf.clone() {
                        let allow = c.last_allow_direct_egress;
                        self.load_pf(&mut c, Some(tun), gws, allow);
                    }
                }
                Event::DnsAnswer(answer, reply) => {
                    let current = !c.stop_requested && c.forwarder.as_ref().is_some_and(|f| f.is_current(answer.epoch));
                    let committed = if current {
                        let changed = c.split_policy.observe(answer.name, &answer.addresses, &answer.direct);
                        let ok = if changed || c.split_needs_sync { self.sync_split_routes(&mut c) } else { true };
                        if let Some(entry) = answer.entry {
                            c.split_hits.retain(|e| *e != entry);
                            c.split_hits.insert(0, entry);
                            c.split_hits.truncate(20);
                        }
                        ok
                    } else { false };
                    let _ = reply.send(committed);
                }
                Event::Respawn => {
                    if !c.stop_requested {
                        self.spawn_next(&mut c);
                    }
                }
                Event::Release => c.released = true,
            }
            self.publish(&c);
            if c.released && c.finished && !c.child_alive() {
                return;
            }
        }
    }

    fn report(&self, c: &Core, detail: &str) {
        let mut state = c.driver.state;
        if (c.tunnel_retrying || (c.hook_fired && c.forwarder.is_some() && c.tunnel_if.is_none())) && state == SessionStatus::Connected {
            state = SessionStatus::Reconnecting;
        }
        // Re-authenticating inside a drop episode is, to the user, still
        // "dropped, network blocked, reconnecting"; approval waits stay
        // visible as such (they need the phone).
        if c.in_drop_episode && matches!(state, SessionStatus::Connecting | SessionStatus::Authenticating) {
            state = SessionStatus::Reconnecting;
        }
        self.publish(c);
        (self.hooks.state)(state_code(state), detail);
    }

    // MARK: Lifecycle

    fn begin(self: &Arc<Self>, c: &mut Core) {
        c.driver.start();
        self.take_over_held_set(c);
        self.report(c, "starting");
        if Self::executable(c).is_none() {
            self.spawn_next(c);
            return;
        }
        self.start_forwarder(c);
        self.watch_physical_network(c);
        self.spawn_next(c);
    }

    /// A set already held when this engine starts (§30.1) is taken over
    /// at once, blocking as before, with this session's gateway let
    /// through. With drop protection off the set goes.
    fn take_over_held_set(self: &Arc<Self>, c: &mut Core) {
        let Some((held_by, mut inputs)) = self.guard.held() else { return };
        if held_by == CISCO_HOLDER {
            return;
        }
        if !c.config.drop_protection {
            self.guard.release(None, network_guard::reason::USER);
            network_guard::log(&format!("engine start: 断线保护 off, released the set left by {held_by}"));
            return;
        }
        if let Some(relay) = &c.config.relay {
            inputs.gateway_ips = vec![relay.gateway_ip.clone()];
        }
        if !c.config.allow_networks.is_empty() {
            inputs.allow_networks = c.direct_networks();
        }
        if let Some(problem) = self.guard.apply(&self.holder, false, &inputs) {
            c.pf_error = Some(problem);
            network_guard::log("engine start: taking over the held set failed");
            return;
        }
        c.last_pf = Some((inputs.tunnel_if.clone(), inputs.gateway_ips.clone()));
        c.last_allow_direct_egress = false;
        c.in_drop_episode = true;
        network_guard::log(&format!("engine start: took over the set held by {held_by}"));
    }

    fn stop(self: &Arc<Self>, c: &mut Core, keep_session: bool, notify: bool) {
        if notify {
            c.pending_stop_notices += 1;
        }
        if c.stop_requested {
            return;
        }
        c.stop_requested = true;
        Self::cancel(c, Timer::ApprovalTimeout);
        Self::cancel(c, Timer::ForceKill);
        c.driver.on_manual_disconnect();
        self.report(c, "manual disconnect");
        // Flag file first: the script's disconnect path reads it.
        self.install_manual_flag(c);
        if c.child_alive() {
            let child = c.child.as_ref().unwrap();
            let (pid, generation) = (child.pid, child.generation);
            unsafe { libc::kill(pid, if keep_session { libc::SIGHUP } else { libc::SIGTERM }) };
            // openconnect logs out on SIGTERM and can hang there when the
            // gateway (or the App's relay) is already gone.
            self.after(8.0, Event::StopKill { pid, generation });
        } else {
            self.finish_manual_stop(c);
        }
    }

    fn finish_terminal(&self, c: &mut Core, reason: Terminal, detail: &str) {
        c.last_terminal = Some(reason);
        c.in_drop_episode = false;
        self.report(c, detail);
        self.publish(c);
        (self.hooks.terminal)(reason as i32);
        c.finished = true;
    }

    // MARK: Split (§26.5)

    fn start_forwarder(self: &Arc<Self>, c: &mut Core) {
        let Some(domains) = c.config.direct_domains.clone() else { return };
        let port = if c.config.test_active { 15353 } else { 53 };
        let weak = Arc::downgrade(self);
        let hook: dns_forwarder::AnswerHook = Box::new(move |answer| {
            let Some(me) = weak.upgrade() else { return false };
            let (tx, rx) = std::sync::mpsc::channel();
            me.send(Event::DnsAnswer(answer, tx));
            // Never acquire the engine lock from a DNS worker. Configuration
            // and route/pf commits share the engine queue, so old replies cannot
            // re-add a bypass after its rule or session was removed.
            rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false)
        });
        let forwarder = Forwarder::with_answer_hook(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_secs(2), domains,
            Upstreams { tunnel: Vec::new(), local: Vec::new(), physical_if: None, tunnel_if: None }, None, Some(hook));
        match forwarder.start() {
            Ok(()) => c.forwarder = Some(forwarder),
            Err(_) => {
                let e = "本机 53 端口被其他程序占用，暂时不能按域名分流（全部走 VPN）".to_string();
                c.last_error = Some(e.clone());
                self.report(c, &e);
            }
        }
    }

    fn sync_split_routes(&self, c: &mut Core) -> bool {
        c.split_needs_sync = true;
        let mut desired = c.split_policy.direct();
        if !desired.is_empty() {
            let Some(own)=direct_routes::assigned_ipv4() else {
                let error="本机地址未确认，直连例外未更新；可使用恢复网络";
                c.pf_error=Some(error.into()); self.report(c,error); return false;
            };
            desired.retain(|value|value.parse().is_ok_and(|ip|direct_routes::ordinary_unicast(ip)&&!own.contains(&ip)));
        }
        let actual: HashSet<_> = self.guard.direct_addresses().into_iter().collect();
        let gone: Vec<_> = actual.difference(&desired).cloned().collect();
        // Close the firewall exception before removing its route; never grant
        // an exception until the corresponding route is installed.
        let firewall_ok = self.guard.remove_direct(&gone);
        let gateways: HashSet<_> = c.last_pf.as_ref().map(|p| p.1.iter().cloned().collect()).unwrap_or_default();
        let lans = direct_routes::attached_networks();
        let explicit = dns_forwarder::SplitRules::new(&c.direct_networks().iter().map(|n| format!("ipcidr:{n}")).collect::<Vec<_>>());
        let routable: HashSet<_> = desired.iter().filter(|ip| !gateways.contains(*ip))
            .filter(|ip| dns_forwarder::ipv4(ip).is_some_and(|v| !lans.iter().any(|l| l.0 <= v && v <= l.1)))
            .filter(|ip| !ip.parse().is_ok_and(|ip| explicit.contains(ip)))
            .cloned().collect();
        let routed: HashSet<_> = self.routes.addresses().into_iter().filter(|e| !direct_routes::is_network(e)).collect();
        let removed: Vec<_> = routed.difference(&routable).cloned().collect();
        let routes_ok = self.routes.remove(&removed);
        if !firewall_ok || !routes_ok {
            let e = "直连例外清理失败，网络保护状态未确认；可使用恢复网络".to_string();
            c.pf_error = Some(e.clone()); self.report(c, &e);
            return false;
        }
        let new: Vec<_> = routable.difference(&routed).cloned().collect();
        if !new.is_empty() {
            let Some(gateway) = &c.physical_gateway else { return false };
            if !self.routes.add(&new, gateway) {
                let error="直连路由安装失败，网络保护状态未确认；可使用恢复网络";
                c.pf_error=Some(error.into()); self.report(c,error); return false;
            }
        }
        let fresh: Vec<_> = desired.difference(&actual).cloned().collect();
        if !self.guard.add_direct(&fresh) { return false; }
        c.split_addresses = desired;
        c.split_needs_sync = false;
        true
    }

    fn update_forwarder(&self, c: &Core) {
        if let Some(f) = &c.forwarder {
            let index=c.tunnel_lease.as_ref().filter(|lease|c.tunnel_if.as_ref()==Some(&lease.name)&&lease.generation==c.generation).map(|lease|lease.index);
            f.set_pinned_upstreams(Upstreams {
                tunnel: c.tunnel_dns.clone(), local: c.local_dns.clone(),
                physical_if: if c.config.no_routes { None } else { Some(c.config.physical_if.clone()) },
                tunnel_if: c.tunnel_if.clone(),
            },index);
        }
    }

    fn update_drop_protection(self: &Arc<Self>, c: &mut Core, on: bool) {
        if c.config.drop_protection == on {
            return;
        }
        c.config.drop_protection = on;
        if on {
            if let Some((tun, gws)) = c.last_pf.clone() {
                if !c.stop_requested {
                    let allow = if c.in_drop_episode { false } else { c.last_allow_direct_egress };
                    self.load_pf(c, Some(tun), gws, allow);
                }
            }
        } else {
            self.guard.release(Some(&self.holder), network_guard::reason::USER);
            c.split_needs_sync = true;
            c.pf_error = None;
            if c.in_drop_episode && c.child.is_none() {
                self.give_back_local_network(c);
            }
        }
    }

    /// Drop protection off, tunnel down (§26.19): no pf set, the saved
    /// default route and local DNS back.
    fn give_back_local_network(&self, c: &Core) {
        self.guard.release(Some(&self.holder), network_guard::reason::USER);
        if route_state_path(&c.support()).exists() {
            run_script("restore", &c.config.script_path, &c.support(), c.config.no_routes, c.config.test_active);
        }
    }

    /// The direct networks (the App's list, the local network, the
    /// gateway's own private excludes) go via the physical router
    /// whenever the session knows it — the domain split's forwarder
    /// or not (§40.1): a split that could not start must not send the
    /// modem at 192.168.100.1 into the tunnel.
    fn route_networks_direct(&self, c: &mut Core) {
        let Some(gateway) = c.physical_gateway.clone() else { return };
        let wanted: HashSet<String> =
            direct_routes::networks_to_route(&c.direct_networks(), &direct_routes::attached_networks()).into_iter().collect();
        let gone: Vec<String> = c.routed_networks.difference(&wanted).cloned().collect();
        let new: Vec<String> = wanted.difference(&c.routed_networks).cloned().collect();
        self.routes.remove(&gone);
        self.routes.add(&new, &gateway);
        c.routed_networks = wanted;
    }

    /// When the Mac's physical network changes, the session follows it,
    /// tunnel up or not (§28.1, §30.2). The kernel says when routes or
    /// addresses change (§32.15: no 5 s polling); a check every 60 s
    /// remains as the fallback.
    fn watch_physical_network(self: &Arc<Self>, c: &mut Core) {
        if c.config.no_routes {
            return;
        }
        c.watching = true;
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return;
        }
        use std::os::fd::FromRawFd;
        let (read_end, write_end) = unsafe {
            (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1]))
        };
        c.watch_stop = Some(write_end);
        let weak = Arc::downgrade(self);
        let _ = std::thread::Builder::new().name("ac-engine-netwatch".into()).stack_size(64 * 1024).spawn(move || {
            let watch = crate::route_watch::RouteWatch::new();
            loop {
                let wake = if let Some(watch) = &watch {
                    watch.wait(Duration::from_secs(60), Duration::from_millis(500), Some(read_end.as_raw_fd()))
                } else {
                    // A failed routing socket must not remove the fallback.
                    let mut stop = libc::pollfd { fd: read_end.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    unsafe { libc::poll(&mut stop, 1, 60_000) };
                    if stop.revents != 0 { crate::route_watch::Wake::Stopped } else { crate::route_watch::Wake::Timeout }
                };
                match wake {
                    crate::route_watch::Wake::Stopped => return,
                    _ => match weak.upgrade() {
                        Some(me) => me.send(Event::Fire { timer: Timer::NetWatch, token: u64::MAX }),
                        None => return,
                    },
                }
            }
        });
    }

    fn stop_split(&self, c: &mut Core) {
        c.watching = false;
        if let Some(stop) = c.watch_stop.take() {
            unsafe { libc::write(stop.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        }
        c.routed_networks.clear();
        if let Some(f) = c.forwarder.take() {
            f.stop();
        }
        if !self.routes.remove_all() {
            let error="直连路由清理未确认；可重试恢复网络";
            c.pf_error=Some(error.into());self.report(c,error);
        }
        c.split_hits.clear();
        c.split_addresses.clear();
        c.tunnel_lease = None;
        c.split_policy = crate::split_policy::SplitPolicy::default();
        c.split_needs_sync = false;
    }

    // MARK: Timers

    fn fire(self: &Arc<Self>, c: &mut Core, timer: Timer) {
        match timer {
            Timer::ForceKill => {
                if c.child_alive() {
                    unsafe { libc::kill(c.child.as_ref().unwrap().pid, libc::SIGTERM) };
                }
            }
            Timer::ApprovalProbe => {
                // Still no answer to the password: the gateway waits for
                // the phone (§30.9).
                if c.credential_sent_at.is_some() && !c.stop_requested && c.child_alive() {
                    self.handle_approval_signal(c);
                }
            }
            Timer::ApprovalTimeout => {
                // openconnect still waits: the request is the gateway's to
                // expire; re-initiating here started a second login.
                if c.child_alive() {
                    return;
                }
                if let DriverAction::Reauthenticate { delay } = c.driver.on_approval_timeout() {
                    self.respawn_after(delay.as_secs_f64());
                }
            }
            Timer::NetWatch => {
                if !c.watching || c.stop_requested {
                    return;
                }
                self.refresh_network(c);
            }
        }
    }

    /// A respawn that no-ops when a manual stop landed first.
    fn respawn_after(self: &Arc<Self>, delay: f64) {
        let weak = Arc::downgrade(self);
        let _ = std::thread::Builder::new().stack_size(32 * 1024).spawn(move || {
            std::thread::sleep(Duration::from_secs_f64(delay.max(0.0)));
            if let Some(me) = weak.upgrade() {
                me.send(Event::Respawn);
            }
        });
    }

    // MARK: Spawn

    fn executable(c: &Core) -> Option<String> {
        if let Some(p) = c.config.openconnect_path.as_ref().filter(|p| !p.is_empty()) {
            return Some(p.clone());
        }
        if c.config.test_active {
            return Some(c.config.test_openconnect.clone().unwrap_or_else(|| "/usr/bin/false".into()));
        }
        Self::default_executable(unsafe { libc::geteuid() } == 0)
    }

    fn default_executable(root: bool) -> Option<String> {
        let bundled = format!("{BUNDLED_DIR}/bin/openconnect");
        if bundled_is_trusted(&bundled) {
            return Some(bundled);
        }
        // The daemon never executes a user's Homebrew or PATH entry.
        if root { return None; }
        for candidate in ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect", "/usr/sbin/openconnect", "/usr/bin/openconnect"] {
            if is_executable(candidate) {
                return Some(candidate.into());
            }
        }
        Some("/usr/bin/env".into())
    }

    fn spawn_next(self: &Arc<Self>, c: &mut Core) {
        if let Some(max) = c.config.max_attempts {
            if c.attempts >= max {
                self.finish_terminal(c, Terminal::AttemptsExhausted, "attempt limit reached");
                return;
            }
        }
        c.attempts += 1;
        c.hook_fired = false;
        c.tunnel_retrying = false;
        c.saw_login_failed = false;
        c.tunnel_dns.clear();
        c.tunnel_lease = None;
        c.tunnel_if = None;
        self.update_forwarder(c);
        if c.in_drop_episode {
            c.episode_retries += 1;
        }
        let cookie = cookie_load(&c.config.cookie_store_path, &c.config.server);
        let Some(executable) = Self::executable(c) else {
            let detail = "内置连接组件缺失或不可信，请重新安装后台服务";
            self.stop_split(c);
            c.last_error = Some(detail.into());
            c.driver.on_manual_disconnect();
            self.finish_terminal(c, Terminal::ComponentMissing, detail);
            return;
        };
        let mut args: Vec<String> = Vec::new();
        if executable == "/usr/bin/env" {
            args.push("openconnect".into());
        }
        args.push(format!("--server={}", c.config.server));
        if !c.config.group.is_empty() {
            args.push(format!("--authgroup={}", c.config.group));
        }
        args.push(format!("--user={}", c.config.username));
        if let Some(cafile) = c.config.cafile.as_ref().filter(|f| !f.is_empty()) {
            args.push(format!("--cafile={cafile}"));
        } else if c.config.relay.is_none() && !c.config.test_active {
            // Straight to the gateway: the bundled GnuTLS has no trust
            // store of its own on other Macs (§27.3).
            if let Some(roots) = (self.hooks.system_roots)() {
                args.push(format!("--cafile={roots}"));
            }
        }
        if let Some(relay) = &c.config.relay {
            args.extend(relay.arguments.iter().cloned());
        }
        let mut credential = match cookie {
            Some(cookie) => {
                args.push("--cookie-on-stdin".into());
                c.fed = Credential::Cookie;
                cookie
            }
            None => {
                args.push("--passwd-on-stdin".into());
                c.fed = Credential::Password;
                c.config.password.clone()
            }
        };
        // openconnect hands --script to /bin/sh -c as a command line, and
        // the installed path has a space ("Application Support").
        args.push(format!("--script={}", shell_quoted(&c.config.script_path)));
        args.push("--dump-http-traffic".into());

        let support = c.support();
        let mut cmd = Command::new(&executable);
        crate::reset_child_signals(&mut cmd);
        cmd.args(&args)
            .env_remove("ALWAYSCONNECT_MANUAL_DISCONNECT")
            // The script's disconnect branch reads a FILE (stop() creates
            // it before terminating the child); a stale one is removed now.
            .env("ALWAYSCONNECT_MANUAL_FLAG_PATH", c.manual_flag_path())
            .env("ALWAYSCONNECT_ROUTE_STATE_PATH", route_state_path(&support))
            .env("ALWAYSCONNECT_BOOT_SESSION", &c.config.boot_session)
            .env_remove("ALWAYSCONNECT_GATEWAY_IP")
            .env_remove("ALWAYSCONNECT_DNS_FIRST")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.remove_manual_flag(c);
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::create_dir_all(&support);
            let _ = std::fs::set_permissions(&support, std::fs::Permissions::from_mode(0o700));
        }
        if c.config.no_routes {
            cmd.env("ALWAYSCONNECT_NO_ROUTES", "1");
        }
        if let Some(relay) = &c.config.relay {
            cmd.env("ALWAYSCONNECT_GATEWAY_IP", &relay.gateway_ip);
        }
        if c.forwarder.is_some() {
            cmd.env("ALWAYSCONNECT_DNS_FIRST", "127.0.0.1");
        }
        c.driver.on_authenticated();
        let label = if c.fed == Credential::Cookie { "cookie" } else { "password" };
        self.report(c, &format!("spawning openconnect (attempt {}, credential {label})", c.attempts));
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                wipe(&mut credential);
                self.handle_post_auth_failure(c, &format!("spawn failed: {e}"));
                return;
            }
        };
        c.generation += 1;
        let generation = c.generation;
        let alive = Arc::new(AtomicBool::new(true));
        let pid = child.id() as i32;
        c.child = Some(Child { pid, generation, alive: Arc::clone(&alive) });
        *self.child_pid.lock().unwrap() = Some((pid, Arc::clone(&alive)));
        c.out_buffer.clear();
        c.err_buffer.clear();
        // Feed the credential once, then close stdin at once: a second
        // read (a re-prompt) sees EOF and the child exits instead of
        // hanging (measured 2026-10-31).
        if let Some(mut stdin) = child.stdin.take() {
            // macOS only: elsewhere the Rust runtime already ignores SIGPIPE.
            #[cfg(target_os = "macos")]
            unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) };
            credential.push('\n');
            let _ = stdin.write_all(credential.as_bytes());
        }
        wipe(&mut credential);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        for (stream, is_stdout) in [
            (child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), true),
            (child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>), false),
        ] {
            let Some(mut stream) = stream else { let _ = done_tx.send(()); continue };
            let me = Arc::downgrade(self);
            let done = done_tx.clone();
            let _ = std::thread::Builder::new().name("ac-engine-pipe".into()).stack_size(64 * 1024).spawn(move || {
                let mut buffer = [0u8; 8192];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let Some(me) = me.upgrade() else { break };
                            me.send(Event::Output { generation, stdout: is_stdout, bytes: buffer[..n].to_vec() });
                        }
                    }
                }
                let _ = done.send(());
            });
        }
        drop(done_tx);
        let me = Arc::downgrade(self);
        let _ = std::thread::Builder::new().name("ac-engine-wait".into()).stack_size(64 * 1024).spawn(move || {
            let _ = child.wait();
            alive.store(false, Ordering::SeqCst);
            // What the pipes still hold first — but never wait on a write
            // end something else inherited (a hang is worse than a lost
            // straggler line; the deciding lines come well before exit).
            let deadline = Instant::now() + Duration::from_millis(500);
            for _ in 0..2 {
                let left = deadline.saturating_duration_since(Instant::now());
                if done_rx.recv_timeout(left).is_err() {
                    break;
                }
            }
            if let Some(me) = me.upgrade() {
                me.send(Event::Exited { generation });
            }
        });
    }

    // MARK: Output

    fn consume(self: &Arc<Self>, c: &mut Core, stdout: bool, bytes: &[u8]) {
        let buffer = if stdout { &mut c.out_buffer } else { &mut c.err_buffer };
        buffer.extend_from_slice(bytes);
        let mut lines = Vec::new();
        while let Some(i) = buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=i).collect();
            lines.push(String::from_utf8_lossy(&line).trim_matches(|ch| ch == '\n' || ch == '\r').to_string());
        }
        for line in lines {
            self.handle_line(c, &line, stdout);
        }
    }

    fn handle_line(self: &Arc<Self>, c: &mut Core, line: &str, stdout: bool) {
        let redacted = redact(line);
        if c.config.debug_child_output {
            let _ = std::io::stderr().write_all(format!("CHILD {}: {}\n", if stdout { "out" } else { "err" }, redacted).as_bytes());
        }
        c.tail.push(redacted);
        if c.tail.len() > 40 {
            let extra = c.tail.len() - 40;
            c.tail.drain(..extra);
        }
        if let Some(payload) = line.strip_prefix("AC_HOOK ") {
            self.handle_hook(c, payload);
            return;
        }
        if let Some(cookie) = capture_cookie(line) {
            cookie_save(&c.config.cookie_store_path, &cookie, &c.config.server);
            return;
        }
        if line.starts_with("> ") && line.contains("<password>") {
            self.credential_sent(c);
        } else if line.starts_with("Got HTTP response:") && c.credential_sent_at.is_some() {
            self.credential_answered(c);
        }
        if !stdout && line.contains("Login failed.") {
            // The child re-prompts after this line; stdin is closed, so
            // it exits; a terminate 3 s later is the backstop.
            c.saw_login_failed = true;
            self.timer(c, Timer::ForceKill, 3.0);
        }
    }

    fn handle_hook(self: &Arc<Self>, c: &mut Core, payload: &str) {
        let mut parts = payload.split(' ').filter(|p| !p.is_empty());
        let Some(event) = parts.next() else { return };
        let pairs: Vec<(&str, &str)> = parts.filter_map(|p| p.split_once('=')).collect();
        match event {
            "connect" => {
                c.tunnel_dns.clear();
                let mut tun = None;
                let mut gateway = None;
                for (k, v) in &pairs {
                    match *k {
                        "tun" => tun = Some(v.to_string()),
                        "gateway" => gateway = Some(v.to_string()),
                        "phys" if !v.is_empty() => c.config.physical_if = v.to_string(),
                        "dns" => c.tunnel_dns = v.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect(),
                        "lanex" => {
                            c.gateway_lan_excludes =
                                v.split(',').filter(|x| crate::kill_switch::is_cidr(x)).map(str::to_string).collect()
                        }
                        "physgw" if is_ipv4(v) => {
                            let previous = c.physical_gateway.replace(v.to_string());
                            // A fresh connect on a different network: this
                            // session's routes still point at the old router.
                            if previous.is_some_and(|p| p != *v) {
                                self.routes.repoint(v);
                            }
                        }
                        _ => {}
                    }
                }
                c.hook_fired = true;
                c.tunnel_retrying = false;
                if c.forwarder.is_some() || c.config.relay.is_some() {
                    c.local_dns = if c.config.no_routes { Vec::new() } else { (self.hooks.local_dns)(&c.config.physical_if) };
                }
                c.tunnel_if = tun.clone();
                self.remember_tunnel(c);
                self.update_forwarder(c);
                Self::cancel(c, Timer::ApprovalTimeout);
                c.unanswered_since = None;
                c.expired_approvals = 0;
                c.declined_approvals = 0;
                c.episode_retries = 0;
                c.in_drop_episode = false;
                c.driver.on_auth_outcome(AuthOutcome::Success);
                self.report(c, "tunnel up");
                let allow = c.config.allow_direct_egress_when_connected;
                self.load_pf(c, tun, gateway.into_iter().collect(), allow);
                self.route_networks_direct(c);
            }
            "attempt-reconnect" => {
                // openconnect is retrying inside the same process (§28.1).
                c.tunnel_retrying = true;
                c.tunnel_if = None;
                self.update_forwarder(c);
                let phys = pairs.iter().find(|(k, v)| *k == "phys" && !v.is_empty()).map(|(_, v)| v.to_string());
                let gw = pairs.iter().find(|(k, v)| *k == "physgw" && is_ipv4(v)).map(|(_, v)| v.to_string());
                if let (Some(gw), Some(phys)) = (gw, phys) {
                    if Some(&gw) != c.physical_gateway.as_ref() || phys != c.config.physical_if {
                        self.follow_network(c, &gw, &phys, false);
                    }
                }
                if !c.config.no_routes { self.refresh_network(c); }
                self.report(c, "隧道断了，正在重连…");
            }
            "reconnect" => {
                c.tunnel_retrying = false;
                if !c.config.no_routes { self.refresh_network(c); }
                c.tunnel_if = pairs.iter().find(|(k,v)| *k == "tun" && !v.is_empty()).map(|(_,v)| v.to_string())
                    .or_else(|| c.last_pf.as_ref().map(|p| p.0.clone()));
                if let Some((_, dns)) = pairs.iter().find(|(k,_)| *k == "dns") {
                    c.tunnel_dns = dns.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect();
                }
                self.remember_tunnel(c);
                self.update_forwarder(c);
                if let Some((_, gateways)) = c.last_pf.clone() {
                    let allow = c.last_allow_direct_egress;
                    self.load_pf(c, c.tunnel_if.clone(), gateways, allow);
                }
                self.report(c, "tunnel up");
            }
            _ => {}
        }
    }

    // MARK: Approval wait (§30.9)

    fn credential_sent(self: &Arc<Self>, c: &mut Core) {
        c.credential_sent_at = Some(Instant::now());
        c.last_credential_wait = 0.0;
        c.approval_waited = false;
        let quiet = c.config.approval_quiet_secs;
        self.timer(c, Timer::ApprovalProbe, quiet);
    }

    fn credential_answered(self: &Arc<Self>, c: &mut Core) {
        if let Some(sent) = c.credential_sent_at.take() {
            c.last_credential_wait = sent.elapsed().as_secs_f64();
        }
        Self::cancel(c, Timer::ApprovalProbe);
        self.leave_approval_wait(c, "approval answered");
    }

    /// Back to Authenticating, so the outcome that follows is classified
    /// as usual.
    fn leave_approval_wait(&self, c: &mut Core, detail: &str) {
        if c.driver.state != SessionStatus::AwaitingApproval {
            return;
        }
        Self::cancel(c, Timer::ApprovalTimeout);
        c.driver.on_approval_timeout();
        self.report(c, detail);
    }

    fn handle_approval_signal(self: &Arc<Self>, c: &mut Core) {
        if c.driver.state != SessionStatus::Authenticating {
            return;
        }
        if let DriverAction::WaitApproval { timeout } = c.driver.on_auth_outcome(AuthOutcome::NeedsApproval) {
            c.approval_waited = true;
            self.report(c, "awaiting approval");
            self.timer(c, Timer::ApprovalTimeout, timeout.as_secs_f64());
        }
    }

    // MARK: Child exit

    fn child_exited(self: &Arc<Self>, c: &mut Core) {
        // Partial trailing lines.
        for stdout in [true, false] {
            let rest = std::mem::take(if stdout { &mut c.out_buffer } else { &mut c.err_buffer });
            if !rest.is_empty() {
                let line = String::from_utf8_lossy(&rest).trim_matches(|ch| ch == '\n' || ch == '\r').to_string();
                self.handle_line(c, &line, stdout);
            }
        }
        c.child = None;
        Self::cancel(c, Timer::ForceKill);
        Self::cancel(c, Timer::ApprovalProbe);
        if let Some(sent) = c.credential_sent_at.take() {
            c.last_credential_wait = sent.elapsed().as_secs_f64();
        }
        self.leave_approval_wait(c, "openconnect exited");
        if c.stop_requested {
            self.finish_manual_stop(c);
            return;
        }
        if c.saw_login_failed && c.last_credential_wait >= c.config.approval_expiry_minimum {
            // The password waited for the phone that long, then failed:
            // the approval expired. Ask again later instead of stopping.
            self.reinitiate_expired_approval(c);
            return;
        }
        if c.saw_login_failed && c.approval_waited {
            // The gateway held the password for the phone, so the password
            // was right; the confirmation failed before it could expire —
            // declined, or the phone off the network (a router restart
            // takes both down, §43). Ask once more, then stop: never a
            // stream of pushes after a real "decline".
            c.saw_login_failed = false;
            c.approval_waited = false;
            if c.declined_approvals == 0 {
                c.declined_approvals += 1;
                let delay = c.config.push_backoff.first().copied().unwrap_or(DECLINED_RETRY) * jitter();
                self.report(c, &format!("手机上的登录确认没有通过，{} 秒后重新发起", delay.round() as i64));
                self.respawn_after(delay);
                return;
            }
            c.driver.on_auth_outcome(AuthOutcome::Rejected);
            let e = "手机上的登录确认没有通过，已停止重连。确认手机能上网后点「重新连接」".to_string();
            c.last_error = Some(e.clone());
            self.report(c, &e);
            self.finish_terminal(c, Terminal::ApprovalDeclined, &e);
            return;
        }
        if c.saw_login_failed {
            // Rejection: stop, never retry (anti-lockout).
            c.driver.on_auth_outcome(AuthOutcome::Rejected);
            let e = "账号或密码被拒绝，请检查凭据".to_string();
            c.last_error = Some(e.clone());
            self.report(c, &e);
            self.finish_terminal(c, Terminal::AuthFailure, &e);
            return;
        }
        if c.fed == Credential::Cookie && !c.hook_fired {
            // Cookie refused before any tunnel: drop it, password once.
            let _ = std::fs::remove_file(&c.config.cookie_store_path);
            if !c.cookie_fallback_used {
                c.cookie_fallback_used = true;
                self.spawn_next(c);
                return;
            }
        }
        c.tunnel_if = None;
        self.update_forwarder(c);
        if c.hook_fired {
            if let DriverAction::Reauthenticate { delay } = c.driver.on_drop(false) {
                c.in_drop_episode = true;
                self.report(c, "dropped, retrying");
                if !c.config.drop_protection {
                    self.give_back_local_network(c);
                } else if let Some((tun, gws)) = c.last_pf.clone() {
                    // The drop window is fail-closed again (§17.5).
                    self.load_pf(c, Some(tun), gws, false);
                }
                self.respawn_after(delay.as_secs_f64());
                return;
            }
        }
        self.handle_post_auth_failure(c, "child exited without connect hook");
    }

    fn reinitiate_expired_approval(self: &Arc<Self>, c: &mut Core) {
        let since = *c.unanswered_since.get_or_insert_with(Instant::now);
        let backoff = if c.config.push_backoff.is_empty() { vec![30.0, 60.0, 120.0, 300.0] } else { c.config.push_backoff.clone() };
        let mut delay = backoff[c.expired_approvals.min(backoff.len() - 1)];
        if since.elapsed().as_secs_f64() >= QUIET_AFTER {
            delay = QUIET_INTERVAL;
        }
        c.expired_approvals += 1;
        delay *= jitter();
        c.saw_login_failed = false;
        let when = if delay < 90.0 { format!("{} 秒", delay.round() as i64) } else { format!("{} 分钟", (delay / 60.0).round() as i64) };
        self.report(c, &format!("手机上的批准已超时，{when}后重新发起批准"));
        self.respawn_after(delay);
    }

    fn handle_post_auth_failure(self: &Arc<Self>, c: &mut Core, detail: &str) {
        if c.in_drop_episode && !c.config.drop_protection {
            self.give_back_local_network(c);
        }
        if let DriverAction::Reauthenticate { delay } = c.driver.on_auth_outcome(AuthOutcome::Transient) {
            self.report(c, detail);
            self.respawn_after(delay.as_secs_f64());
        } else if let DriverAction::Reauthenticate { delay } = c.driver.on_drop(false) {
            self.respawn_after(delay.as_secs_f64());
        } else {
            self.finish_terminal(c, Terminal::AttemptsExhausted, detail);
        }
    }

    // MARK: pf and manual stop

    fn load_pf(&self, c: &mut Core, tunnel_if: Option<String>, gateway_ips: Vec<String>, allow_direct_egress: bool) {
        // Not after the user's disconnect began (§30.3).
        if c.stop_requested {
            return;
        }
        let Some(tun) = tunnel_if.filter(|_| !gateway_ips.is_empty()) else {
            let e = "pf 兜底未生效：缺少隧道接口或网关 IP".to_string();
            c.pf_error = Some(e.clone());
            self.report(c, &e);
            return;
        };
        if !c.config.drop_protection {
            // No set of ours; the inputs are kept for switching it on.
            c.pf_error = None;
            c.last_pf = Some((tun, gateway_ips));
            c.last_allow_direct_egress = allow_direct_egress;
            return;
        }
        let mut inputs = Inputs {
            tunnel_if: tun.clone(),
            gateway_ips: gateway_ips.clone(),
            physical_if: c.config.physical_if.clone(),
            allow_networks: c.direct_networks(),
            allow_dns: false,
            local_dns_servers: c.local_dns.clone(),
            direct_table: false,
            strict_dns: c.config.relay.is_some(),
        };
        let mut connected = allow_direct_egress;
        if c.forwarder.is_some() {
            // Reconcile the current policy, never replay an append-only list
            // from an older rule set after protection is re-enabled.
            if !self.sync_split_routes(c) { return; }
            // Domain split (§26.7): one set, connected and dropped alike.
            inputs.local_dns_servers = c.local_dns.clone();
            inputs.direct_table = true;
            connected = false;
        }
        if let Some(problem) = self.guard.apply(&self.holder, connected, &inputs) {
            c.pf_error = Some(problem.clone());
            self.report(c, &problem);
            return;
        }
        c.pf_error = None;
        c.last_pf = Some((tun, gateway_ips));
        c.last_allow_direct_egress = allow_direct_egress;
    }

    fn remove_manual_flag(&self, c: &mut Core) {
        let _ = std::fs::remove_file(c.manual_flag_path());
        c.manual_flag_installed = false;
    }

    fn install_manual_flag(&self, c: &mut Core) {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = c.support();
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        if std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(c.manual_flag_path()).is_ok() {
            c.manual_flag_installed = true;
        } else {
            network_guard::log("CLIOrchestrator: manual flag install failed");
        }
    }

    fn finish_manual_stop(&self, c: &mut Core) {
        // The split's own changes first: the forwarder, then the routes.
        self.stop_split(c);
        // Idempotent restore (a child stopped between retries never ran
        // the script's manual path).
        run_script("restore", &c.config.script_path, &c.support(), c.config.no_routes, c.config.test_active);
        self.guard.release(Some(&self.holder), network_guard::reason::USER);
        c.last_pf = None;
        self.remove_manual_flag(c);
        self.finish_terminal(c, Terminal::StoppedManual, "manual disconnect");
        for _ in 0..std::mem::take(&mut c.pending_stop_notices) {
            (self.hooks.stopped)();
        }
    }

    fn remember_tunnel(&self, c: &mut Core) {
        c.tunnel_lease = c.tunnel_if.as_ref().and_then(|name| interface_index(name)
            .map(|index| TunnelLease { name: name.clone(), index, generation: c.generation }));
        if c.tunnel_lease.is_some() && c.last_error.as_deref()==Some(TUNNEL_RECONFIRM_ERROR) { c.last_error=None; }
    }

    /// A short physical outage need not make openconnect reconnect. Re-arm
    /// only the exact interface previously confirmed by this live child.
    fn reconfirm_tunnel(&self, c: &mut Core) -> bool {
        if c.stop_requested || c.tunnel_retrying || !c.hook_fired { return false; }
        let Some(lease) = &c.tunnel_lease else { return false };
        if !c.child.as_ref().is_some_and(|child| child.alive.load(Ordering::SeqCst)
            && child.generation == lease.generation && c.generation == lease.generation)
            || interface_index(&lease.name) != Some(lease.index) {
            c.tunnel_if=None;
            self.update_forwarder(c);
            if c.last_error.as_deref()!=Some(TUNNEL_RECONFIRM_ERROR) {
                c.last_error=Some(TUNNEL_RECONFIRM_ERROR.into()); self.report(c,TUNNEL_RECONFIRM_ERROR);
            }
            return false;
        }
        if c.tunnel_if.as_ref() == Some(&lease.name) { return false; }
        c.tunnel_if = Some(lease.name.clone());
        if c.last_error.as_deref()==Some(TUNNEL_RECONFIRM_ERROR) { c.last_error=None; }
        self.update_forwarder(c);
        true
    }

    /// Configd can change DNS without a routing event or a different router.
    /// All watchers feed this one reducer path; unchanged facts do no work.
    fn refresh_network(&self, c: &mut Core) {
        let Some((gateway, interface)) = (self.hooks.physical_network)(&c.config.physical_if) else {
            if c.physical_gateway.is_some() || c.tunnel_if.is_some() || !c.local_dns.is_empty() {
                c.physical_gateway = None;
                c.tunnel_if = None;
                c.local_dns.clear();
                self.update_forwarder(c);
                if let Some((tun, gws)) = c.last_pf.clone() {
                    self.load_pf(c, Some(tun), gws, false);
                }
                self.report(c, "正在重新确认网络；断线保护保持");
            }
            return;
        };
        if c.physical_gateway.as_ref() != Some(&gateway) || c.config.physical_if != interface {
            self.follow_network(c, &gateway, &interface, true);
            return;
        }
        if self.reconfirm_tunnel(c) { self.report(c, "网络已恢复，继续使用当前 VPN"); }
        if c.forwarder.is_some() || c.config.relay.is_some() {
            let dns = (self.hooks.local_dns)(&interface);
            if dns != c.local_dns {
                c.local_dns = dns;
                self.update_forwarder(c);
                if let Some((tun, gws)) = c.last_pf.clone() {
                    let allow = c.last_allow_direct_egress;
                    self.load_pf(c, Some(tun), gws, allow);
                }
            }
        }
    }

    /// The physical network changed under a live session (§28.1).
    fn follow_network(&self, c: &mut Core, gateway: &str, interface: &str, move_gateway_route: bool) {
        network_guard::log(&format!("network changed: now via {interface}"));
        c.physical_gateway = Some(gateway.to_string());
        c.config.physical_if = interface.to_string();
        if move_gateway_route {
            run_script("follow-network", &c.config.script_path, &c.support(), c.config.no_routes, c.config.test_active);
        }
        // The session's direct routes (the split's addresses and the
        // direct networks, §40.1) go via the new router.
        self.routes.repoint(gateway);
        c.tunnel_if = None;
        if c.forwarder.is_some() || c.config.relay.is_some() {
            c.local_dns = if c.config.no_routes { Vec::new() } else { (self.hooks.local_dns)(interface) };
        }
        self.reconfirm_tunnel(c);
        self.update_forwarder(c);
        self.sync_split_routes(c);
        self.route_networks_direct(c);
        if let Some((tun, gws)) = c.last_pf.clone() {
            // pf passes the gateway on the physical interface.
            let allow = c.last_allow_direct_egress;
            self.load_pf(c, Some(tun), gws, allow);
        }
        self.report(c, if c.tunnel_if.is_some() { "网络已更新，继续使用当前 VPN" } else { "网络已更新，等待确认 VPN 接口；断线保护保持" });
    }
}

fn wipe(s: &mut String) {
    unsafe {
        for b in s.as_bytes_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_engine(name: &str) -> (Engine, PathBuf) {
        split_engine_with_hooks(name, Hooks {
            state: Box::new(|_, _| {}), terminal: Box::new(|_| {}),
            physical_network: Box::new(|_| None), local_dns: Box::new(|_| vec![]),
            system_roots: Box::new(|| None), stopped: Box::new(|| {}),
        })
    }
    fn split_engine_with_hooks(name: &str, hooks: Hooks) -> (Engine, PathBuf) {
        let support = std::env::temp_dir().join(format!("ac-split-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&support);
        std::fs::create_dir_all(&support).unwrap();
        let guard = Arc::new(Guard::new(network_guard::Settings {
            support_dir: support.clone(), boot: Some("test-boot".into()),
            grace: Duration::from_secs(120), pfctl: None,
        }));
        let engine = Engine::new(Config { no_routes: true, test_active: true,
            support_dir: support.to_string_lossy().into_owned(), boot_session: "test-boot".into(),
            script_path: "/usr/bin/true".into(), ..Config::default() }, hooks, guard);
        {
            let mut c = engine.shared.core.lock().unwrap();
            c.physical_gateway = Some("192.168.1.1".into());
            c.forwarder = Some(Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), 53,
                Duration::from_millis(50), vec!["direct.example".into()],
                Upstreams { tunnel: vec![], local: vec![], physical_if: None, tunnel_if: None }, None));
        }
        (engine, support)
    }
    fn dns_event(engine: &Engine, epoch: u64, name: &str, direct: bool) -> bool {
        let (tx, rx) = mpsc::channel();
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        engine.send(Event::DnsAnswer(dns_forwarder::Observation {
            epoch, name: name.into(), entry: direct.then(|| name.into()),
            addresses: vec![ip], direct: if direct { vec![ip] } else { vec![] },
        }, tx));
        rx.recv_timeout(Duration::from_secs(2)).unwrap()
    }
    #[test]
    fn queued_rule_removal_revokes_route_pf_and_rejects_late_reply() {
        let (engine, support) = split_engine("remove");
        let epoch = engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine, epoch, "direct.example", true));
        assert_eq!(engine.shared.routes.addresses(), vec!["203.0.113.9"]);
        assert_eq!(engine.shared.guard.direct_addresses(), vec!["203.0.113.9"]);
        engine.update_direct_domains(vec![]);
        assert!(!dns_event(&engine, epoch, "direct.example", true), "old query must stay invalid after removal");
        assert!(engine.shared.routes.addresses().is_empty());
        assert!(engine.shared.guard.direct_addresses().is_empty());
        assert!(!std::fs::read_to_string(support.join("direct-routes")).unwrap().contains("203.0.113.9"));
        engine.stop(false, false);
        assert!(!dns_event(&engine, epoch, "direct.example", true));
        drop(engine);
        std::fs::remove_dir_all(support).unwrap();
    }
    #[test]
    fn vpn_observation_revokes_shared_ip_before_ack_and_protection_rearm() {
        let (engine, support) = split_engine("shared");
        let epoch = engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine, epoch, "direct.example", true));
        assert!(dns_event(&engine, epoch, "vpn.example", false));
        assert!(engine.shared.routes.addresses().is_empty());
        assert!(engine.shared.guard.direct_addresses().is_empty());
        // Reconciliation after a guard release cannot resurrect stale IPs.
        engine.shared.guard.release(Some(&engine.holder()), network_guard::reason::USER);
        {
            let mut c = engine.shared.core.lock().unwrap();
            assert!(engine.shared.sync_split_routes(&mut c));
            assert!(c.split_addresses.is_empty());
        }
        engine.stop(false, false);
        assert!(!dns_event(&engine, epoch, "direct.example", true));
        drop(engine);
        std::fs::remove_dir_all(support).unwrap();
    }
    #[test]
    fn reconnect_and_network_change_invalidate_vpn_dns_interface() {
        let (engine, support) = split_engine("reconnect");
        let mut c = engine.shared.core.lock().unwrap();
        c.last_pf = Some(("utun5".into(), vec!["198.51.100.1".into()]));
        c.tunnel_if = Some("utun5".into());
        engine.shared.update_forwarder(&c);
        let epoch = c.forwarder.as_ref().unwrap().epoch();
        engine.shared.handle_hook(&mut c, "attempt-reconnect");
        assert_eq!(c.tunnel_if, None);
        assert!(!c.forwarder.as_ref().unwrap().is_current(epoch));
        engine.shared.handle_hook(&mut c, "reconnect");
        assert_eq!(c.tunnel_if.as_deref(), Some("utun5"));
        engine.shared.handle_hook(&mut c, "reconnect tun=utun6 dns=10.2.2.2");
        assert_eq!(c.tunnel_if.as_deref(), Some("utun6"));
        assert_eq!(c.tunnel_dns, vec!["10.2.2.2"]);
        let epoch = c.forwarder.as_ref().unwrap().epoch();
        engine.shared.follow_network(&mut c, "192.168.2.1", "en5", false);
        assert_eq!(c.tunnel_if, None, "new physical path cannot silently reuse an unconfirmed VPN interface");
        assert!(!c.forwarder.as_ref().unwrap().is_current(epoch));
        drop(c);
        engine.stop(false, false);
        assert!(!dns_event(&engine, epoch, "direct.example", true));
        drop(engine);
        std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn unchanged_interface_and_gateway_still_refresh_changed_dns_and_invalidate_old_answers() {
        let facts = Arc::new(Mutex::new(Some(("192.168.1.1".into(), "en0".into()))));
        let dns = Arc::new(Mutex::new(vec!["192.168.1.2".into(), "192.168.1.3".into()]));
        let f = facts.clone(); let d = dns.clone();
        let (engine, support) = split_engine_with_hooks("dns-only", Hooks {
            state: Box::new(|_, _| {}), terminal: Box::new(|_| {}),
            physical_network: Box::new(move |_| f.lock().unwrap().clone()),
            local_dns: Box::new(move |_| d.lock().unwrap().clone()),
            system_roots: Box::new(|| None), stopped: Box::new(|| {}),
        });
        let epoch = {
            let mut c = engine.shared.core.lock().unwrap();
            c.config.physical_if = "en0".into(); c.watching = true;
            c.local_dns = vec!["192.168.1.1".into()]; c.tunnel_if = Some("utun5".into());
            engine.shared.update_forwarder(&c); c.forwarder.as_ref().unwrap().epoch()
        };
        engine.network_changed();
        assert!(!dns_event(&engine, epoch, "direct.example", true));
        {
            let mut c = engine.shared.core.lock().unwrap();
            assert_eq!(c.local_dns, *dns.lock().unwrap());
            assert_eq!(c.tunnel_if.as_deref(), Some("utun5"), "DNS-only updates do not falsely disconnect the VPN");
            let epoch = c.forwarder.as_ref().unwrap().epoch();
            engine.shared.refresh_network(&mut c);
            assert!(c.forwarder.as_ref().unwrap().is_current(epoch), "same facts do not churn configuration");
            *facts.lock().unwrap() = None; // sleep/offline: no physical service
            engine.shared.refresh_network(&mut c);
            assert!(c.local_dns.is_empty() && c.tunnel_if.is_none() && c.physical_gateway.is_none());
            assert!(!c.forwarder.as_ref().unwrap().is_current(epoch));
        }
        engine.stop(false, false); assert!(!dns_event(&engine, epoch, "direct.example", true));
        drop(engine); std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn sinkhole_and_local_dns_answers_cannot_install_routes_or_poison_other_names() {
        let (engine,support)=split_engine("special-addresses");
        engine.shared.routes.test_commands(Box::new(|_|panic!("special answer must not mutate routes")),crate::network_check::Output::default());
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        for ip in ["0.0.0.0","127.0.0.1","127.0.0.2","169.254.1.2","224.0.0.1","255.255.255.255"] {
            let (tx,rx)=mpsc::channel();let ip=ip.parse().unwrap();
            engine.send(Event::DnsAnswer(dns_forwarder::Observation { epoch,name:"direct.example".into(),entry:Some("direct.example".into()),addresses:vec![ip],direct:vec![ip] },tx));
            assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
            assert!(engine.shared.routes.addresses().is_empty()); assert!(engine.shared.guard.direct_addresses().is_empty());
            assert!(dns_event(&engine,epoch,"vpn.example",false));
        }
        engine.stop(false,false); assert!(!dns_event(&engine,0,"old.example",true));
        drop(engine); std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn withdrawn_route_already_removed_by_system_does_not_poison_other_dns_answers() {
        let (engine,support)=split_engine("absent-route");
        engine.shared.routes.test_commands(Box::new(|args| if args.contains(&"delete") {1}else{0}),
            crate::network_check::Output { ok:true,text:"Destination Gateway Flags Netif Expire\ndefault 192.168.1.1 UGSc en0\n".into() });
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine,epoch,"direct.example",true));
        engine.update_direct_domains(vec![]); assert!(!dns_event(&engine,epoch,"direct.example",true));
        let current=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(engine.shared.routes.addresses().is_empty());
        assert!(dns_event(&engine,current,"vpn.example",false));
        assert!(dns_event(&engine,current,"another.example",false));
        engine.stop(false,false); assert!(!dns_event(&engine,0,"old.example",true));
        drop(engine); std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn live_tunnel_binding_recovers_after_short_outage_without_another_hook() {
        let facts = Arc::new(Mutex::new(Some(("192.168.1.1".into(), "en0".into()))));
        let observed = facts.clone();
        let (engine, support) = split_engine_with_hooks("live-binding", Hooks {
            state: Box::new(|_,_| {}), terminal: Box::new(|_| {}),
            physical_network: Box::new(move |_| observed.lock().unwrap().clone()),
            local_dns: Box::new(|_| vec![]), system_roots: Box::new(|| None), stopped: Box::new(|| {}),
        });
        let iface = if cfg!(target_os="macos") { "lo0" } else { "lo" };
        let udp=std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let server=udp.local_addr().unwrap().to_string();
        let done=Arc::new(AtomicBool::new(false)); let stop=done.clone();
        let packets=Arc::new(std::sync::atomic::AtomicUsize::new(0));let count=packets.clone();
        let responder=std::thread::spawn(move || {
            let mut bytes=[0;512];
            while !stop.load(Ordering::SeqCst) { if let Ok((n,peer))=udp.recv_from(&mut bytes) {
                count.fetch_add(1,Ordering::SeqCst); let mut reply=bytes[..n].to_vec();
                reply[2]=0x81;reply[3]=0x80;reply[7]=1;
                reply.extend([0xc0,12,0,1,0,1,0,0,0,60,0,4,198,51,100,1]);let _=udp.send_to(&reply,peer);
            }}
        });
        let query=crate::on_demand::dns_query("vpn.example").unwrap();
        let mut c = engine.shared.core.lock().unwrap();
        c.tunnel_dns=vec![server];
        c.config.physical_if = "en0".into(); c.generation = 7; c.hook_fired = true;
        c.child = Some(Child { pid: i32::MAX, generation: 7, alive: Arc::new(AtomicBool::new(true)) });
        c.tunnel_if = Some(iface.into()); engine.shared.remember_tunnel(&mut c); engine.shared.update_forwarder(&c);
        *facts.lock().unwrap() = None; engine.shared.refresh_network(&mut c); assert!(c.tunnel_if.is_none());
        *facts.lock().unwrap() = Some(("192.168.1.1".into(), "en0".into()));
        engine.shared.refresh_network(&mut c);
        assert_eq!(c.forwarder.as_ref().unwrap().bound_tunnel_interface().as_deref(), Some(iface));
        assert!(c.forwarder.as_ref().unwrap().inner().resolve(&query).is_some());
        let before=packets.load(Ordering::SeqCst);
        let epoch=c.forwarder.as_ref().unwrap().epoch();
        let index=c.tunnel_lease.as_ref().unwrap().index;
        c.tunnel_lease.as_mut().unwrap().index=index+10000;
        engine.shared.refresh_network(&mut c);
        assert!(c.tunnel_if.is_none());
        assert!(!c.forwarder.as_ref().unwrap().is_current(epoch));
        assert!(c.forwarder.as_ref().unwrap().bound_tunnel_interface().is_none());
        assert!(c.forwarder.as_ref().unwrap().inner().resolve(&query).is_none());
        assert_eq!(packets.load(Ordering::SeqCst),before);
        c.tunnel_lease.as_mut().unwrap().index=index;
        engine.shared.refresh_network(&mut c);
        assert_eq!(c.forwarder.as_ref().unwrap().bound_tunnel_interface().as_deref(),Some(iface));
        c.tunnel_if = None; c.tunnel_retrying = true; engine.shared.refresh_network(&mut c);
        assert!(c.tunnel_if.is_none(), "an internal reconnect still needs its own confirmation");
        c.tunnel_retrying = false; c.generation = 8; engine.shared.refresh_network(&mut c);
        assert!(c.tunnel_if.is_none(), "old ownership cannot confirm a new child generation");
        c.child = None; drop(c); engine.stop(false,false); assert!(!dns_event(&engine,0,"old.example",true));
        done.store(true,Ordering::SeqCst);responder.join().unwrap();
        drop(engine); std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn startup_cleanup_reports_pending_when_script_exits_unsuccessfully() {
        let dir=std::env::temp_dir().join(format!("ac-pending-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(route_state_path(&dir),"AC_BOOT=B1\n").unwrap();
        assert_eq!(undo_journal_at_start("/usr/bin/false",&dir,Some("B1"),true),"pending");
        assert!(route_state_path(&dir).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn self_check_cannot_report_a_green_snapshot_across_a_rule_or_network_change() {
        let (engine, support) = split_engine("check-generation");
        let result = engine.run_network_check_with(|_| {
            engine.update_direct_domains(vec!["new.example".into()]);
            // A queue barrier: update above is applied before this stale reply.
            assert!(!dns_event(&engine, 0, "old.example", true));
            vec![crate::network_check::Item { item:"fixture".into(), passed:true, informational:false, detail:"old pass".into() }]
        });
        let rows: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(rows[0]["passed"], false);
        assert!(rows[0]["detail"].as_str().unwrap().contains("已变化"));
        engine.stop(false, false); assert!(!dns_event(&engine, 0, "old.example", true));
        drop(engine); std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn root_default_never_falls_back_to_user_tools() {
        let selected = Shared::default_executable(true);
        match selected {
            Some(path) => {
                assert_eq!(path, format!("{BUNDLED_DIR}/bin/openconnect"));
                assert!(bundled_is_trusted(&path));
            }
            None => assert!(!bundled_is_trusted(&format!("{BUNDLED_DIR}/bin/openconnect"))),
        }
        assert!(!bundled_is_trusted("/usr/bin/true"));
        assert!(!bundled_is_trusted("relative/bin/openconnect"));
        assert!(Shared::default_executable(false).is_some());
    }

    #[test]
    fn redaction_masks_and_terminates() {
        assert_eq!(redact("Set-Cookie: webvpn=abc; path=/"), "Set-Cookie: webvpn=***; path=/");
        assert_eq!(redact("Cookie: webvpncontext=xyz webvpn=q"), "Cookie: webvpncontext=*** webvpn=***");
        assert_eq!(redact("> <auth><password>hunter2</password></auth>"), "> <auth><password>***</password></auth>");
        assert_eq!(redact("webvpn="), "webvpn=***");
        assert_eq!(capture_cookie("Cookie: webvpn=ABC123; webvpnc=x").as_deref(), Some("ABC123"));
        assert_eq!(capture_cookie("Set-Cookie: webvpn=<elided>"), None);
        assert_eq!(capture_cookie("Cookie: webvpncontext=zz"), None);
        assert_eq!(shell_quoted("/a b/it's"), "'/a b/it'\\''s'");
    }
}
