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
use std::collections::{HashMap,HashSet};
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
    let success=crate::child_io::status(&mut cmd).is_ok_and(|status|status.success());
    if !success { network_guard::log("CLIOrchestrator: route operation did not complete"); }
    success
}

/// "The local network is still held closed": the gate holds a set, or
/// the script changed routes and no restore has undone them yet.
pub fn local_network_held(support: &Path) -> bool {
    // Direct host-route cleanup does not close the physical default path.
    // Keep that journal for diagnosis without stranding UI or idle shutdown.
    network_guard::shared().is_some_and(|g| g.is_holding()) || route_state_path(support).exists()
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
    pub split_warning: Option<String>,
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
const SPLIT_CAPACITY_ERROR: &str = "分流记录已达到容量上限，本次连接暂时全部走 VPN；请重新连接以恢复按网站分流";
enum SplitSync { Complete, PendingAdditions, Blocked }
struct DirectRetry { until:Instant, delay:Duration }
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
    pf_needs_load: bool,
    forwarder: Option<Forwarder>,
    physical_gateway: Option<String>,
    local_dns: Vec<String>,
    routed_networks: HashSet<String>,
    network_routes_error: Option<String>,
    routes_need_repoint: bool,
    split_hits: Vec<String>,
    split_addresses: HashSet<String>,
    last_pf: Option<(String, Vec<String>)>,
    last_allow_direct_egress: bool,
    tunnel_dns: Vec<String>,
    tunnel_if: Option<String>,
    tunnel_lease: Option<TunnelLease>,
    split_policy: crate::split_policy::SplitPolicy,
    split_needs_sync: bool,
    direct_retries: HashMap<Ipv4Addr,DirectRetry>,
    direct_retry_warning: Option<String>,
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
        guard.own_engine_started(&holder);
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
                pf_needs_load: false,
                forwarder: None,
                physical_gateway: None,
                local_dns: Vec::new(),
                routed_networks: HashSet::new(),
                network_routes_error: None,
                routes_need_repoint: false,
                split_hits: Vec::new(),
                split_addresses: HashSet::new(),
                last_pf: None,
                last_allow_direct_egress: false,
                tunnel_dns: Vec::new(),
                tunnel_if: None,
                tunnel_lease: None,
                split_policy: crate::split_policy::SplitPolicy::default(),
                split_needs_sync: false,
                direct_retries: HashMap::new(),
                direct_retry_warning: None,
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
            routes: self.shared.routes.addresses(), error: c.pf_error.clone().or_else(||c.network_routes_error.clone()),
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
    fn direct_retry_ready(&self,ip:&Ipv4Addr,now:Instant)->bool {
        self.direct_retries.get(ip).is_none_or(|retry|now>=retry.until)
    }
    fn reset_direct_retries(&mut self) {
        self.direct_retries=HashMap::new();self.direct_retry_warning=None;
    }
    fn record_direct_retries(&mut self,intended:&HashSet<String>,attempted:&HashSet<Ipv4Addr>,now:Instant) {
        let pending:HashSet<Ipv4Addr>=intended.difference(&self.split_addresses).filter_map(|ip|ip.parse().ok()).collect();
        self.direct_retries.retain(|ip,_|pending.contains(ip));
        if pending.is_empty() {self.reset_direct_retries();return;}
        for ip in &pending {
            self.direct_retries.entry(*ip).and_modify(|retry| {
                if attempted.contains(ip) {
                    retry.delay=retry.delay.saturating_mul(2).min(Duration::from_secs(30));
                    retry.until=now+retry.delay;
                }
            }).or_insert(DirectRetry{until:now+Duration::from_secs(1),delay:Duration::from_secs(1)});
        }
        let name=pending.iter().min().and_then(|ip|self.split_policy.direct_name(ip)).unwrap_or("部分网站");
        self.direct_retry_warning=Some(format!("直连网站「{name}」暂时不可达，已限制重试频率；其他域名不受影响。可移出直连名单或重新连接后重试。"));
    }
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
            pf_error: c.pf_error.clone().or_else(||c.network_routes_error.clone()),
            last_terminal: c.last_terminal.map(|t| t as i32),
            split_running: c.forwarder.is_some(),
            split_hits: if c.forwarder.is_some() { c.split_hits.clone() } else { Vec::new() },
            split_warning: if c.split_policy.is_saturated() {Some(SPLIT_CAPACITY_ERROR.into())}else{c.direct_retry_warning.clone()},
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
                    c.reset_direct_retries();
                    if let Some(f) = &c.forwarder {
                        f.set_rules(&d);
                    }
                    c.split_policy.revalidate(&dns_forwarder::SplitRules::new(&d));
                    self.sync_split_routes(&mut c);
                    c.config.direct_domains = Some(d);
                }
                Event::DropProtection(on) => self.update_drop_protection(&mut c, on),
                Event::AllowNetworks(n) => {
                    c.reset_direct_retries();
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
                        let direct=if answer.direct.is_empty() {Vec::new()} else {
                            direct_routes::assigned_ipv4().map(|own|answer.direct.iter().copied().filter(|ip|!own.contains(ip)).collect()).unwrap_or_else(||answer.direct.clone())
                        };
                        let changed = c.split_policy.observe(answer.name, &answer.addresses, &direct);
                        let needs_answer_sync=c.split_needs_sync&&!self.dns_observation_ready(&c,&answer.addresses);
                        let now=Instant::now();
                        let retry_ready=answer.addresses.iter().any(|ip|!c.split_policy.allows(ip)||c.direct_retry_ready(ip,now));
                        if changed || c.pf_needs_load || (needs_answer_sync && retry_ready) {
                            self.sync_split_routes(&mut c);
                        }
                        if c.split_policy.is_saturated() && c.last_error.as_deref()!=Some(SPLIT_CAPACITY_ERROR) {
                            c.last_error=Some(SPLIT_CAPACITY_ERROR.into());self.report(&c,SPLIT_CAPACITY_ERROR);
                        }
                        let ok=self.dns_observation_ready(&c,&answer.addresses);
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
        inputs.allow_networks = c.direct_networks();
        // This session has not reconciled the previous engine's DNS policy.
        // Preserve its base guard, never re-enable its dynamic bypasses.
        inputs.block_direct = inputs.direct_table;
        c.last_pf = Some((inputs.tunnel_if.clone(), inputs.gateway_ips.clone()));
        c.last_allow_direct_egress = false;
        c.pf_needs_load = true;
        if let Some(problem) = self.guard.apply(&self.holder, false, &inputs) {
            c.pf_error = Some(problem);
            network_guard::log("engine start: taking over the held set failed");
            return;
        }
        c.pf_needs_load = false;
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
        self.guard.own_engine_finished(&self.holder);
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
        match self.try_sync_split_routes(c) {
            SplitSync::Complete=>true,
            SplitSync::PendingAdditions=>false,
            SplitSync::Blocked=>{self.suspend_dynamic_direct(c);false}
        }
    }

    /// Confirm this answer, independently of optional work for other names.
    /// A revoked address must have lost its route and effective PF permission.
    fn dns_observation_ready(&self,c:&Core,addresses:&[Ipv4Addr])->bool {
        if c.pf_needs_load {return false;}
        let active=!c.config.drop_protection||self.guard.dynamic_direct_enabled(&self.holder);
        addresses.iter().all(|ip| {
            let text=ip.to_string();
            if c.split_policy.allows(ip) {c.split_addresses.contains(&text)&&active}
            else {!self.routes.contains_address(&text)&&(!active||!self.guard.direct_contains(&text))}
        })
    }

    fn suspend_dynamic_direct(&self, c: &mut Core) -> bool {
        if !c.config.drop_protection || c.stop_requested { return true; }
        let Some((holder, mut inputs)) = self.guard.held() else { return c.last_pf.is_none(); };
        if holder != self.holder { c.pf_needs_load=true; return false; }
        if !inputs.direct_table || inputs.block_direct { return true; }
        inputs.block_direct = true;
        if let Some(error) = self.guard.apply(&self.holder, false, &inputs) {
            c.pf_needs_load=true;
            c.pf_error = Some(error.clone()); self.report(c, &error);
            return false;
        }
        true
    }

    fn try_sync_split_routes(&self, c: &mut Core) -> SplitSync {
        let recovering=c.pf_error.is_some();
        if c.pf_needs_load && !self.apply_base_pf(c) { return SplitSync::Blocked; }
        if !self.repoint_routes(c) { return SplitSync::Blocked; }
        if !self.routes.reconcile_metadata(){
            let error="路由退休记录尚未持久化；基础保护保持";c.pf_error=Some(error.into());self.report(c,error);return SplitSync::Blocked;
        }
        let mut desired = c.split_policy.direct();
        if !desired.is_empty() {
            let Some(own)=direct_routes::assigned_ipv4() else {
                let error="本机地址未确认，直连例外未更新；可使用恢复网络";
                c.pf_error=Some(error.into()); self.report(c,error); return SplitSync::Blocked;
            };
            desired.retain(|value|value.parse().is_ok_and(|ip|direct_routes::ordinary_unicast(ip)&&!own.contains(&ip)));
        }
        let intended=desired.clone();
        let now=Instant::now();
        let attempting:HashSet<Ipv4Addr>=intended.iter().filter_map(|ip|ip.parse().ok()).filter(|ip|c.direct_retry_ready(ip,now)).collect();
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
            return SplitSync::Blocked;
        }
        let new: Vec<_> = routable.difference(&routed).filter(|ip|ip.parse().is_ok_and(|ip|attempting.contains(&ip))).cloned().collect();
        if !new.is_empty() {
            // DirectRoutes records exact per-address outcomes, so one batch
            // avoids repeating fsync and rewriting the journal for every IP.
            if let Some(gateway)=&c.physical_gateway {self.routes.add(&new,gateway);}
        }
        let persisted=self.routes.reconcile_metadata();
        let installed:HashSet<_>=self.routes.addresses().into_iter().collect();
        let mut additions_ok=persisted&&new.iter().all(|ip|installed.contains(ip));
        let mut unconfirmed=HashSet::new();
        if !persisted {unconfirmed.extend(new);}
        desired.retain(|ip|!unconfirmed.contains(ip)&&(!routable.contains(ip)||installed.contains(ip))&&ip.parse().is_ok_and(|ip|attempting.contains(&ip)));
        let fresh:Vec<_>=desired.difference(&actual).cloned().collect();
        // Table additions are optional too: one failure must not poison
        // unrelated VPN DNS, nor authorise an unrouted direct address.
        if !self.guard.add_direct(&fresh) {
            // A command may mutate the kernel and then report failure. First
            // disable the table, then rearm through an exact full replacement.
            if !self.suspend_dynamic_direct(c) {return SplitSync::Blocked;}
            let known:HashSet<_>=self.guard.direct_addresses().into_iter().collect();
            desired.retain(|address|known.contains(address));
            additions_ok=false;
        }
        c.split_addresses=desired;
        additions_ok&=intended.is_subset(&c.split_addresses);
        let rearmed=self.rearm_direct_after_sync(c);
        c.split_needs_sync=!rearmed||!additions_ok;
        if !rearmed {return SplitSync::Blocked;}
        c.record_direct_retries(&intended,&attempting,now);
        if !additions_ok {
            let error="部分直连路由安装失败；受影响网站等待重试，其余 DNS 正常，基础保护保持";
            c.pf_error=Some(error.into());self.report(c,error);return SplitSync::PendingAdditions;
        }
        c.pf_error=None;
        if recovering {
            let detail=c.network_routes_error.as_deref().or(c.last_error.as_deref()).unwrap_or("直连例外已恢复同步");
            self.report(c,detail);
        }
        SplitSync::Complete
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
            c.pf_needs_load = false;
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
        if !self.repoint_routes(c) { return; }
        let Some(gateway)=c.physical_gateway.clone() else {return;};
        let wanted:HashSet<String>=direct_routes::networks_to_route(&c.direct_networks(),&direct_routes::attached_networks()).into_iter().collect();
        let actual:HashSet<String>=self.routes.managed_addresses().into_iter().filter(|s|direct_routes::is_network(s)).collect();
        let gone:Vec<_>=actual.difference(&wanted).cloned().collect();
        let new:Vec<_>=wanted.difference(&actual).cloned().collect();
        let removed=self.routes.remove(&gone);
        let added=self.routes.add(&new,&gateway);
        c.routed_networks=self.routes.addresses().into_iter().filter(|s|direct_routes::is_network(s)).collect();
        if !removed || !added || c.routed_networks!=wanted {
            let error="直连网段尚未同步完成；基础断线保护保持，可重试恢复网络";
            c.network_routes_error=Some(error.into());self.report(c,error);
        } else {c.network_routes_error=None;}
    }

    fn repoint_routes(&self, c: &mut Core) -> bool {
        if !c.routes_need_repoint { return true; }
        if !c.physical_gateway.as_ref().is_some_and(|gateway| self.routes.repoint(gateway)) {
            let error="直连路由仍待切换到当前网关；基础保护保持";
            c.network_routes_error=Some(error.into()); self.report(c,error); return false;
        }
        c.routes_need_repoint=false;
        true
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
        let Ok((read_end, write_end)) = crate::child_io::pipe() else { return };
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
        c.network_routes_error=None;
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
        c.reset_direct_retries();
        if c.last_error.as_deref()==Some(SPLIT_CAPACITY_ERROR) {c.last_error=None;}
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
        let mut child = match crate::child_io::spawn(&mut cmd) {
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
                        "phys" if !v.is_empty() => {
                            if c.config.physical_if != *v { c.routes_need_repoint=true; }
                            c.config.physical_if = v.to_string();
                        }
                        "dns" => c.tunnel_dns = v.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect(),
                        "lanex" => {
                            c.gateway_lan_excludes =
                                v.split(',').filter(|x| crate::kill_switch::is_cidr(x)).map(str::to_string).collect()
                        }
                        "physgw" if is_ipv4(v) => {
                            let previous = c.physical_gateway.replace(v.to_string());
                            // A fresh connect on a different network: this
                            // session's routes still point at the old router.
                            if previous.as_deref() != Some(*v) {
                                c.routes_need_repoint = true;
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
        if c.stop_requested {return;}
        let Some(tun)=tunnel_if.filter(|_|!gateway_ips.is_empty()) else {
            let error="pf 兜底未生效：缺少隧道接口或网关 IP";c.pf_error=Some(error.into());self.report(c,error);return;
        };
        // Keep the current intent even when an OS operation fails, so later
        // events can retry without relying on another connect hook.
        c.last_pf=Some((tun.clone(),gateway_ips.clone()));
        c.last_allow_direct_egress=allow_direct_egress;
        if !self.apply_base_pf(c) {return;}
        if c.forwarder.is_some() && !self.sync_split_routes(c) {return;}
        c.pf_error=None;
    }

    /// Retryable mandatory work, separate from optional split convergence so
    /// either network refresh or DNS acknowledgement can recover it safely.
    fn apply_base_pf(&self, c: &mut Core) -> bool {
        if c.stop_requested {return false;}
        if !c.config.drop_protection {c.pf_needs_load=false;c.pf_error=None;return true;}
        let Some((tun,gateway_ips))=c.last_pf.clone() else {return false;};
        c.pf_needs_load=true;
        let split=c.forwarder.is_some();
        let own_dns=c.config.direct_domains.is_some()||c.config.relay.is_some()||split;
        let connected=c.last_allow_direct_egress&&!own_dns;
        let inputs=Inputs {tunnel_if:tun,gateway_ips,physical_if:c.config.physical_if.clone(),allow_networks:c.direct_networks(),allow_dns:false,local_dns_servers:c.local_dns.clone(),tunnel_dns_servers:c.tunnel_dns.clone(),direct_table:split,strict_dns:own_dns,block_direct:split};
        // The base guard is mandatory. Optional routing, journaling and table
        // failures may disable bypasses, never the physical blocking policy.
        if let Some(error)=self.guard.apply(&self.holder,connected,&inputs) {c.pf_error=Some(error.clone());self.report(c,&error);return false;}
        c.pf_needs_load=false;
        if split {c.split_needs_sync=true;}
        c.pf_error=None;true
    }

    fn rearm_direct_after_sync(&self,c:&mut Core)->bool {
        if !c.config.drop_protection || c.stop_requested {return true;}
        let Some((holder,mut inputs))=self.guard.held() else {return c.last_pf.is_none();};
        if holder!=self.holder || !inputs.direct_table || !inputs.block_direct {return true;}
        inputs.block_direct=false;
        if let Some(error)=self.guard.apply(&self.holder,false,&inputs) {c.pf_error=Some(error.clone());self.report(c,&error);return false;}
        true
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
        c.pf_needs_load = false;
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
        if c.pf_needs_load {self.apply_base_pf(c);}
        if c.split_needs_sync {self.sync_split_routes(c);}
        if c.network_routes_error.is_some() || c.routes_need_repoint {self.route_networks_direct(c);}
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
        c.reset_direct_retries();
        network_guard::log(&format!("network changed: now via {interface}"));
        c.physical_gateway = Some(gateway.to_string());
        c.config.physical_if = interface.to_string();
        if move_gateway_route {
            run_script("follow-network", &c.config.script_path, &c.support(), c.config.no_routes, c.config.test_active);
        }
        // The session's direct routes (the split's addresses and the
        // direct networks, §40.1) go via the new router.
        c.routes_need_repoint = true;
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
    #[test]
    fn successful_split_recovery_replaces_a_stale_warning_without_repeated_pushes() {
        let notices=Arc::new(Mutex::new(Vec::<String>::new()));let output=notices.clone();
        let (engine,support)=split_engine_with_hooks("warning-recovery",Hooks {
            state:Box::new(move |_,detail|output.lock().unwrap().push(detail.into())),
            terminal:Box::new(|_|{}),physical_network:Box::new(|_|None),local_dns:Box::new(|_|vec![]),
            system_roots:Box::new(||None),stopped:Box::new(||{}),
        });
        let (message,quiet,preserved)={let mut c=engine.shared.core.lock().unwrap();
            c.pf_error=Some("直连例外清理失败，网络保护状态未确认".into());
            engine.shared.report(&c,c.pf_error.as_deref().unwrap());
            assert!(engine.shared.sync_split_routes(&mut c));assert!(c.pf_error.is_none());
            let message=notices.lock().unwrap().last().cloned().unwrap();
            let before=notices.lock().unwrap().len();
            for _ in 0..4 {assert!(engine.shared.sync_split_routes(&mut c));}
            let quiet=notices.lock().unwrap().len()==before;
            c.pf_error=Some("prior split error".into());c.network_routes_error=Some("直连网段仍待核验".into());
            assert!(engine.shared.sync_split_routes(&mut c));
            let preserved=notices.lock().unwrap().last().is_some_and(|detail|detail=="直连网段仍待核验");
            (message,quiet,preserved)
        };
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
        assert!(!message.contains("失败")&&!message.contains("未确认"),"a recovered structured error must not leave the old status detail visible");
        assert!(quiet,"healthy synchronizations must not add state pushes or wakeups");
        assert!(preserved,"successful host-route recovery cannot hide another pending network error");
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
    fn socket_late_answers_cannot_restore_revoked_routes_or_cross_dns_sessions() {
        use std::net::{TcpListener, TcpStream};

        fn reply(query: &[u8], last: u8) -> Vec<u8> {
            let mut answer = query.to_vec();
            answer[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            answer.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, last]);
            answer
        }
        fn request(tcp: bool, query: &[u8]) -> Option<Vec<u8>> {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 15353);
            if tcp {
                let socket = crate::child_io::socket(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).ok()?;
                socket.connect_timeout(&socket2::SockAddr::from(address), Duration::from_secs(1)).ok()?;
                let mut peer: TcpStream = socket.into();
                peer.set_read_timeout(Some(Duration::from_millis(400))).ok()?;
                peer.set_write_timeout(Some(Duration::from_secs(1))).ok()?;
                dns_forwarder::write_framed(&mut peer, query).ok()?;
                dns_forwarder::read_framed(&mut peer)
            } else {
                let peer = crate::child_io::udp_bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).ok()?;
                peer.set_read_timeout(Some(Duration::from_millis(400))).ok()?;
                peer.send_to(query, address).ok()?;
                let mut bytes = [0; 512];
                let n = peer.recv(&mut bytes).ok()?;
                Some(bytes[..n].to_vec())
            }
        }
        // The production engine listener uses this test-only high port. No
        // real resolver, routing command or PF command is used by this test.
        let reservation = crate::child_io::udp_bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 15353)).unwrap();
        let tcp_reservation = crate::child_io::creation(|| TcpListener::bind((Ipv4Addr::LOCALHOST, 15353))).unwrap();
        drop((reservation, tcp_reservation));
        for client_tcp in [false, true] {
            for upstream_tcp in [false, true] {
                for change in ["rules", "upstreams", "listener"] {
                    // A random UDP port may already carry another test's TCP
                    // socket; pick again until both protocols bind.
                    let (udp, tcp) = (0..200).find_map(|_| {
                        let udp = crate::child_io::udp_bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).ok()?;
                        let address = udp.local_addr().ok()?;
                        let tcp = crate::child_io::creation(|| TcpListener::bind(address)).ok()?;
                        Some((udp, tcp))
                    }).expect("a loopback port free for both UDP and TCP");
                    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let server = udp.local_addr().unwrap();
                    tcp.set_nonblocking(true).unwrap();
                    let (seen_tx, seen_rx) = mpsc::channel();
                    let (release_tx, release_rx) = mpsc::channel();
                    let upstream = std::thread::spawn(move || {
                        for round in 0..3 {
                            let mut bytes = [0; 512];
                            let (n, from) = udp.recv_from(&mut bytes).unwrap();
                            let mut query = bytes[..n].to_vec();
                            let mut stream = if upstream_tcp {
                                let mut truncated = query.clone();
                                truncated[2..12].copy_from_slice(&[0x83, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
                                udp.send_to(&truncated, from).unwrap();
                                let deadline = Instant::now() + Duration::from_secs(2);
                                let mut peer = loop {
                                    match crate::child_io::accept(&tcp) {
                                        Ok((peer, _)) => break peer,
                                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                            assert!(Instant::now() < deadline, "TCP fallback did not arrive");
                                            std::thread::sleep(Duration::from_millis(5));
                                        }
                                        Err(error) => panic!("TCP fallback: {error}"),
                                    }
                                };
                                peer.set_nonblocking(false).unwrap();
                                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                                peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                                query = dns_forwarder::read_framed(&mut peer).unwrap();
                                Some(peer)
                            } else { None };
                            if round == 1 {
                                seen_tx.send(()).unwrap();
                                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                            }
                            let answer = reply(&query, [9, 19, 29][round]);
                            if let Some(peer) = &mut stream {
                                dns_forwarder::write_framed(peer, &answer).unwrap();
                            } else {
                                udp.send_to(&answer, from).unwrap();
                            }
                        }
                    });
                    let (engine, support) = split_engine(&format!("wire-{client_tcp}-{upstream_tcp}-{change}"));
                    let upstreams = || Upstreams {
                        tunnel: vec![server.to_string()], local: vec![server.to_string()],
                        physical_if: None,
                        tunnel_if: Some(if cfg!(target_os = "macos") { "lo0" } else { "lo" }.into()),
                    };
                    {
                        let mut c = engine.shared.core.lock().unwrap();
                        c.config.direct_domains = Some(vec!["full:direct.example".into()]);
                        engine.shared.start_forwarder(&mut c);
                        c.forwarder.as_ref().unwrap().set_upstreams(upstreams());
                    }
                    let query = crate::on_demand::dns_query("direct.example").unwrap();
                    assert_eq!(dns_forwarder::ipv4_answers(&request(client_tcp, &query).unwrap()),
                        vec![Ipv4Addr::new(203, 0, 113, 9)]);
                    assert_eq!(engine.shared.routes.addresses(), vec!["203.0.113.9"]);
                    assert_eq!(engine.shared.guard.direct_addresses(), vec!["203.0.113.9"]);
                    let pending_query = query.clone();
                    let pending = std::thread::spawn(move || request(client_tcp, &pending_query));
                    seen_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    if change == "rules" {
                        engine.update_direct_domains(vec![]);
                        assert!(!dns_event(&engine, 0, "barrier.example", false));
                    } else {
                        let c = engine.shared.core.lock().unwrap();
                        let forwarder = c.forwarder.as_ref().unwrap();
                        if change == "upstreams" { forwarder.set_upstreams(upstreams()); }
                        else { forwarder.stop(); forwarder.start().unwrap(); }
                    }
                    release_tx.send(()).unwrap();
                    let late = pending.join().unwrap();
                    let stale_route = engine.shared.routes.addresses().contains(&"203.0.113.19".into());
                    let stale_permit = engine.shared.guard.direct_addresses().contains(&"203.0.113.19".into());
                    let journal = std::fs::read_to_string(support.join("direct-routes")).unwrap();
                    let withdrawn = !engine.shared.routes.addresses().contains(&"203.0.113.9".into());
                    let fresh = request(client_tcp, &query);
                    upstream.join().unwrap();
                    engine.stop(false, false);
                    assert!(!dns_event(&engine, 0, "barrier.example", false));
                    drop(engine);
                    std::fs::remove_dir_all(support).unwrap();
                    assert!(late.is_none(), "old DNS answer reached {client_tcp}/{upstream_tcp}/{change} client");
                    assert!(!stale_route && !stale_permit && !journal.contains("203.0.113.19"),
                        "late answer recreated a route, PF permission or journal entry");
                    assert!(change != "rules" || withdrawn, "rule removal did not retire the original route");
                    assert_eq!(dns_forwarder::ipv4_answers(&fresh.unwrap()), vec![Ipv4Addr::new(203, 0, 113, 29)],
                        "a fresh query must still work after the transition");
                }
            }
        }
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
    fn static_network_add_and_delete_failures_are_retried_without_changing_intent() {
        let (engine,support)=split_engine("network-retries");
        let fail=Arc::new(AtomicBool::new(true));let f=fail.clone();
        engine.shared.routes.test_commands(Box::new(move |_|if f.load(Ordering::SeqCst){1}else{0}),
            crate::network_check::Output {ok:true,text:"Destination Gateway Flags Netif Expire\n".into()});
        {
            let mut c=engine.shared.core.lock().unwrap();c.config.allow_networks=vec!["198.51.100.0/24".into()];
            engine.shared.route_networks_direct(&mut c);assert!(c.routed_networks.is_empty());assert!(c.network_routes_error.is_some());
            fail.store(false,Ordering::SeqCst);engine.shared.route_networks_direct(&mut c);
            assert!(c.routed_networks.contains("198.51.100.0/24"));assert!(c.network_routes_error.is_none());
            let f=fail.clone();
            engine.shared.routes.test_commands(Box::new(move |_|if f.load(Ordering::SeqCst){1}else{0}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n198.51.100/24 192.168.1.1 UGSc en0\n".into()});
            c.config.allow_networks.clear();fail.store(true,Ordering::SeqCst);engine.shared.route_networks_direct(&mut c);
            assert!(c.routed_networks.contains("198.51.100.0/24"));assert!(c.network_routes_error.is_some());
            fail.store(false,Ordering::SeqCst);engine.shared.route_networks_direct(&mut c);
            assert!(c.routed_networks.is_empty());assert!(c.network_routes_error.is_none());
        }
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn gateway_repoint_failure_remains_pending_until_the_same_network_refresh_retries() {
        let (engine,support)=split_engine("repoint-retry");
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine,epoch,"direct.example",true));
        let fail=Arc::new(AtomicBool::new(true));let failure=fail.clone();
        engine.shared.routes.test_commands(Box::new(move |_|if failure.load(Ordering::SeqCst){1}else{0}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n".into()});
        {
            let mut c=engine.shared.core.lock().unwrap();c.physical_gateway=Some("192.168.2.1".into());c.routes_need_repoint=true;
            assert!(!engine.shared.sync_split_routes(&mut c));assert!(c.routes_need_repoint);assert!(c.network_routes_error.is_some());
            fail.store(false,Ordering::SeqCst);
            assert!(engine.shared.sync_split_routes(&mut c));assert!(!c.routes_need_repoint);
            engine.shared.route_networks_direct(&mut c);assert!(c.network_routes_error.is_none());
            assert!(std::fs::read_to_string(support.join("direct-routes")).unwrap().contains("203.0.113.9 192.168.2.1"));
        }
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn connect_rechecks_routes_after_unknown_gateway_or_interface_only_change() {
        let (engine,support)=split_engine("hook-path-recheck");
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine,epoch,"direct.example",true));
        {
            let mut c=engine.shared.core.lock().unwrap();c.physical_gateway=None;
            engine.shared.handle_hook(&mut c,"connect tun=lo0 gateway=198.51.100.1 phys=en0 physgw=192.168.2.1");
            assert!(!c.routes_need_repoint);
            assert!(std::fs::read_to_string(support.join("direct-routes")).unwrap().contains("203.0.113.9 192.168.2.1"));
            // Same gateway, different physical interface: the journal must
            // be checked again, not skipped because the address is unchanged.
            let path=support.join("direct-routes");std::fs::remove_file(&path).unwrap();std::fs::create_dir(&path).unwrap();
            engine.shared.handle_hook(&mut c,"connect tun=lo0 gateway=198.51.100.1 phys=en5 physgw=192.168.2.1");
            assert!(c.routes_need_repoint);assert!(c.network_routes_error.is_some());
            std::fs::remove_dir(&path).unwrap();
        }
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn optional_route_failure_keeps_initial_and_reenabled_base_protection() {
        use std::os::unix::fs::PermissionsExt;
        let support=std::env::temp_dir().join(format!("ac-base-protection-{}",std::process::id()));
        let _=std::fs::remove_dir_all(&support);std::fs::create_dir_all(&support).unwrap();
        let tool=support.join("pfctl-stub");
        std::fs::write(&tool,"#!/bin/sh\nif [ \"$1\" = -E ]; then echo 'Token : 123' >&2; fi\ncase \"$*\" in *delete*|*replace*|*flush*) [ ! -f \"$0.fail\" ] || exit 1;; esac\ncat >/dev/null\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool,std::fs::Permissions::from_mode(0o700)).unwrap();
        let guard=Arc::new(Guard::new(network_guard::Settings {support_dir:support.clone(),boot:Some("B1".into()),grace:Duration::from_secs(120),pfctl:Some(tool.to_string_lossy().into())}));
        guard.owner_attached();
        let engine=Engine::new(Config {no_routes:true,test_active:true,support_dir:support.to_string_lossy().into(),boot_session:"B1".into(),script_path:"/usr/bin/true".into(),drop_protection:true,..Config::default()},Hooks {
            state:Box::new(|_,_|{}),terminal:Box::new(|_|{}),physical_network:Box::new(|_|None),local_dns:Box::new(|_|vec![]),system_roots:Box::new(||None),stopped:Box::new(||{}),
        },guard);
        {
            let mut c=engine.shared.core.lock().unwrap();c.physical_gateway=Some("192.168.1.1".into());
            c.forwarder=Some(Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),53,Duration::from_millis(50),vec!["direct.example".into()],Upstreams {tunnel:vec![],local:vec![],physical_if:None,tunnel_if:None},None));
        }
        engine.shared.routes.test_commands(Box::new(|_|1),crate::network_check::Output::default());
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(!dns_event(&engine,epoch,"direct.example",true));
        {
            let mut c=engine.shared.core.lock().unwrap();
            engine.shared.handle_hook(&mut c,"connect tun=lo0 gateway=198.51.100.1 phys=en0 physgw=192.168.1.1");
            assert!(engine.shared.guard.is_holding(),"optional failure must not skip base PF");
            assert!(c.last_pf.is_some());
            assert!(engine.shared.guard.direct_addresses().is_empty(),"failed optional installs must grant no dynamic address");
            assert!(c.pf_error.as_deref().unwrap().contains("直连路由安装失败"));
            engine.shared.update_drop_protection(&mut c,false);assert!(!engine.shared.guard.is_holding());
            engine.shared.update_drop_protection(&mut c,true);assert!(engine.shared.guard.is_holding());
            c.split_policy=crate::split_policy::SplitPolicy::default();
            engine.shared.load_pf(&mut c,Some("lo0".into()),vec!["198.51.100.1".into()],false);
            assert!(engine.shared.guard.expected_rules().unwrap().contains("pass out quick to <ac_direct>"));
            assert!(engine.shared.guard.add_direct(&["203.0.113.9".into()]));
            let failure=tool.with_extension("fail");std::fs::write(&failure,"").unwrap();
            assert!(!engine.shared.sync_split_routes(&mut c));
            assert!(engine.shared.guard.is_holding());
            assert!(!engine.shared.guard.expected_rules().unwrap().contains("pass out quick to <ac_direct>"),"table revocation failure must disable dynamic bypasses");
            std::fs::remove_file(failure).unwrap();
            assert!(engine.shared.sync_split_routes(&mut c));assert!(c.pf_error.is_none());
            // Table replacement failure while enabling exceptions also keeps
            // the already-loaded conservative base set in force.
            let failure=tool.with_extension("fail");std::fs::write(&failure,"").unwrap();
            let (_,inputs)=engine.shared.guard.held().unwrap();
            assert!(engine.shared.guard.apply(&engine.holder(),false,&inputs).is_some());
            assert!(!engine.shared.guard.expected_rules().unwrap().contains("pass out quick to <ac_direct>"));
            std::fs::remove_file(failure).unwrap();
        }
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
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
    fn recovery_guard(name: &str) -> (std::path::PathBuf, Arc<Guard>, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let support=std::env::temp_dir().join(format!("ac-r3-{name}-{}",std::process::id()));
        std::fs::create_dir_all(&support).unwrap();
        let tool=support.join("pfctl-stub");
        std::fs::write(&tool,"#!/bin/sh\nif [ \"$1\" = -E ];then echo 'Token : 99' >&2;fi\ncase \"$*\" in *'-f -'*) [ ! -f \"$0.fail\" ] || exit 1;;esac\ncat >/dev/null\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool,std::fs::Permissions::from_mode(0o700)).unwrap();
        let guard=Arc::new(Guard::new(network_guard::Settings {support_dir:support.clone(),boot:Some("B1".into()),grace:Duration::from_secs(120),pfctl:Some(tool.to_string_lossy().into())}));
        guard.owner_attached();(support,guard,tool)
    }
    fn recovery_engine(support: &Path,guard: Arc<Guard>)->Engine {
        Engine::new(Config {no_routes:true,test_active:true,support_dir:support.to_string_lossy().into(),boot_session:"B1".into(),script_path:"/usr/bin/true".into(),physical_if:"en0".into(),drop_protection:true,direct_domains:Some(vec![]),..Config::default()},Hooks {
            state:Box::new(|_,_|{}),terminal:Box::new(|_|{}),physical_network:Box::new(|_|Some(("192.168.1.1".into(),"en0".into()))),local_dns:Box::new(|_|vec![]),system_roots:Box::new(||None),stopped:Box::new(||{}),
        },guard)
    }
    #[test]
    fn failed_split_forwarder_keeps_physical_blocking_and_gateway_dns_fallback() {
        let (support,guard,_)=recovery_guard("forwarder-fallback");
        let engine=recovery_engine(&support,guard.clone());
        let rules={
            let mut c=engine.shared.core.lock().unwrap();
            c.forwarder=None;
            c.tunnel_dns=vec!["10.1.1.1".into()];
            engine.shared.load_pf(&mut c,Some("utun5".into()),vec!["198.51.100.1".into()],true);
            guard.expected_rules().unwrap()
        };
        assert!(rules.ends_with("block drop out quick all\n"),
            "a failed optional forwarder must not open unlisted physical TCP/UDP");
        assert!(rules.contains("on utun5 proto { udp tcp } to 10.1.1.1 port 53 no state"),
            "the system resolver must retain the current gateway DNS path");
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);
        std::fs::remove_dir_all(support).unwrap();
    }
    #[test]
    fn live_takeover_with_empty_list_keeps_old_exceptions_disabled() {
        let (support,guard,_)=recovery_guard("takeover");
        let old=guard.new_own_holder();
        let inputs=Inputs {tunnel_if:"utun5".into(),physical_if:"en0".into(),gateway_ips:vec!["198.51.100.1".into()],allow_networks:vec!["198.51.100.0/24".into()],direct_table:true,strict_dns:true,..Inputs::default()};
        assert!(guard.apply(&old,false,&inputs).is_none());
        assert!(guard.add_direct(&["203.0.113.9".into()]));
        let engine=recovery_engine(&support,guard.clone());
        let enabled={let mut c=engine.shared.core.lock().unwrap();engine.shared.take_over_held_set(&mut c);
            assert!(guard.held().unwrap().1.allow_networks.is_empty(),"empty current list must also revoke old static exceptions");
            guard.expected_rules().unwrap().contains("pass out quick to <ac_direct>")};
        eprintln!("R3 takeover: old IPs={:?}; new empty list; dynamic pass={enabled}",guard.direct_addresses());
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);
        std::fs::remove_dir_all(&support).unwrap();
        assert!(!enabled,"replacement has not reconciled its empty policy, but old dynamic bypass was reenabled");
    }
    #[test]
    fn base_load_failure_recovers_on_unchanged_network_and_accepts_dns() {
        let (support,guard,tool)=recovery_guard("base-retry");
        let engine=recovery_engine(&support,guard.clone());
        std::fs::write(tool.with_extension("fail"),"").unwrap();
        let recovered={
            let mut c=engine.shared.core.lock().unwrap();c.physical_gateway=Some("192.168.1.1".into());
            c.forwarder=Some(Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),53,Duration::from_millis(10),vec![],Upstreams{tunnel:vec![],local:vec![],physical_if:None,tunnel_if:None},None));
            engine.shared.load_pf(&mut c,Some("utun5".into()),vec!["198.51.100.1".into()],false);
            assert!(c.last_pf.is_some() && c.pf_error.is_some() && !guard.is_holding());
            std::fs::remove_file(tool.with_extension("fail")).unwrap();
            engine.shared.refresh_network(&mut c);
            assert!(guard.is_holding(),"unchanged network refresh alone must retry the mandatory load");
            eprintln!("R3 base retry: holding={}; split_needs_sync={}; error={:?}",guard.is_holding(),c.split_needs_sync,c.pf_error);
            guard.is_holding()
        };
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        let accepted=dns_event(&engine,epoch,"vpn.example",false);
        eprintln!("R3 actual DNS queue reply accepted={accepted}");
        { let mut c=engine.shared.core.lock().unwrap();engine.shared.load_pf(&mut c,Some("utun5".into()),vec!["198.51.100.1".into()],false);assert!(guard.is_holding(),"positive control: kernel stub has recovered"); }
        eprintln!("R3 positive control: explicit load_pf succeeds after fault removed");
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);
        std::fs::remove_dir_all(&support).unwrap();
        assert!(recovered,"successful later kernel operations never reinstall the saved base PF intent");
    }

    #[test]
    fn dns_acknowledgement_retries_base_without_waiting_for_a_network_event() {
        let (support,guard,tool)=recovery_guard("dns-base-retry");
        let engine=recovery_engine(&support,guard.clone());
        std::fs::write(tool.with_extension("fail"),"").unwrap();
        let epoch={let mut c=engine.shared.core.lock().unwrap();
            c.physical_gateway=Some("192.168.1.1".into());
            c.split_policy.observe("vpn.example".into(),&["203.0.113.9".parse().unwrap()],&[]);
            c.forwarder=Some(Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),53,Duration::from_millis(10),vec![],Upstreams{tunnel:vec![],local:vec![],physical_if:None,tunnel_if:None},None));
            engine.shared.load_pf(&mut c,Some("utun5".into()),vec!["198.51.100.1".into()],false);
            assert!(c.pf_needs_load);c.forwarder.as_ref().unwrap().epoch()};
        std::fs::remove_file(tool.with_extension("fail")).unwrap();
        assert!(dns_event(&engine,epoch,"vpn.example",false));assert!(guard.is_holding());
        {let mut c=engine.shared.core.lock().unwrap();assert!(!c.pf_needs_load);engine.shared.update_drop_protection(&mut c,false);engine.shared.refresh_network(&mut c);assert!(!guard.is_holding());}
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn one_failed_direct_install_does_not_block_unrelated_vpn_answers() {
        let (engine,support)=split_engine("claude-optional-poison");
        engine.shared.routes.test_commands(Box::new(|args|if args.contains(&"add"){1}else{0}),
            crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.9.1 UGHS en0\n".into()});
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(!dns_event(&engine,epoch,"direct.example",true));
        let mut accepted=0;
        for n in 0..5 {
            let (tx,rx)=mpsc::channel();
            engine.send(Event::DnsAnswer(dns_forwarder::Observation{epoch,name:format!("vpn{n}.example"),entry:None,
                addresses:vec![Ipv4Addr::new(198,51,100,10+n)],direct:vec![]},tx));
            if rx.recv_timeout(Duration::from_secs(2)).unwrap(){accepted+=1;}
        }
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
        assert_eq!(accepted,5,"optional direct conflict must not poison unrelated VPN DNS");
    }

    #[test]
    fn saturated_split_policy_is_reported_to_the_panel() {
        let (engine,support)=split_engine("claude-capacity-notice");
        {let mut c=engine.shared.core.lock().unwrap();
            for n in 0..4097u32 {c.split_policy.observe(format!("{n}.vpn.example"),&[Ipv4Addr::new(198,18,(n>>8) as u8,n as u8)],&[]);}
        }
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine,epoch,"after-limit.example",false));
        let shown=engine.shared.info.lock().unwrap().last_error.clone();
        let panel=serde_json::to_value(&*engine.shared.info.lock().unwrap()).unwrap();
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
        assert!(shown.is_some_and(|s|s.contains("容量")),"safe capacity fallback must be visible");
        assert!(panel["splitWarning"].as_str().is_some_and(|s|s.contains("容量")),"panel warning must have a dedicated transport field");
    }

    #[test]
    fn failed_optional_address_does_not_revoke_working_direct_addresses() {
        let (engine,support)=split_engine("claude-partial-grants");
        engine.shared.routes.test_commands(Box::new(|args|if args.contains(&"203.0.113.9")&&args.contains(&"add"){1}else{0}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n".into()});
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(!dns_event(&engine,epoch,"bad.direct.example",true));
        let (tx,rx)=mpsc::channel();engine.send(Event::DnsAnswer(dns_forwarder::Observation{epoch,name:"good.direct.example".into(),entry:Some("direct.example".into()),addresses:vec![Ipv4Addr::new(203,0,113,10)],direct:vec![Ipv4Addr::new(203,0,113,10)]},tx));
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
        assert_eq!(engine.shared.guard.direct_addresses(),vec!["203.0.113.10"]);
        assert_eq!(engine.shared.routes.addresses(),vec!["203.0.113.10"]);
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn failed_revocation_blocks_only_the_affected_vpn_answer() {
        let (engine,support)=split_engine("claude-revocation-isolation");
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(dns_event(&engine,epoch,"direct.example",true));
        engine.shared.routes.test_commands(Box::new(|_|1),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n".into()});
        assert!(!dns_event(&engine,epoch,"shared-vpn.example",false));
        let (tx,rx)=mpsc::channel();engine.send(Event::DnsAnswer(dns_forwarder::Observation{epoch,name:"unrelated-vpn.example".into(),entry:None,addresses:vec![Ipv4Addr::new(198,51,100,10)],direct:vec![]},tx));
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
        engine.shared.routes.test_commands(Box::new(|_|0),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n".into()});
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn recovery_intents_do_not_claim_that_the_network_is_still_blocked() {
        let support=std::env::temp_dir().join(format!("ac-held-intent-{}",std::process::id()));
        std::fs::create_dir_all(&support).unwrap();
        for row in ["install 203.0.113.9 192.168.1.1","retire 203.0.113.9 192.168.1.1","203.0.113.9 192.168.1.1"] {
            std::fs::write(support.join("direct-routes"),format!("boot B1\n{row}\n")).unwrap();
            assert!(!local_network_held(&support),"a cleanup-only host route journal is not a blocking policy");
            assert!(support.join("direct-routes").exists(),"diagnostic ownership evidence must remain intact");
        }
        std::fs::write(route_state_path(&support),"AC_BOOT=B1\n").unwrap();
        assert!(local_network_held(&support),"the default-route/DNS journal still indicates unrestored network state");
        std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn installed_route_with_unconfirmed_metadata_is_not_published_as_direct() {
        let (engine,support)=split_engine("claude-partial-journal");
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        direct_routes::set_test_journal_write_budget(&engine.shared.routes,Some(1));
        let granted=dns_event(&engine,epoch,"direct.example",true);
        direct_routes::set_test_journal_write_budget(&engine.shared.routes,None);
        {let mut c=engine.shared.core.lock().unwrap();for retry in c.direct_retries.values_mut(){retry.until=Instant::now()-Duration::from_secs(1);}}
        assert!(!granted,"kernel success alone cannot override a failed route transaction");
        assert!(engine.shared.guard.direct_addresses().is_empty());
        assert!(dns_event(&engine,epoch,"direct.example",true),"after metadata recovery the same query can become direct");
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn a_partially_applied_pf_add_is_removed_before_unrelated_answers_continue() {
        use std::os::unix::fs::PermissionsExt;
        let (support,guard,tool)=recovery_guard("partial-pf-add");
        std::fs::write(&tool,r#"#!/bin/sh
D=$(dirname "$0")
if [ "$1" = -E ];then echo 'Token : 123' >&2;exit 0;fi
if [ "$3" = -f ];then cat > "$D/rules";exit 0;fi
if [ "$5" = -T ];then
 op=$6;shift 6
 case "$op" in replace|flush) : > "$D/table";;esac
 case "$op" in add|replace) for ip do echo "$ip" >> "$D/table";done;;esac
 if [ "$op" = add ] && [ -f "$D/fail-add" ];then exit 1;fi
fi
exit 0
"#).unwrap();std::fs::set_permissions(&tool,std::fs::Permissions::from_mode(0o700)).unwrap();
        let engine=recovery_engine(&support,guard.clone());
        let epoch={let mut c=engine.shared.core.lock().unwrap();c.physical_gateway=Some("192.168.1.1".into());
            c.forwarder=Some(Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0),53,Duration::from_millis(50),vec!["direct.example".into()],Upstreams{tunnel:vec![],local:vec![],physical_if:None,tunnel_if:None},None));
            engine.shared.load_pf(&mut c,Some("lo0".into()),vec!["198.51.100.1".into()],false);c.forwarder.as_ref().unwrap().epoch()};
        std::fs::write(support.join("fail-add"),"").unwrap();
        assert!(!dns_event(&engine,epoch,"direct.example",true));
        assert!(dns_event(&engine,epoch,"vpn.example",false));
        let table=std::fs::read_to_string(support.join("table")).unwrap();
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);
        assert!(!table.contains("203.0.113.9"),"a failed add must not leave an untracked kernel permission");
        std::fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn repeated_direct_conflicts_are_rate_limited_and_show_the_affected_name() {
        let (engine,support)=split_engine("review2-retry-rate");
        let attempts=Arc::new(std::sync::atomic::AtomicUsize::new(0));let count=attempts.clone();
        let conflict=Arc::new(AtomicBool::new(true));let blocked=conflict.clone();
        engine.shared.routes.test_commands(Box::new(move |args| {
            if args.contains(&"add")&&args.contains(&"203.0.113.9") {count.fetch_add(1,Ordering::SeqCst);if blocked.load(Ordering::SeqCst){1}else{0}}else{0}
        }),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.9.1 UGHS en0\n".into()});
        let epoch=engine.shared.core.lock().unwrap().forwarder.as_ref().unwrap().epoch();
        assert!(!dns_event(&engine,epoch,"direct.example",true));
        {let mut c=engine.shared.core.lock().unwrap();for retry in c.direct_retries.values_mut(){retry.until=Instant::now()+Duration::from_secs(60);}}
        for _ in 0..4 {assert!(!dns_event(&engine,epoch,"direct.example",true));}
        assert_eq!(attempts.load(Ordering::SeqCst),1,"client retries within a backoff window must not execute more route commands");
        assert!(engine.info().split_warning.is_some_and(|s|s.contains("direct.example")),"the panel must name the affected website");
        // A new, unrelated direct IP may proceed while the old one cools down.
        let (tx,rx)=mpsc::channel();engine.send(Event::DnsAnswer(dns_forwarder::Observation{epoch,name:"good.direct.example".into(),entry:Some("direct.example".into()),addresses:vec![Ipv4Addr::new(203,0,113,10)],direct:vec![Ipv4Addr::new(203,0,113,10)]},tx));
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());assert_eq!(attempts.load(Ordering::SeqCst),1);
        // Advance the retry clock without wall-clock sleeps, checking that
        // repeated failures remain bounded rather than growing without limit.
        for _ in 0..8 {
            {let mut c=engine.shared.core.lock().unwrap();for retry in c.direct_retries.values_mut(){retry.until=Instant::now()-Duration::from_secs(1);}}
            assert!(!dns_event(&engine,epoch,"direct.example",true));
            let c=engine.shared.core.lock().unwrap();assert!(c.direct_retries.values().all(|retry|retry.until<=Instant::now()+Duration::from_secs(60)));
        }
        assert_eq!(attempts.load(Ordering::SeqCst),9);
        conflict.store(false,Ordering::SeqCst);
        {let mut c=engine.shared.core.lock().unwrap();for retry in c.direct_retries.values_mut(){retry.until=Instant::now()-Duration::from_secs(1);}}
        assert!(dns_event(&engine,epoch,"direct.example",true));
        assert!(!dns_event(&engine,0,"publication-barrier.example",false));
        assert!(engine.info().split_warning.is_none());
        assert_eq!(engine.shared.core.lock().unwrap().direct_retries.capacity(),0,"recovered retry state must release its allocation");
        engine.stop(false,false);assert!(!dns_event(&engine,0,"barrier.example",false));drop(engine);std::fs::remove_dir_all(support).unwrap();
    }

}
