//! C ABI for the Swift app shell.
//!
//! The Swift side holds an opaque `ac_engine_t` handle. All functions are
//! null-safe and return -1 on bad input; direction codes are 0 = VPN,
//! 1 = direct. Rule and engine state live behind a Mutex, so the handle
//! is safe to share across threads.

use crate::rules::{self, DefaultMode, Direction, Rule, RuleType};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;

pub struct Engine {
    rules: Mutex<Vec<Rule>>,
    default: DefaultMode,
}

/// Engine version string (static, never freed by the caller).
#[no_mangle]
pub extern "C" fn ac_version() -> *const c_char {
    b"0.1.0\0".as_ptr() as *const c_char
}

/// default_mode: 0 = secure (default VPN), 1 = split (default direct).
/// Returns a null pointer on an invalid mode.
#[no_mangle]
pub extern "C" fn ac_engine_new(default_mode: c_int) -> *mut Engine {
    let default = match default_mode {
        0 => DefaultMode::Secure,
        1 => DefaultMode::Split,
        _ => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(Engine {
        rules: Mutex::new(Vec::new()),
        default,
    }))
}

/// rule_type: 0 = app, 1 = domain, 2 = network.
/// direction: 0 = VPN, 1 = direct. Returns 0 on success, -1 on bad input.
#[no_mangle]
pub extern "C" fn ac_engine_add_rule(
    engine: *mut Engine,
    rule_type: c_int,
    target: *const c_char,
    direction: c_int,
    enabled: bool,
) -> c_int {
    if engine.is_null() || target.is_null() {
        return -1;
    }
    let rule_type = match rule_type {
        0 => RuleType::App,
        1 => RuleType::Domain,
        2 => RuleType::Network,
        _ => return -1,
    };
    let direction = match direction {
        0 => Direction::Vpn,
        1 => Direction::Direct,
        _ => return -1,
    };
    let target = unsafe {
        match CStr::from_ptr(target).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return -1,
        }
    };
    let engine = unsafe { &*engine };
    engine.rules.lock().unwrap().push(Rule {
        rule_type,
        target,
        direction,
        enabled,
    });
    0
}

/// Returns 0 (VPN), 1 (direct), or -1 on bad input.
#[no_mangle]
pub extern "C" fn ac_engine_resolve(
    engine: *mut Engine,
    app: *const c_char,
    domain: *const c_char,
    ip: *const c_char,
) -> c_int {
    if engine.is_null() || app.is_null() || domain.is_null() || ip.is_null() {
        return -1;
    }
    let read = |p: *const c_char| unsafe { CStr::from_ptr(p).to_str().ok() };
    let (Some(app), Some(domain), Some(ip)) = (read(app), read(domain), read(ip)) else {
        return -1;
    };
    let engine = unsafe { &*engine };
    let rules = engine.rules.lock().unwrap();
    match rules::resolve(app, domain, ip, &rules, engine.default).0 {
        Direction::Vpn => 0,
        Direction::Direct => 1,
    }
}

/// Like ac_engine_resolve, but also writes the machine-readable reason
/// code (see rules::resolve: "lan-hard-rule", "app-rule",
/// "app-conflict->vpn", "domain-rule", "domain-conflict->vpn",
/// "network-rule", "network-conflict->vpn", "default-secure",
/// "default-split") into out_reason as a NUL-terminated string,
/// truncated to buf_len - 1 bytes when the buffer is short.
/// Returns 0 (VPN), 1 (direct), or -1 on bad input (null engine,
/// null inputs, or null/zero-length reason buffer); on -1 nothing is
/// written. The rule tester UI shows direction + reason together.
#[no_mangle]
pub extern "C" fn ac_engine_resolve_detail(
    engine: *mut Engine,
    app: *const c_char,
    domain: *const c_char,
    ip: *const c_char,
    out_reason: *mut c_char,
    buf_len: usize,
) -> c_int {
    if engine.is_null()
        || app.is_null()
        || domain.is_null()
        || ip.is_null()
        || out_reason.is_null()
        || buf_len == 0
    {
        return -1;
    }
    let read = |p: *const c_char| unsafe { CStr::from_ptr(p).to_str().ok() };
    let (Some(app), Some(domain), Some(ip)) = (read(app), read(domain), read(ip)) else {
        return -1;
    };
    let engine = unsafe { &*engine };
    let rules = engine.rules.lock().unwrap();
    let (direction, reason) = rules::resolve(app, domain, ip, &rules, engine.default);
    let bytes = reason.as_bytes();
    let writable = buf_len - 1;
    let n = bytes.len().min(writable);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_reason as *mut u8, n);
        *out_reason.add(n) = 0;
    }
    match direction {
        Direction::Vpn => 0,
        Direction::Direct => 1,
    }
}

#[no_mangle]
pub extern "C" fn ac_engine_free(engine: *mut Engine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

// ---- Session driver (core/src/session.rs) ----
//
// Action codes returned by every ac_session_* call:
//   0 = NoAction, 1 = ReconnectInProcess, 2 = Reauthenticate,
//   3 = WaitApproval, 4 = StopNeedsUser, 5 = TornDown, 6 = Ignored.
// The delay/timeout seconds for actions 1/2/3 are written to
// `delay_secs_out` when it is non-null, else ignored.
// State codes (ac_session_state):
//   0 = Disconnected, 1 = Connecting, 2 = Authenticating,
//   3 = AwaitingApproval, 4 = Connected, 5 = Reconnecting; -1 on null.
// AuthOutcome codes in: 0 = Success, 1 = NeedsApproval, 2 = Rejected,
// 3 = Transient; any other code returns Ignored and leaves the driver
// untouched. Null handles return Ignored (state: -1) and never crash.

use crate::session::{AuthOutcome, DriverAction, SessionDriver};
use crate::state_machine::SessionStatus;

pub struct SessionHandle {
    driver: Mutex<SessionDriver>,
}

fn encode_action(action: DriverAction, delay_secs_out: *mut f64) -> c_int {
    let (code, secs) = match action {
        DriverAction::NoAction => (0, 0.0),
        DriverAction::ReconnectInProcess { delay } => (1, delay.as_secs_f64()),
        DriverAction::Reauthenticate { delay } => (2, delay.as_secs_f64()),
        DriverAction::WaitApproval { timeout } => (3, timeout.as_secs_f64()),
        DriverAction::StopNeedsUser => (4, 0.0),
        DriverAction::TornDown => (5, 0.0),
        DriverAction::Ignored => (6, 0.0),
    };
    if !delay_secs_out.is_null() {
        unsafe {
            *delay_secs_out = secs;
        }
    }
    code
}

fn encode_state(state: SessionStatus) -> c_int {
    match state {
        SessionStatus::Disconnected => 0,
        SessionStatus::Connecting => 1,
        SessionStatus::Authenticating => 2,
        SessionStatus::AwaitingApproval => 3,
        SessionStatus::Connected => 4,
        SessionStatus::Reconnecting => 5,
    }
}

#[no_mangle]
pub extern "C" fn ac_session_new(seed: u64) -> *mut SessionHandle {
    Box::into_raw(Box::new(SessionHandle {
        driver: Mutex::new(SessionDriver::new(seed)),
    }))
}

#[no_mangle]
pub extern "C" fn ac_session_free(handle: *mut SessionHandle) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
    }
}

#[no_mangle]
pub extern "C" fn ac_session_state(handle: *mut SessionHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    encode_state(handle.driver.lock().unwrap().state)
}

#[no_mangle]
pub extern "C" fn ac_session_start(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().start();
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_authenticated(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_authenticated();
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_drop(
    handle: *mut SessionHandle,
    cookie_alive: bool,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle
        .driver
        .lock()
        .unwrap()
        .on_drop(cookie_alive);
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_reconnected(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_reconnected();
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_auth_outcome(
    handle: *mut SessionHandle,
    outcome: c_int,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let outcome = match outcome {
        0 => AuthOutcome::Success,
        1 => AuthOutcome::NeedsApproval,
        2 => AuthOutcome::Rejected,
        3 => AuthOutcome::Transient,
        _ => return 6,
    };
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_auth_outcome(outcome);
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_approved(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_approved();
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_approval_timeout(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_approval_timeout();
    encode_action(action, delay_secs_out)
}

#[no_mangle]
pub extern "C" fn ac_session_manual_disconnect(
    handle: *mut SessionHandle,
    delay_secs_out: *mut f64,
) -> c_int {
    if handle.is_null() {
        return 6;
    }
    let handle = unsafe { &*handle };
    let action = handle.driver.lock().unwrap().on_manual_disconnect();
    encode_action(action, delay_secs_out)
}

// ---- pf anchor generation (core/src/pf.rs) ----
//
// ac_pf_generate returns a malloc'd C string the caller frees with
// ac_string_free, or null on bad input (null pointers, non-UTF8,
// invalid networks/IPs, empty gateway list). The three list arguments
// (gateways, allowed networks, local DNS servers) are comma-separated;
// surrounding whitespace is trimmed; an empty allow or DNS list is
// valid. The final argument is a flag set: bit 0 selects the connected
// set (DESIGN.md §17.5; 0 = blocking set, the fail-closed default),
// bit 1 lets DNS out to any address (§二十一), bit 2 declares and
// passes the direct-address table <ac_direct> (plan v2, §25.8).

use crate::pf::{PfInput, PfError};
use std::ffi::CString;

fn split_csv(s: &str) -> Vec<String> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .collect()
}

fn read_cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p).to_str().ok().map(|s| s.to_owned()) }
}

#[no_mangle]
pub extern "C" fn ac_pf_generate(
    physical_if: *const c_char,
    tunnel_if: *const c_char,
    gateway_ips_csv: *const c_char,
    allow_networks_csv: *const c_char,
    dns_servers_csv: *const c_char,
    flags: i32,
) -> *mut c_char {
    let (
        Some(physical_if),
        Some(tunnel_if),
        Some(gateway_ips_csv),
        Some(allow_networks_csv),
        Some(dns_servers_csv),
    ) = (
        read_cstr(physical_if),
        read_cstr(tunnel_if),
        read_cstr(gateway_ips_csv),
        read_cstr(allow_networks_csv),
        read_cstr(dns_servers_csv),
    ) else {
        return std::ptr::null_mut();
    };
    let input = PfInput {
        physical_if,
        tunnel_if,
        gateway_ips: split_csv(&gateway_ips_csv),
        allow_networks: split_csv(&allow_networks_csv),
        allow_direct_egress: flags & 1 != 0,
        allow_dns: flags & 2 != 0,
        dns_servers: split_csv(&dns_servers_csv),
        direct_table: flags & 4 != 0,
    };
    match crate::pf::generate(&input) {
        Ok(text) => match CString::new(text) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(PfError::EmptyInterface)
        | Err(PfError::EmptyGateway)
        | Err(PfError::BadNetwork(_))
        | Err(PfError::BadIp(_)) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ac_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn ffi_round_trip() {
        let e = ac_engine_new(0);
        assert!(!e.is_null());
        let app = c("com.example.workapp");
        let dom = c("a.video.example");
        let tgt = c("*.video.example");
        assert_eq!(ac_engine_add_rule(e, 1, tgt.as_ptr(), 1, true), 0);
        let ip = c("1.2.3.4");
        // Domain rule says direct...
        assert_eq!(
            ac_engine_resolve(e, c("other.app").as_ptr(), dom.as_ptr(), ip.as_ptr()),
            1
        );
        // ...but the LAN hard rule still wins.
        let lan = c("192.168.1.1");
        assert_eq!(
            ac_engine_resolve(e, app.as_ptr(), dom.as_ptr(), lan.as_ptr()),
            1
        );
        // Bad input is rejected, not a crash.
        assert_eq!(
            ac_engine_resolve(
                std::ptr::null_mut(),
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr()
            ),
            -1
        );
        assert_eq!(ac_engine_new(9), std::ptr::null_mut());
        ac_engine_free(e);
    }

    #[test]
    fn ffi_resolve_detail_reason_codes() {
        let e = ac_engine_new(0);
        assert!(!e.is_null());
        let app = c("com.example.app");
        let dom = c("a.video.example");
        let ip = c("1.2.3.4");
        let mut buf = vec![0i8; 64];
        let reason = |buf: &[i8]| unsafe {
            CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_owned()
        };
        // No rule yet: secure default.
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                buf.as_mut_ptr(),
                buf.len()
            ),
            0
        );
        assert_eq!(reason(&buf), "default-secure");
        // Domain rule matches.
        assert_eq!(
            ac_engine_add_rule(e, 1, c("*.video.example").as_ptr(), 1, true),
            0
        );
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                buf.as_mut_ptr(),
                buf.len()
            ),
            1
        );
        assert_eq!(reason(&buf), "domain-rule");
        // LAN hard rule beats the domain rule.
        let lan = c("192.168.1.1");
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                lan.as_ptr(),
                buf.as_mut_ptr(),
                buf.len()
            ),
            1
        );
        assert_eq!(reason(&buf), "lan-hard-rule");
        // Same app target on both sides: conflict fails closed to VPN.
        assert_eq!(
            ac_engine_add_rule(e, 0, app.as_ptr(), 0, true),
            0
        );
        assert_eq!(
            ac_engine_add_rule(e, 0, app.as_ptr(), 1, true),
            0
        );
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                buf.as_mut_ptr(),
                buf.len()
            ),
            0
        );
        assert_eq!(reason(&buf), "app-conflict->vpn");
        // Short buffer truncates the reason but keeps the direction
        // and the NUL terminator.
        let mut small = vec![0i8; 4];
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                small.as_mut_ptr(),
                small.len()
            ),
            0
        );
        assert_eq!(reason(&small), "app");
        // Bad input: nothing written, no crash.
        assert_eq!(
            ac_engine_resolve_detail(
                std::ptr::null_mut(),
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                buf.as_mut_ptr(),
                buf.len()
            ),
            -1
        );
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                std::ptr::null_mut(),
                64
            ),
            -1
        );
        assert_eq!(
            ac_engine_resolve_detail(
                e,
                app.as_ptr(),
                dom.as_ptr(),
                ip.as_ptr(),
                buf.as_mut_ptr(),
                0
            ),
            -1
        );
        ac_engine_free(e);
    }

    #[test]
    fn session_abi_full_flow() {
        let h = ac_session_new(42);
        assert!(!h.is_null());
        let mut delay = -1.0f64;
        assert_eq!(ac_session_start(h, &mut delay), 0);
        assert_eq!(ac_session_state(h), 1);
        assert_eq!(ac_session_authenticated(h, &mut delay), 0);
        assert_eq!(ac_session_state(h), 2);
        assert_eq!(ac_session_auth_outcome(h, 0, &mut delay), 0);
        assert_eq!(ac_session_state(h), 4);
        // Drop with a live in-process cookie: reconnect in process.
        assert_eq!(ac_session_drop(h, true, &mut delay), 1);
        assert!(delay > 0.0 && delay < 2.0);
        assert_eq!(ac_session_state(h), 5);
        assert_eq!(ac_session_reconnected(h, &mut delay), 0);
        assert_eq!(ac_session_state(h), 4);
        // User-initiated disconnect tears down.
        assert_eq!(ac_session_manual_disconnect(h, &mut delay), 5);
        assert_eq!(ac_session_state(h), 0);
        ac_session_free(h);
    }

    #[test]
    fn session_abi_approval_and_reject() {
        let h = ac_session_new(7);
        let mut delay = -1.0f64;
        ac_session_start(h, &mut delay);
        ac_session_authenticated(h, &mut delay);
        assert_eq!(ac_session_auth_outcome(h, 1, &mut delay), 3);
        assert!((delay - 120.0).abs() < f64::EPSILON);
        assert_eq!(ac_session_state(h), 3);
        assert_eq!(ac_session_approval_timeout(h, &mut delay), 2);
        assert_eq!(ac_session_state(h), 2);
        assert_eq!(ac_session_auth_outcome(h, 2, &mut delay), 4);
        assert_eq!(ac_session_state(h), 0);
        ac_session_free(h);
    }

    #[test]
    fn session_abi_bad_input() {
        let null = std::ptr::null_mut();
        let mut delay = -1.0f64;
        assert_eq!(ac_session_state(null), -1);
        assert_eq!(ac_session_start(null, &mut delay), 6);
        assert_eq!(ac_session_drop(null, true, &mut delay), 6);
        assert_eq!(ac_session_auth_outcome(null, 0, &mut delay), 6);
        // Null out-param is fine on a legal call.
        let h = ac_session_new(1);
        assert_eq!(ac_session_start(h, std::ptr::null_mut()), 0);
        // Invalid outcome code leaves the driver untouched.
        assert_eq!(ac_session_auth_outcome(h, 9, &mut delay), 6);
        assert_eq!(ac_session_state(h), 1);
        ac_session_free(null);
        ac_session_free(h);
    }

    #[test]
    fn pf_abi_generate_and_free() {
        let dns = c("");
        let phys = c("en0");
        let tun = c("utun5");
        let gw = c("203.0.113.10");
        let allow = c("192.168.0.0/16");
        let out = ac_pf_generate(
            phys.as_ptr(),
            tun.as_ptr(),
            gw.as_ptr(),
            allow.as_ptr(),
            dns.as_ptr(),
            0,
        );
        assert!(!out.is_null());
        let text = unsafe { CStr::from_ptr(out).to_str().unwrap().to_owned() };
        assert!(text.contains("block drop out quick all\n"));
        assert!(text.contains("pass out quick to 203.0.113.10 no state\n"));
        ac_string_free(out);
        // Connected set (nonzero flag) ends with a pass, not a block.
        let out = ac_pf_generate(
            phys.as_ptr(),
            tun.as_ptr(),
            gw.as_ptr(),
            allow.as_ptr(),
            dns.as_ptr(),
            1,
        );
        assert!(!out.is_null());
        let text = unsafe { CStr::from_ptr(out).to_str().unwrap().to_owned() };
        assert!(text.ends_with("pass out quick on en0 all\n"));
        ac_string_free(out);
        // Bad input yields null, never a crash.
        assert!(ac_pf_generate(
            std::ptr::null(),
            tun.as_ptr(),
            gw.as_ptr(),
            allow.as_ptr(),
            dns.as_ptr(),
            0
        )
        .is_null());
        let empty_gw = c("");
        assert!(ac_pf_generate(
            phys.as_ptr(),
            tun.as_ptr(),
            empty_gw.as_ptr(),
            allow.as_ptr(),
            dns.as_ptr(),
            0
        )
        .is_null());
        let bad_net = c("10.0.0.0/33");
        assert!(ac_pf_generate(
            phys.as_ptr(),
            tun.as_ptr(),
            gw.as_ptr(),
            bad_net.as_ptr(),
            dns.as_ptr(),
            0
        )
        .is_null());
        // Split mode (§25.8): DNS servers and the direct table.
        let servers = c("192.168.1.1");
        let out = ac_pf_generate(
            phys.as_ptr(),
            tun.as_ptr(),
            gw.as_ptr(),
            allow.as_ptr(),
            servers.as_ptr(),
            4,
        );
        assert!(!out.is_null());
        let text = unsafe { CStr::from_ptr(out).to_str().unwrap().to_owned() };
        assert!(text.contains("table <ac_direct> persist\n"));
        assert!(text.contains("to 192.168.1.1 port 53 no state\n"));
        ac_string_free(out);
        ac_string_free(std::ptr::null_mut());
    }
}

// MARK: - DNS forwarder (DESIGN.md §26.4, §32.6)

use crate::dns_forwarder::{self, Forwarder, Upstreams};
use std::ffi::c_void;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// Called with the list entry and the comma-separated IPv4 addresses of
/// a direct answer; must return only once they are routed direct.
pub type AcDnsDirect = extern "C" fn(ctx: *mut c_void, entry: *const c_char, ips: *const c_char);
/// Called once when nothing can call `AcDnsDirect` any more.
pub type AcDnsRelease = extern "C" fn(ctx: *mut c_void);

struct HookContext {
    ctx: *mut c_void,
    direct: AcDnsDirect,
    release: Option<AcDnsRelease>,
}
// The Swift side's context is a retained object it only reads behind its
// own synchronisation; Rust just hands the pointer back.
unsafe impl Send for HookContext {}
unsafe impl Sync for HookContext {}
impl Drop for HookContext {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            release(self.ctx);
        }
    }
}

fn c_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_string)
}

fn c_list(p: *const c_char, separator: char) -> Vec<String> {
    c_str(p)
        .map(|s| s.split(separator).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

/// A forwarder listening on `listen`:`port` once started. `direct` may be
/// null (no hook); `release` (may be null) runs when the handle is freed
/// and the last query in flight has finished. Null on bad input.
#[no_mangle]
pub extern "C" fn ac_dns_new(
    listen: *const c_char,
    port: u16,
    upstream_port: u16,
    timeout_ms: u32,
    direct: Option<AcDnsDirect>,
    release: Option<AcDnsRelease>,
    ctx: *mut c_void,
) -> *mut Forwarder {
    let Some(address) = c_str(listen).and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        return std::ptr::null_mut();
    };
    let hook = direct.map(|direct| {
        let context = HookContext { ctx, direct, release };
        Box::new(move |entry: &str, ips: &[Ipv4Addr]| {
            // The whole context, not just its fields (edition-2021
            // closures would capture the raw pointer alone).
            let context = &context;
            let entry = CString::new(entry).unwrap_or_default();
            let ips = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
            let ips = CString::new(ips).unwrap_or_default();
            (context.direct)(context.ctx, entry.as_ptr(), ips.as_ptr());
        }) as dns_forwarder::DirectHook
    });
    let upstreams = Upstreams { tunnel: Vec::new(), local: Vec::new(), physical_if: None };
    Box::into_raw(Box::new(Forwarder::new(
        SocketAddrV4::new(address, port),
        upstream_port,
        Duration::from_millis(timeout_ms as u64),
        Vec::new(),
        upstreams,
        hook,
    )))
}

/// 0 = listening; otherwise the errno (e.g. EADDRINUSE: port 53 taken).
#[no_mangle]
pub extern "C" fn ac_dns_start(f: *const Forwarder) -> c_int {
    let Some(f) = (unsafe { f.as_ref() }) else { return -1 };
    match f.start() {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().unwrap_or(-1),
    }
}

/// Stops listening; the port is free on return.
#[no_mangle]
pub extern "C" fn ac_dns_stop(f: *const Forwarder) {
    if let Some(f) = unsafe { f.as_ref() } {
        f.stop();
    }
}

#[no_mangle]
pub extern "C" fn ac_dns_free(f: *mut Forwarder) {
    if !f.is_null() {
        unsafe { drop(Box::from_raw(f)) };
    }
}

/// The expanded direct list, one rule per line.
#[no_mangle]
pub extern "C" fn ac_dns_set_rules(f: *const Forwarder, rules: *const c_char) {
    if let Some(f) = unsafe { f.as_ref() } {
        f.set_rules(&c_list(rules, '\n'));
    }
}

/// Comma-separated servers ("a.b.c.d" or "a.b.c.d:port"); `physical_if`
/// may be null or empty (no binding).
#[no_mangle]
pub extern "C" fn ac_dns_set_upstreams(
    f: *const Forwarder,
    tunnel: *const c_char,
    local: *const c_char,
    physical_if: *const c_char,
) {
    if let Some(f) = unsafe { f.as_ref() } {
        f.set_upstreams(Upstreams {
            tunnel: c_list(tunnel, ','),
            local: c_list(local, ','),
            physical_if: c_str(physical_if).filter(|s| !s.is_empty()),
        });
    }
}

/// The name last answered with this address (free with ac_string_free),
/// or null.
#[no_mangle]
pub extern "C" fn ac_dns_name_for(f: *const Forwarder, ip: *const c_char) -> *mut c_char {
    let Some(f) = (unsafe { f.as_ref() }) else { return std::ptr::null_mut() };
    let Some(ip) = c_str(ip).and_then(|s| s.parse::<Ipv4Addr>().ok()) else { return std::ptr::null_mut() };
    f.name_for(ip)
        .and_then(|n| CString::new(n).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

// MARK: - Certificate relay (DESIGN.md §32.7)

use crate::relay::{self, Stream};

/// One relay log line (the App writes relay.log).
pub type AcRelayLog = extern "C" fn(line: *const c_char);

/// The plaintext side of relayed connection `pair` to `gateway_ip`.
/// Null on a bad address. Used from one queue at a time.
#[no_mangle]
pub extern "C" fn ac_relay_stream_new(pair: u32, gateway_ip: *const c_char, log: Option<AcRelayLog>) -> *mut Stream {
    let Some(gateway) = c_str(gateway_ip).and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        return std::ptr::null_mut();
    };
    // No callback: the relay log itself (crate::relay_log).
    let log: relay::Log = match log {
        Some(f) => std::sync::Arc::new(move |line: &str| {
            if let Ok(c) = CString::new(line) {
                f(c.as_ptr());
            }
        }),
        None => std::sync::Arc::new(crate::relay_log::write),
    };
    Box::into_raw(Box::new(Stream::new(pair, gateway, Some(log))))
}

/// The gateway connection's local IPv4 and/or interface name (either may
/// be null): the DTLS channel leaves through the same interface.
#[no_mangle]
pub extern "C" fn ac_relay_stream_set_path(s: *mut Stream, local_ip: *const c_char, interface: *const c_char) {
    if let Some(s) = unsafe { s.as_mut() } {
        s.set_path(c_str(local_ip).as_deref(), c_str(interface).as_deref());
    }
}

/// One read from openconnect (`from_client`) or the gateway. Returns the
/// number of chunks to send, each as its own write (read them with
/// ac_relay_stream_chunk before the next feed in the same direction);
/// -1 = not CSTP / bad request, -2 = oversized.
#[no_mangle]
pub extern "C" fn ac_relay_stream_feed(s: *mut Stream, from_client: bool, data: *const u8, len: usize) -> c_int {
    let Some(s) = (unsafe { s.as_mut() }) else { return -1 };
    let bytes = if data.is_null() || len == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(data, len) } };
    match s.feed(bytes, from_client) {
        Ok(n) => n as c_int,
        Err(relay::FramingError::Invalid) => -1,
        Err(relay::FramingError::Oversized) => -2,
    }
}

/// Chunk `index` of the last feed in that direction; its length, with
/// `*data` pointing at bytes owned by the stream.
#[no_mangle]
pub extern "C" fn ac_relay_stream_chunk(s: *const Stream, from_client: bool, index: usize, data: *mut *const u8) -> usize {
    let Some(s) = (unsafe { s.as_ref() }) else { return 0 };
    let chunks = &s.out[if from_client { 0 } else { 1 }];
    if index >= chunks.len() || data.is_null() {
        return 0;
    }
    let chunk = chunks.get(index);
    unsafe { *data = chunk.as_ptr() };
    chunk.len()
}

/// True once the CONNECT was answered 200 (whole CSTP packets since).
#[no_mangle]
pub extern "C" fn ac_relay_stream_in_tunnel(s: *const Stream) -> bool {
    unsafe { s.as_ref() }.is_some_and(Stream::in_tunnel)
}

/// Stops the DTLS channel; the counters for the close line (free with
/// ac_string_free).
#[no_mangle]
pub extern "C" fn ac_relay_stream_close(s: *mut Stream) -> *mut c_char {
    let Some(s) = (unsafe { s.as_mut() }) else { return std::ptr::null_mut() };
    CString::new(s.close()).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_relay_stream_free(s: *mut Stream) {
    if !s.is_null() {
        unsafe { drop(Box::from_raw(s)) };
    }
}

/// The gateway address for this session (§30.6) from comma-separated
/// `addresses`; `prefer` / `avoid` may be null. Null when none.
#[no_mangle]
pub extern "C" fn ac_relay_pick(addresses: *const c_char, prefer: *const c_char, avoid: *const c_char) -> *mut c_char {
    let list = c_list(addresses, ',');
    let (prefer, avoid) = (c_str(prefer), c_str(avoid));
    relay::pick(&list, prefer.as_deref(), avoid.as_deref())
        .and_then(|a| CString::new(a.as_str()).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

// MARK: - Connections page (DESIGN.md §28.7, §32.9)

/// The live connections as a ConnectionRow JSON array (free with
/// ac_string_free). Lists are comma-separated; `names` (may be null) is
/// the split's DNS forwarder, for the names addresses were looked up under.
#[no_mangle]
pub extern "C" fn ac_connections_json(
    gateway_ips: *const c_char,
    direct_addresses: *const c_char,
    direct_networks: *const c_char,
    names: *const Forwarder,
) -> *mut c_char {
    let context = crate::connections::Context {
        gateway_ips: c_list(gateway_ips, ','),
        direct_addresses: c_list(direct_addresses, ','),
        direct_networks: c_list(direct_networks, ','),
        names: unsafe { names.as_ref() },
    };
    let json = crate::connections::to_json(&crate::connections::list(&context));
    CString::new(json).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Speeds for the connections page (DESIGN.md §四十五): `rows` is the
/// ConnectionRow JSON array the page shows; returns the Speeds JSON (free
/// with ac_string_free), null on bad input. Keeps one snapshot until
/// ac_traffic_stop.
#[no_mangle]
pub extern "C" fn ac_traffic_sample(rows: *const c_char) -> *mut c_char {
    c_str(rows)
        .map(|rows| crate::traffic::sample_json(&rows))
        .filter(|json| !json.is_empty())
        .and_then(|json| CString::new(json).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// The connections page closed: the snapshot goes.
#[no_mangle]
pub extern "C" fn ac_traffic_stop() {
    crate::traffic::stop();
}

/// The panel's speed totals (DESIGN.md §45.4): Totals JSON (free with
/// ac_string_free). One sysctl, no process; keeps one snapshot until
/// ac_speed_totals_stop.
#[no_mangle]
pub extern "C" fn ac_speed_totals() -> *mut c_char {
    serde_json::to_string(&crate::traffic::sample_totals())
        .ok()
        .and_then(|json| CString::new(json).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_speed_totals_stop() {
    crate::traffic::stop_totals();
}

/// The interface the kernel routes `ip` through, or null.
#[no_mangle]
pub extern "C" fn ac_route_interface(ip: *const c_char) -> *mut c_char {
    c_str(ip)
        .and_then(|ip| crate::connections::route_interface(&ip))
        .and_then(|name| CString::new(name).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// One line into the relay log (relay.log, bounded; §32.9).
#[no_mangle]
pub extern "C" fn ac_relay_log(line: *const c_char) {
    if let Some(line) = c_str(line) {
        crate::relay_log::write(&line);
    }
}

// MARK: - Direct routes journal (DESIGN.md §26.5, §32.10)

use crate::direct_routes::{self, DirectRoutes};

fn csv_out(items: &[String]) -> *mut c_char {
    CString::new(items.join(",")).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_routes_new(journal: *const c_char, boot: *const c_char, no_routes: bool) -> *mut DirectRoutes {
    let Some(journal) = c_str(journal) else { return std::ptr::null_mut() };
    Box::into_raw(Box::new(DirectRoutes::new(journal.into(), c_str(boot).unwrap_or_default(), no_routes)))
}

#[no_mangle]
pub extern "C" fn ac_routes_free(r: *mut DirectRoutes) {
    if !r.is_null() {
        unsafe { drop(Box::from_raw(r)) };
    }
}

#[no_mangle]
pub extern "C" fn ac_routes_add(r: *const DirectRoutes, entries: *const c_char, gateway: *const c_char) {
    if let (Some(r), Some(gw)) = (unsafe { r.as_ref() }, c_str(gateway)) {
        r.add(&c_list(entries, ','), &gw);
    }
}

#[no_mangle]
pub extern "C" fn ac_routes_repoint(r: *const DirectRoutes, gateway: *const c_char) {
    if let (Some(r), Some(gw)) = (unsafe { r.as_ref() }, c_str(gateway)) {
        r.repoint(&gw);
    }
}

#[no_mangle]
pub extern "C" fn ac_routes_remove(r: *const DirectRoutes, entries: *const c_char) {
    if let Some(r) = unsafe { r.as_ref() } {
        r.remove(&c_list(entries, ','));
    }
}

#[no_mangle]
pub extern "C" fn ac_routes_remove_all(r: *const DirectRoutes) {
    if let Some(r) = unsafe { r.as_ref() } {
        r.remove_all();
    }
}

/// Comma-separated (free with ac_string_free).
#[no_mangle]
pub extern "C" fn ac_routes_addresses(r: *const DirectRoutes) -> *mut c_char {
    let Some(r) = (unsafe { r.as_ref() }) else { return std::ptr::null_mut() };
    csv_out(&r.addresses())
}

/// "none", "dropped" or "removed N" (free with ac_string_free).
#[no_mangle]
pub extern "C" fn ac_routes_undo_at_start(journal: *const c_char, boot: *const c_char, no_routes: bool) -> *mut c_char {
    let Some(journal) = c_str(journal) else { return std::ptr::null_mut() };
    let result = direct_routes::undo_at_start(std::path::Path::new(&journal), c_str(boot).as_deref(), no_routes);
    CString::new(result).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// The en* networks the Mac sits on, as "first-last" numbers, comma-separated.
#[no_mangle]
pub extern "C" fn ac_routes_attached() -> *mut c_char {
    let list: Vec<String> = direct_routes::attached_networks().iter().map(|(a, b)| format!("{a}-{b}")).collect();
    csv_out(&list)
}

/// `networks` (comma-separated CIDRs) minus those inside an `attached`
/// ("first-last" numbers) network.
#[no_mangle]
pub extern "C" fn ac_routes_networks_to_route(networks: *const c_char, attached: *const c_char) -> *mut c_char {
    let ranges: Vec<(u32, u32)> = c_list(attached, ',')
        .iter()
        .filter_map(|r| r.split_once('-').and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?))))
        .collect();
    csv_out(&direct_routes::networks_to_route(&c_list(networks, ','), &ranges))
}

// MARK: - Cisco engine (DESIGN.md §二十一, §32.11)

use crate::cisco;

/// The App's side of the Cisco engine; `ctx` is handed back to every
/// call and released (`release`) when the engine is freed.
#[repr(C)]
pub struct AcCiscoHooks {
    pub ctx: *mut c_void,
    pub state: extern "C" fn(*mut c_void, c_int, *const c_char),
    pub terminal: extern "C" fn(*mut c_void, c_int),
    pub kill_switch: extern "C" fn(*mut c_void, c_int, *const c_char, *const c_char),
    /// Fills three malloc'd strings (entry, username, password); false = none.
    pub credentials: extern "C" fn(*mut c_void, *mut *mut c_char, *mut *mut c_char, *mut *mut c_char) -> bool,
    /// Comma-separated hosts (malloc'd) or null.
    pub profile_hosts: extern "C" fn(*mut c_void) -> *mut c_char,
    pub before_login: extern "C" fn(*mut c_void),
    pub owned: extern "C" fn(*mut c_void, bool),
    pub log: extern "C" fn(*mut c_void, *const c_char),
    pub disconnected: extern "C" fn(*mut c_void),
    pub release: extern "C" fn(*mut c_void),
}

struct Ctx(*mut c_void, extern "C" fn(*mut c_void));
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}
impl Drop for Ctx {
    fn drop(&mut self) {
        (self.1)(self.0)
    }
}

/// Takes a malloc'd C string, wiping it before it is freed.
fn take_malloced(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe {
        let len = libc::strlen(p);
        std::ptr::write_bytes(p, 0, len);
        libc::free(p as *mut c_void);
    }
    Some(value)
}

fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

#[no_mangle]
pub extern "C" fn ac_cisco_new(cli: *const c_char, approval_minimum_ms: u32, monitor_ms: u32,
                               hooks: *const AcCiscoHooks) -> *mut cisco::Engine {
    let (Some(cli), Some(h)) = (c_str(cli), unsafe { hooks.as_ref() }) else { return std::ptr::null_mut() };
    let ctx = std::sync::Arc::new(Ctx(h.ctx, h.release));
    let (state, terminal, kill_switch, credentials) = (h.state, h.terminal, h.kill_switch, h.credentials);
    let (profile_hosts, before_login, owned, log, disconnected) = (h.profile_hosts, h.before_login, h.owned, h.log, h.disconnected);
    let c = || std::sync::Arc::clone(&ctx);
    let hooks = cisco::Hooks {
        state: { let x = c(); Box::new(move |s, d| state(x.0, s, cstring(d).as_ptr())) },
        terminal: { let x = c(); Box::new(move |code| terminal(x.0, code)) },
        kill_switch: {
            let x = c();
            Box::new(move |mode, tun, gws| kill_switch(x.0, mode, cstring(tun).as_ptr(), cstring(&gws.join(",")).as_ptr()))
        },
        credentials: {
            let x = c();
            Box::new(move || {
                let (mut e, mut u, mut p) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
                let ok = credentials(x.0, &mut e, &mut u, &mut p);
                let (e, u, p) = (take_malloced(e), take_malloced(u), take_malloced(p));
                match (ok, e, u, p) {
                    (true, Some(entry), Some(username), Some(password)) => Some(cisco::Credentials { entry, username, password }),
                    _ => None,
                }
            })
        },
        profile_hosts: {
            let x = c();
            Box::new(move || {
                take_malloced(profile_hosts(x.0))
                    .map(|s| s.split(',').filter(|h| !h.is_empty()).map(str::to_string).collect())
                    .unwrap_or_default()
            })
        },
        before_login: { let x = c(); Box::new(move || before_login(x.0)) },
        owned: { let x = c(); Box::new(move |o| owned(x.0, o)) },
        log: { let x = c(); Box::new(move |l| log(x.0, cstring(l).as_ptr())) },
        disconnected: { let x = c(); Box::new(move || disconnected(x.0)) },
    };
    drop(ctx);
    let monitor = if monitor_ms == 0 { cisco::MONITOR } else { Duration::from_millis(monitor_ms as u64) };
    let config = cisco::Config { cli, approval_timeout_minimum: Duration::from_millis(approval_minimum_ms as u64), monitor };
    Box::into_raw(Box::new(cisco::Engine::new(config, hooks)))
}

/// Ends the engine's thread once it is idle; `release` runs then.
#[no_mangle]
pub extern "C" fn ac_cisco_free(e: *mut cisco::Engine) {
    if !e.is_null() {
        unsafe { drop(Box::from_raw(e)) };
    }
}

#[no_mangle]
pub extern "C" fn ac_cisco_connect(e: *const cisco::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.connect() }
}
#[no_mangle]
pub extern "C" fn ac_cisco_disconnect(e: *const cisco::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.disconnect() }
}
#[no_mangle]
pub extern "C" fn ac_cisco_rearm(e: *const cisco::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.rearm() }
}
#[no_mangle]
pub extern "C" fn ac_cisco_refresh(e: *const cisco::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.refresh() }
}
#[no_mangle]
pub extern "C" fn ac_cisco_is_managing(e: *const cisco::Engine) -> bool {
    unsafe { e.as_ref() }.is_some_and(|e| e.is_managing())
}
#[no_mangle]
pub extern "C" fn ac_cisco_episode_retries(e: *const cisco::Engine) -> u32 {
    unsafe { e.as_ref() }.map_or(0, |e| e.episode_retries())
}

/// Runs the Cisco CLI once (`args` newline-separated); the output (free
/// with ac_string_free), the exit status in `*status`.
#[no_mangle]
pub extern "C" fn ac_cisco_run(cli: *const c_char, args: *const c_char, input: *const c_char, timeout_ms: u32,
                               status: *mut c_int) -> *mut c_char {
    let Some(cli) = c_str(cli) else { return std::ptr::null_mut() };
    let args = c_list(args, '\n');
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let input = c_str(input);
    let r = cisco::run(&cli, &args, input.as_deref(), Duration::from_millis(timeout_ms as u64), &mut |_| {}, &mut |_| {});
    if !status.is_null() {
        unsafe { *status = r.status };
    }
    CString::new(r.output.replace('\0', "")).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// The last ">> state: X" in a CLI output, or null.
#[no_mangle]
pub extern "C" fn ac_cisco_parse_state(output: *const c_char) -> *mut c_char {
    c_str(output).and_then(|o| cisco::parse_state(&o)).and_then(|s| CString::new(s).ok()).map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// The tunnel interface holding the default route, or null.
#[no_mangle]
pub extern "C" fn ac_default_route_tunnel() -> *mut c_char {
    cisco::default_route_tunnel().and_then(|s| CString::new(s).ok()).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

// MARK: - Network gate and Cisco kill switch (DESIGN.md §25.2, §32.12)

use crate::{kill_switch, network_guard};

fn guard() -> Option<std::sync::Arc<network_guard::Guard>> {
    network_guard::shared()
}

fn owned(s: String) -> *mut c_char {
    CString::new(s).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Sets up the process's gate once (later calls change nothing).
/// `pfctl` null = no pfctl on this host. `grace_expired` runs on its own
/// thread when a hold outlived its last App.
#[no_mangle]
pub extern "C" fn ac_guard_init(support_dir: *const c_char, boot: *const c_char, grace_ms: u64,
                                pfctl: *const c_char, grace_expired: Option<extern "C" fn()>) {
    let Some(dir) = c_str(support_dir) else { return };
    let g = network_guard::init(network_guard::Settings {
        support_dir: dir.into(),
        boot: c_str(boot).filter(|b| !b.is_empty()),
        grace: Duration::from_millis(grace_ms),
        pfctl: c_str(pfctl).filter(|p| !p.is_empty()),
    });
    if let Some(f) = grace_expired {
        g.set_on_grace_expired(std::sync::Arc::new(move || f()));
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_new_own_holder() -> *mut c_char {
    guard().map(|g| owned(g.new_own_holder())).unwrap_or(std::ptr::null_mut())
}

/// `inputs` is the Inputs JSON. Null = applied (or stale holder); else
/// the panel's red pf line.
#[no_mangle]
pub extern "C" fn ac_guard_apply(holder: *const c_char, connected: bool, inputs: *const c_char) -> *mut c_char {
    let (Some(g), Some(holder)) = (guard(), c_str(holder)) else { return owned("pf 兜底未生效".into()) };
    let Some(inputs) = c_str(inputs).and_then(|j| serde_json::from_str::<network_guard::Inputs>(&j).ok()) else {
        return owned("pf 兜底未生效：规则生成被拒".into());
    };
    g.apply(&holder, connected, &inputs).map(owned).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_guard_release(holder: *const c_char, reason: *const c_char) {
    if let Some(g) = guard() {
        g.release(c_str(holder).as_deref(), &c_str(reason).unwrap_or_else(|| "user".into()));
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_is_holding() -> bool {
    guard().is_some_and(|g| g.is_holding())
}

/// {"holder":..,"inputs":{..}} or null.
#[no_mangle]
pub extern "C" fn ac_guard_held() -> *mut c_char {
    guard()
        .and_then(|g| g.held())
        .and_then(|(holder, inputs)| serde_json::to_string(&serde_json::json!({"holder": holder, "inputs": inputs})).ok())
        .map(owned)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_guard_holder() -> *mut c_char {
    guard().and_then(|g| g.holder()).map(owned).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_guard_supersede_own_holders() {
    if let Some(g) = guard() {
        g.supersede_own_holders();
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_update_held_allow_networks(networks: *const c_char) {
    if let Some(g) = guard() {
        g.update_held_allow_networks(&c_list(networks, ','));
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_add_direct(ips: *const c_char) -> bool {
    guard().is_some_and(|g| g.add_direct(&c_list(ips, ',')))
}

#[no_mangle]
pub extern "C" fn ac_guard_remove_direct(ips: *const c_char) {
    if let Some(g) = guard() {
        g.remove_direct(&c_list(ips, ','));
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_flush_direct() {
    if let Some(g) = guard() {
        g.flush_direct();
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_direct_addresses() -> *mut c_char {
    guard().map(|g| owned(g.direct_addresses().join(","))).unwrap_or(std::ptr::null_mut())
}

/// {"reason":..,"at":"<ISO 8601>"} or null.
#[no_mangle]
pub extern "C" fn ac_guard_last_release() -> *mut c_char {
    guard()
        .and_then(|g| g.last_release())
        .and_then(|r| serde_json::to_string(&r).ok())
        .map(owned)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_guard_owner_attached() {
    if let Some(g) = guard() {
        g.owner_attached();
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_owner_lost(session_active: bool) {
    if let Some(g) = guard() {
        g.owner_lost(session_active);
    }
}

#[no_mangle]
pub extern "C" fn ac_guard_adopt_at_start() {
    if let Some(g) = guard() {
        g.adopt_at_start();
    }
}

/// The anchor text for a set (Inputs JSON), or null when refused.
#[no_mangle]
pub extern "C" fn ac_guard_text(connected: bool, inputs: *const c_char) -> *mut c_char {
    c_str(inputs)
        .and_then(|j| serde_json::from_str::<network_guard::Inputs>(&j).ok())
        .and_then(|i| network_guard::text(connected, &i))
        .map(owned)
        .unwrap_or(std::ptr::null_mut())
}

fn kill_switch() -> Option<std::sync::Arc<kill_switch::KillSwitch>> {
    guard().map(kill_switch::shared)
}

/// The Cisco kill switch: mode 0 off, 1 connected, 2 blocking. Empty
/// string = applied; else the panel's red pf line.
#[no_mangle]
pub extern "C" fn ac_ks_set(mode: c_int, tunnel_if: *const c_char, gateways: *const c_char, ok: *mut bool) -> *mut c_char {
    let Some(ks) = kill_switch() else { return owned("pf 兜底未生效".into()) };
    let (applied, message) = ks.set(mode, &c_str(tunnel_if).unwrap_or_default(), &c_list(gateways, ','));
    if !ok.is_null() {
        unsafe { *ok = applied };
    }
    owned(message)
}

#[no_mangle]
pub extern "C" fn ac_ks_update_allow_networks(networks: *const c_char) {
    if let Some(ks) = kill_switch() {
        ks.update_allow_networks(&c_list(networks, ','));
    }
}

#[no_mangle]
pub extern "C" fn ac_ks_is_off() -> bool {
    kill_switch().map_or(true, |k| k.is_off())
}

/// "tunnel|gw,gw|physical" while armed, else null.
#[no_mangle]
pub extern "C" fn ac_ks_snapshot() -> *mut c_char {
    kill_switch()
        .and_then(|k| k.snapshot())
        .map(|(t, g, p)| owned(format!("{}|{}|{}", t, g.join(","), p)))
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_ks_disarm() {
    if let Some(k) = kill_switch() {
        k.disarm();
    }
}

// MARK: - openconnect engine (DESIGN.md §32.13)

use crate::oc_engine;

#[repr(C)]
pub struct AcEngineHooks {
    pub ctx: *mut c_void,
    pub state: extern "C" fn(*mut c_void, c_int, *const c_char),
    pub terminal: extern "C" fn(*mut c_void, c_int),
    /// "router|interface" (malloc'd) or null.
    pub physical_network: extern "C" fn(*mut c_void, *const c_char) -> *mut c_char,
    /// Comma-separated (malloc'd) or null.
    pub local_dns: extern "C" fn(*mut c_void, *const c_char) -> *mut c_char,
    /// A PEM path (malloc'd) or null.
    pub system_roots: extern "C" fn(*mut c_void) -> *mut c_char,
    pub stopped: extern "C" fn(*mut c_void),
    pub release: extern "C" fn(*mut c_void),
}

/// `config` is the engine Config JSON (the password inside is wiped from
/// this copy once parsed). Null on bad input or before ac_guard_init.
#[no_mangle]
pub extern "C" fn ac_oc_new(config: *const c_char, hooks: *const AcEngineHooks) -> *mut oc_engine::Engine {
    let (Some(json), Some(h), Some(guard)) = (c_str(config), unsafe { hooks.as_ref() }, network_guard::shared()) else {
        return std::ptr::null_mut();
    };
    let parsed = serde_json::from_str::<oc_engine::Config>(&json);
    let mut json = json;
    unsafe {
        for b in json.as_bytes_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    let Ok(config) = parsed else { return std::ptr::null_mut() };
    let ctx = std::sync::Arc::new(Ctx(h.ctx, h.release));
    let c = || std::sync::Arc::clone(&ctx);
    let (state, terminal, physical_network, local_dns, system_roots, stopped) =
        (h.state, h.terminal, h.physical_network, h.local_dns, h.system_roots, h.stopped);
    let hooks = oc_engine::Hooks {
        state: { let x = c(); Box::new(move |s, d| state(x.0, s, cstring(d).as_ptr())) },
        terminal: { let x = c(); Box::new(move |t| terminal(x.0, t)) },
        physical_network: {
            let x = c();
            Box::new(move |prefer| {
                let text = take_malloced(physical_network(x.0, cstring(prefer).as_ptr()))?;
                let (gw, iface) = text.split_once('|')?;
                Some((gw.to_string(), iface.to_string()))
            })
        },
        local_dns: {
            let x = c();
            Box::new(move |iface| {
                take_malloced(local_dns(x.0, cstring(iface).as_ptr()))
                    .map(|s| s.split(',').filter(|v| !v.is_empty()).map(str::to_string).collect())
                    .unwrap_or_default()
            })
        },
        system_roots: { let x = c(); Box::new(move || take_malloced(system_roots(x.0)).filter(|p| !p.is_empty())) },
        stopped: { let x = c(); Box::new(move || stopped(x.0)) },
    };
    drop(ctx);
    Box::into_raw(Box::new(oc_engine::Engine::new(config, hooks, guard)))
}

#[no_mangle]
pub extern "C" fn ac_oc_free(e: *mut oc_engine::Engine) {
    if !e.is_null() {
        unsafe { drop(Box::from_raw(e)) };
    }
}
#[no_mangle]
pub extern "C" fn ac_oc_start(e: *const oc_engine::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.start() }
}
#[no_mangle]
pub extern "C" fn ac_oc_stop(e: *const oc_engine::Engine, keep_session: bool, notify: bool) {
    if let Some(e) = unsafe { e.as_ref() } { e.stop(keep_session, notify) }
}
#[no_mangle]
pub extern "C" fn ac_oc_kill_child(e: *const oc_engine::Engine) {
    if let Some(e) = unsafe { e.as_ref() } { e.kill_child() }
}
#[no_mangle]
pub extern "C" fn ac_oc_update_direct_domains(e: *const oc_engine::Engine, domains: *const c_char) {
    if let Some(e) = unsafe { e.as_ref() } { e.update_direct_domains(c_list(domains, '\n')) }
}
#[no_mangle]
pub extern "C" fn ac_oc_update_drop_protection(e: *const oc_engine::Engine, on: bool) {
    if let Some(e) = unsafe { e.as_ref() } { e.update_drop_protection(on) }
}
#[no_mangle]
pub extern "C" fn ac_oc_update_allow_networks(e: *const oc_engine::Engine, networks: *const c_char) {
    if let Some(e) = unsafe { e.as_ref() } { e.update_allow_networks(c_list(networks, ',')) }
}
#[no_mangle]
pub extern "C" fn ac_oc_holder(e: *const oc_engine::Engine) -> *mut c_char {
    unsafe { e.as_ref() }.map(|e| owned(e.holder())).unwrap_or(std::ptr::null_mut())
}
/// The Info JSON (free with ac_string_free).
#[no_mangle]
pub extern "C" fn ac_oc_info(e: *const oc_engine::Engine) -> *mut c_char {
    unsafe { e.as_ref() }
        .and_then(|e| serde_json::to_string(&e.info()).ok())
        .map(owned)
        .unwrap_or(std::ptr::null_mut())
}
#[no_mangle]
pub extern "C" fn ac_oc_connections_json(e: *const oc_engine::Engine, fallback_gateways: *const c_char) -> *mut c_char {
    let fallback = c_list(fallback_gateways, ',');
    let json = match unsafe { e.as_ref() } {
        Some(e) => e.connections_json(&fallback),
        None => crate::connections::to_json(&crate::connections::list(&crate::connections::Context {
            gateway_ips: fallback,
            direct_addresses: Vec::new(),
            direct_networks: Vec::new(),
            names: None,
        })),
    };
    owned(json)
}

#[no_mangle]
pub extern "C" fn ac_oc_redact(line: *const c_char) -> *mut c_char {
    owned(oc_engine::redact(&c_str(line).unwrap_or_default()))
}
#[no_mangle]
pub extern "C" fn ac_oc_run_script(reason: *const c_char, script: *const c_char, support: *const c_char,
                                       no_routes: bool, test_active: bool) {
    if let (Some(r), Some(s), Some(d)) = (c_str(reason), c_str(script), c_str(support)) {
        oc_engine::run_script(&r, &s, std::path::Path::new(&d), no_routes, test_active);
    }
}
#[no_mangle]
pub extern "C" fn ac_oc_local_network_held(support: *const c_char) -> bool {
    c_str(support).is_some_and(|d| oc_engine::local_network_held(std::path::Path::new(&d)))
}
#[no_mangle]
pub extern "C" fn ac_oc_undo_journal_at_start(script: *const c_char, support: *const c_char, boot: *const c_char,
                                                  test_active: bool) -> *mut c_char {
    let (Some(s), Some(d)) = (c_str(script), c_str(support)) else { return owned("none".into()) };
    owned(oc_engine::undo_journal_at_start(&s, std::path::Path::new(&d), c_str(boot).filter(|b| !b.is_empty()).as_deref(), test_active))
}
#[no_mangle]
pub extern "C" fn ac_oc_restore_without_engine(script: *const c_char, reason: *const c_char, support: *const c_char,
                                                   boot: *const c_char, test_active: bool) {
    if let (Some(s), Some(r), Some(d)) = (c_str(script), c_str(reason), c_str(support)) {
        oc_engine::restore_without_engine(&s, &r, std::path::Path::new(&d), c_str(boot).filter(|b| !b.is_empty()).as_deref(), test_active);
    }
}

// ---- Update check (DESIGN.md §三十三) ----

/// Which GitHub Release the App should point at: `current` is this App's
/// version, `releases` the body of the releases list, `skipped` the
/// version the user dismissed (may be null). Returns the decision as JSON
/// (`status`: newer / skipped / current / unreadable); free with
/// ac_string_free.
#[no_mangle]
pub extern "C" fn ac_update_decide(
    current: *const c_char,
    releases: *const c_char,
    skipped: *const c_char,
) -> *mut c_char {
    let decision = crate::update_check::decide(
        &c_str(current).unwrap_or_default(),
        &c_str(releases).unwrap_or_default(),
        c_str(skipped).as_deref().filter(|s| !s.is_empty()),
    );
    CString::new(crate::update_check::to_json(&decision))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// The server list merged with the Mac's Cisco profiles (DESIGN.md
/// §三十八): request and result are JSON (cisco_import::SyncRequest /
/// SyncResult). Free the result with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_cisco_sync(request: *const c_char) -> *mut c_char {
    let request: crate::cisco_import::SyncRequest =
        c_str(request).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    serde_json::to_string(&crate::cisco_import::sync(&request))
        .ok()
        .and_then(|s| CString::new(s).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Cisco's server entries and last connection, read-only (JSON,
/// cisco_import::Snapshot). Free the result with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_cisco_snapshot(request: *const c_char) -> *mut c_char {
    let request: crate::cisco_import::SnapshotRequest =
        c_str(request).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    serde_json::to_string(&crate::cisco_import::snapshot(&request))
        .ok()
        .and_then(|s| CString::new(s).ok())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// First-match on-demand decision as JSON; release with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_on_demand_decide(request: *const c_char) -> *mut c_char {
    let answer = c_str(request)
        .and_then(|s| serde_json::from_str::<crate::on_demand::Request>(&s).ok())
        .map(|r| crate::on_demand::decide(&r));
    CString::new(serde_json::to_string(&answer).unwrap_or_default())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
/// Apply one policy event; release the returned JSON with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_on_demand_transition(request: *const c_char) -> *mut c_char {
    let answer = c_str(request)
        .and_then(|s| serde_json::from_str::<crate::on_demand::Transition>(&s).ok())
        .map(crate::on_demand::transition);
    CString::new(serde_json::to_string(&answer).unwrap_or_default())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
/// Build a probe with a caller-supplied random transaction_id, or parse a reply.
/// DNS reply requests must include the original query bytes. Free with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_on_demand_probe(request: *const c_char) -> *mut c_char {
    let answer = c_str(request)
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| {
            if let Some(bytes) = v.get("bytes") {
                let bytes = serde_json::from_value::<Vec<u8>>(bytes.clone()).unwrap_or_default();
                let query =
                    serde_json::from_value::<Vec<u8>>(v["query"].clone()).unwrap_or_default();
                crate::on_demand::probe_reply(v["kind"].as_str().unwrap_or(""), &bytes, &query)
            } else {
                v["transaction_id"]
                    .as_u64()
                    .and_then(|id| u16::try_from(id).ok())
                    .and_then(|id| {
                        serde_json::from_value::<crate::on_demand::Probe>(v)
                            .ok()
                            .and_then(|p| crate::on_demand::probe_plan(&p, id))
                    })
                    .and_then(|p| serde_json::to_value(p).ok())
                    .unwrap_or(serde_json::Value::Null)
            }
        });
    CString::new(serde_json::to_string(&answer).unwrap_or_default())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Validate a stored rule without system I/O; free with ac_string_free.
#[no_mangle]
pub extern "C" fn ac_on_demand_validate(request: *const c_char) -> *mut c_char {
    let valid = c_str(request)
        .and_then(|s| serde_json::from_str::<crate::on_demand::Rule>(&s).ok())
        .is_some_and(|r| crate::on_demand::valid(&r));
    CString::new(serde_json::json!({"valid":valid}).to_string())
        .unwrap()
        .into_raw()
}
