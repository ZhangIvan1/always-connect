//! libopenconnect FFI binding (feature `openconnect`).
//!
//! Signatures and struct layouts verified against
//! `/usr/include/openconnect.h` (openconnect 9.12, Ubuntu 24.04).
//!
//! Covered: session init/free, URL parsing, credential-form callback,
//! cookie acquisition, CA file override. NOT covered yet (Phase 0 on
//! macOS, where the real gateway and phone approval live): the tunnel
//! connect (`openconnect_connect`, `openconnect_mainloop`) and the packet
//! pump between the NE packet flow and libopenconnect's tunnel.
//!
//! Note on the progress callback: upstream declares it variadic
//! (`...`), which stable Rust cannot express (`c_variadic` is nightly).
//! The binding therefore passes a fixed-arg no-op: libopenconnect
//! calls progress during connect/auth, and a NULL callback segfaults
//! on this build. A fixed-arg callee safely ignores the extra
//! variadic arguments on x86_64 SysV; a real logging callback needs
//! a tiny C shim or nightly Rust, which belongs to Phase 0.

#![cfg(feature = "openconnect")]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Once;

/// Form option types (OC_FORM_OPT_* in openconnect.h).
const OPT_TEXT: c_int = 1;
const OPT_PASSWORD: c_int = 2;

/// One option in a server authentication form. Field order matches
/// `struct oc_form_opt` in openconnect.h.
#[repr(C)]
pub struct OcFormOpt {
    pub next: *mut OcFormOpt,
    pub type_: c_int,
    pub name: *const c_char,
    pub label: *const c_char,
    pub _value: *mut c_char,
    pub flags: c_uint,
    pub reserved: *mut c_void,
}

/// One choice in a group-select option. Field order matches
/// `struct oc_choice` in openconnect.h.
#[repr(C)]
pub struct OcChoice {
    pub name: *const c_char,
    pub label: *const c_char,
    pub auth_type: *const c_char,
    pub override_name: *const c_char,
    pub override_label: *const c_char,
}

/// A select option (group picker). Field order matches
/// `struct oc_form_opt_select` in openconnect.h.
#[repr(C)]
pub struct OcFormOptSelect {
    pub form: OcFormOpt,
    pub nr_choices: c_int,
    pub choices: *mut *mut OcChoice,
}

/// A server authentication form. Field order matches
/// `struct oc_auth_form` in openconnect.h.
#[repr(C)]
pub struct OcAuthForm {
    pub banner: *const c_char,
    pub message: *const c_char,
    pub error: *const c_char,
    pub auth_id: *const c_char,
    pub method: *const c_char,
    pub action: *const c_char,
    pub opts: *mut OcFormOpt,
    pub authgroup_opt: *mut OcFormOptSelect,
    pub authgroup_selection: c_int,
}

#[link(name = "openconnect")]
extern "C" {
    fn openconnect_init_ssl() -> c_int;
    fn openconnect_vpninfo_new(
        useragent: *const c_char,
        validate_peer_cert: Option<ValidatePeerCertFn>,
        write_new_config: Option<WriteNewConfigFn>,
        process_auth_form: Option<ProcessAuthFormFn>,
        progress: Option<ProgressFn>,
        privdata: *mut c_void,
    ) -> *mut VpnInfo;
    fn openconnect_vpninfo_free(vpninfo: *mut VpnInfo);
    fn openconnect_parse_url(vpninfo: *mut VpnInfo, url: *const c_char) -> c_int;
    fn openconnect_obtain_cookie(vpninfo: *mut VpnInfo) -> c_int;
    fn openconnect_set_option_value(opt: *mut OcFormOpt, value: *const c_char) -> c_int;
    fn openconnect_get_cookie(vpninfo: *mut VpnInfo) -> *const c_char;
    fn openconnect_set_cookie(vpninfo: *mut VpnInfo, cookie: *const c_char) -> c_int;
    fn openconnect_clear_cookie(vpninfo: *mut VpnInfo);
    fn openconnect_set_cafile(vpninfo: *mut VpnInfo, path: *const c_char) -> c_int;
}

/// Opaque libopenconnect session handle.
#[repr(C)]
pub struct VpnInfo {
    _private: [u8; 0],
}

pub type ValidatePeerCertFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
pub type WriteNewConfigFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);
pub type ProcessAuthFormFn = unsafe extern "C" fn(*mut c_void, *mut OcAuthForm) -> c_int;
/// Fixed-arg no-op for the upstream variadic progress callback.
/// libopenconnect logs progress during connect/auth; a NULL callback
/// crashes the process on this build (SIGSEGV in obtain_cookie with
/// progress=None, init/free unaffected). A fixed-arg callee safely
/// ignores the extra variadic arguments on x86_64 SysV.
pub type ProgressFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char);

unsafe extern "C" fn noop_progress(_privdata: *mut c_void, _level: c_int, _fmt: *const c_char) {}

/// Credentials the auth-form callback fills in. `group` is the AnyConnect
/// group (e.g. `Staff`); `None` leaves the server's default group.
#[derive(Debug, Default, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub group: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    ParseUrl,
    Obtain(c_int),
    NoCookie,
    CaFile,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::ParseUrl => write!(f, "failed to parse gateway URL"),
            AuthError::Obtain(code) => write!(f, "obtain_cookie failed ({code})"),
            AuthError::NoCookie => write!(f, "server accepted auth but returned no cookie"),
            AuthError::CaFile => write!(f, "failed to set CA file"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Map an authentication failure to the session driver's outcome.
/// Contract (callback convention): the auth-form callback returns -1
/// exactly when it refuses to submit — unknown group, or a credential
/// field it cannot fill (empty username/password). Other negative
/// obtain_cookie codes are network-level failures and stay retryable.
/// Trade-off, stated plainly: a transient failure that happens to
/// return -1 stops auto-retry (the user reconnects manually once),
/// which is preferable to hammering the gateway with the same rejected
/// credentials on a loop (account lockout risk).
pub fn map_auth_error(e: &AuthError) -> crate::session::AuthOutcome {
    use crate::session::AuthOutcome;
    match e {
        // Broken configuration: retrying the same input is futile.
        AuthError::ParseUrl | AuthError::CaFile => AuthOutcome::Rejected,
        // Callback refusal: bad credentials or unknown group.
        AuthError::Obtain(-1) => AuthOutcome::Rejected,
        // Network-level failure, or a server that accepted auth but
        // returned no cookie: retry with backoff.
        AuthError::Obtain(_) | AuthError::NoCookie => AuthOutcome::Transient,
    }
}

/// Read a possibly-null C string field as &str.
unsafe fn opt_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

/// Auth-form callback (runs inside `openconnect_obtain_cookie`).
/// Fills username/password fields by name, selects the group when one
/// is configured, and submits anything else unchanged (server-driven
/// forms such as a push-approval notice). Returns 0 to submit, -1 on
/// error. `privdata` points at the session's `Credentials` box, which
/// outlives every callback invocation.
///
/// Phase 1 gap, documented not hidden: obtain_cookie BLOCKS while the
/// server waits for a push approval, so the driver only learns
/// "NeedsApproval" if this callback notifies it when it sees a
/// push-style form (no fillable credential fields) — and the approval
/// timeout needs openconnect_set_cancel_fd wired to abort the wait.
/// Both need the real gateway's form shape to verify, so they stay
/// unwired until a Mac + real gateway exists.
unsafe extern "C" fn auth_form_callback(privdata: *mut c_void, form: *mut OcAuthForm) -> c_int {
    if privdata.is_null() || form.is_null() {
        return -1;
    }
    let creds = &*(privdata as *const Credentials);
    let form = &mut *form;

    // Group selection first: a configured group that the server does
    // not offer is a hard error, not a silent default.
    if !form.authgroup_opt.is_null() {
        if let Some(want) = &creds.group {
            let select = &mut *form.authgroup_opt;
            let mut found = -1;
            for i in 0..select.nr_choices {
                let choice = *select.choices.add(i as usize);
                if choice.is_null() {
                    continue;
                }
                if opt_str((*choice).name) == Some(want.as_str()) {
                    found = i;
                    break;
                }
            }
            if found < 0 {
                return -1;
            }
            form.authgroup_selection = found;
        }
    }

    let mut asked_user = false;
    let mut asked_pass = false;
    let mut opt = form.opts;
    while !opt.is_null() {
        let o = &mut *opt;
        let name = opt_str(o.name);
        let value: Option<&str> = match (o.type_, name) {
            (OPT_TEXT, Some("username")) => {
                asked_user = true;
                if creds.username.is_empty() {
                    None
                } else {
                    Some(&creds.username)
                }
            }
            (OPT_PASSWORD, Some("password")) => {
                asked_pass = true;
                if creds.password.is_empty() {
                    None
                } else {
                    Some(&creds.password)
                }
            }
            _ => None,
        };
        if let Some(v) = value {
            let c = match CString::new(v) {
                Ok(c) => c,
                Err(_) => return -1,
            };
            if openconnect_set_option_value(opt, c.as_ptr()) != 0 {
                return -1;
            }
        }
        opt = o.next;
    }

    // A credential field the form asked for but we cannot fill must
    // fail rather than submit a blank login.
    if (asked_user && creds.username.is_empty()) || (asked_pass && creds.password.is_empty()) {
        return -1;
    }
    0
}

/// Global TLS init, run exactly once: libopenconnect's init is not
/// safe to call concurrently (GnuTLS global init), and the test suite
/// creates sessions on several threads at once.
static INIT_ONCE: Once = Once::new();
static INIT_RESULT: AtomicI32 = AtomicI32::new(-1);

fn ensure_init_ssl() -> bool {
    INIT_ONCE.call_once(|| {
        INIT_RESULT.store(unsafe { openconnect_init_ssl() }, Ordering::SeqCst);
    });
    INIT_RESULT.load(Ordering::SeqCst) == 0
}

/// RAII wrapper: frees the session on drop. The session handle is only
/// touched on one thread in this design (the tunnel thread owns it); it
/// is deliberately NOT Send/Sync.
pub struct VpnSession {
    raw: *mut VpnInfo,
    creds: Box<Credentials>,
}

impl VpnSession {
    /// Initialise libopenconnect and allocate a session. Returns `None`
    /// if SSL init fails or allocation fails.
    pub fn new(useragent: &str) -> Option<Self> {
        unsafe {
            if !ensure_init_ssl() {
                return None;
            }
            let ua = CString::new(useragent).ok()?;
            // The credentials box is heap-allocated and never moves, so
            // the privdata pointer stays valid for the session's life.
            let mut creds = Box::new(Credentials::default());
            let privdata = &mut *creds as *mut Credentials as *mut c_void;
            let raw = openconnect_vpninfo_new(
                ua.as_ptr(),
                None,
                None,
                Some(auth_form_callback),
                Some(noop_progress),
                privdata,
            );
            if raw.is_null() {
                None
            } else {
                Some(Self { raw, creds })
            }
        }
    }

    pub fn set_credentials(&mut self, creds: Credentials) {
        *self.creds = creds;
    }

    /// Override the CA used to verify the gateway (test servers with a
    /// self-signed CA). Production gateways use system trust: skip this.
    pub fn set_cafile(&mut self, path: &str) -> Result<(), AuthError> {
        let c = CString::new(path).map_err(|_| AuthError::CaFile)?;
        let ret = unsafe { openconnect_set_cafile(self.raw, c.as_ptr()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(AuthError::CaFile)
        }
    }

    /// Parse the gateway URL and run the auth exchange (username /
    /// password form, plus any server-driven rounds). Returns the
    /// session cookie. Tunnel connect is a separate Phase 0 step.
    pub fn obtain_cookie(&mut self, url: &str) -> Result<String, AuthError> {
        let curl = CString::new(url).map_err(|_| AuthError::ParseUrl)?;
        let ret = unsafe { openconnect_parse_url(self.raw, curl.as_ptr()) };
        if ret != 0 {
            return Err(AuthError::ParseUrl);
        }
        let ret = unsafe { openconnect_obtain_cookie(self.raw) };
        if ret != 0 {
            return Err(AuthError::Obtain(ret));
        }
        let cookie = unsafe { openconnect_get_cookie(self.raw) };
        match unsafe { opt_str(cookie) } {
            Some(s) if !s.is_empty() => Ok(s.to_owned()),
            _ => Err(AuthError::NoCookie),
        }
    }

    /// Read back the session cookie currently held by the library, if
    /// any. The string is copied out immediately; the library-owned
    /// pointer must not be kept. An empty cookie counts as absent
    /// (clear_cookie leaves an empty string, not NULL).
    pub fn cookie(&self) -> Option<String> {
        let cookie = unsafe { openconnect_get_cookie(self.raw) };
        unsafe { opt_str(cookie) }
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
    }

    /// Inject a previously saved cookie into this session, so a fresh
    /// process can resume without re-authenticating (verified against
    /// the 9.12 header: openconnect_set_cookie, openconnect.h:669).
    /// Returns the library's status code on failure. Whether the server
    /// still accepts the cookie is only proven by the connect attempt.
    pub fn set_cookie(&mut self, cookie: &str) -> Result<(), c_int> {
        let c = CString::new(cookie).map_err(|_| -1)?;
        let ret = unsafe { openconnect_set_cookie(self.raw, c.as_ptr()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }

    /// Drop the held cookie, if any.
    pub fn clear_cookie(&mut self) {
        unsafe { openconnect_clear_cookie(self.raw) }
    }
}

impl Drop for VpnSession {
    fn drop(&mut self) {
        unsafe {
            // Runs before the creds box drops, so no callback can fire
            // against freed credentials.
            openconnect_vpninfo_free(self.raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env() -> Option<(String, String, String, String)> {
        let url = std::env::var("AC_TEST_URL").ok()?;
        let ca = std::env::var("AC_TEST_CA").ok()?;
        let user = std::env::var("AC_TEST_USER").ok()?;
        let pass = std::env::var("AC_TEST_PASS").ok()?;
        Some((url, ca, user, pass))
    }

    #[test]
    fn session_init_and_free_links() {
        // Proves the Rust -> libopenconnect binding links and runs:
        // init_ssl + vpninfo_new + vpninfo_free against the real library.
        let session = VpnSession::new("AlwaysConnect/0.1.0");
        assert!(session.is_some());
        drop(session);
        // Second session proves free() did not corrupt library state.
        assert!(VpnSession::new("AlwaysConnect/0.1.0").is_some());
    }

    #[test]
    fn cookie_set_get_clear_round_trip() {
        // No gateway needed: parse_url only parses, and set/get/clear
        // operate on the session's held cookie string.
        let mut s = VpnSession::new("AlwaysConnect/0.1.0").expect("session");
        let url = CString::new("https://127.0.0.1:4443").unwrap();
        let ret = unsafe { openconnect_parse_url(s.raw, url.as_ptr()) };
        assert_eq!(ret, 0, "parse_url must succeed");
        assert_eq!(s.cookie(), None, "no cookie before set");
        s.set_cookie("test-cookie-value").expect("set_cookie");
        assert_eq!(s.cookie().as_deref(), Some("test-cookie-value"));
        s.clear_cookie();
        assert_eq!(s.cookie(), None, "no cookie after clear");
    }

    #[test]
    fn obtain_cookie_against_local_ocserv() {
        let Some((url, ca, user, pass)) = test_env() else {
            eprintln!("skipping: AC_TEST_URL/CA/USER/PASS not set");
            return;
        };
        let mut s = VpnSession::new("AlwaysConnect/0.1.0").expect("session");
        s.set_cafile(&ca).expect("cafile");
        s.set_credentials(Credentials {
            username: user,
            password: pass,
            group: None,
        });
        let cookie = s.obtain_cookie(&url).expect("obtain_cookie");
        assert!(!cookie.is_empty(), "cookie must be non-empty");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let Some((url, ca, user, _)) = test_env() else {
            eprintln!("skipping: AC_TEST_URL/CA/USER/PASS not set");
            return;
        };
        let mut s = VpnSession::new("AlwaysConnect/0.1.0").expect("session");
        s.set_cafile(&ca).expect("cafile");
        s.set_credentials(Credentials {
            username: user,
            password: "definitely-not-the-password".into(),
            group: None,
        });
        assert!(s.obtain_cookie(&url).is_err(), "wrong password must fail");
    }

    #[test]
    fn auth_error_maps_to_driver_outcome() {
        use crate::session::AuthOutcome;
        // Broken configuration stops: retrying the same input is futile.
        assert_eq!(
            map_auth_error(&AuthError::ParseUrl),
            AuthOutcome::Rejected
        );
        assert_eq!(
            map_auth_error(&AuthError::CaFile),
            AuthOutcome::Rejected
        );
        // Callback refusal (-1) stops: bad credentials / unknown group.
        assert_eq!(
            map_auth_error(&AuthError::Obtain(-1)),
            AuthOutcome::Rejected
        );
        // Other failures retry with backoff.
        assert_eq!(
            map_auth_error(&AuthError::Obtain(-5)),
            AuthOutcome::Transient
        );
        assert_eq!(
            map_auth_error(&AuthError::NoCookie),
            AuthOutcome::Transient
        );
    }
}
