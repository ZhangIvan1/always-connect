//! AlwaysConnect core: portable decision logic, no Apple frameworks.
//!
//! This crate compiles and tests on Linux. The macOS app links it via the
//! C ABI in [`ffi`] and keeps only thin Swift adapters for NetworkExtension,
//! Keychain, and UI. Mirrors DESIGN.md v0.4 §4-§6.

pub mod backoff;
pub mod cisco;
pub mod cisco_import;
pub mod connections;
pub mod direct_routes;
pub mod dns_forwarder;
pub mod dns_routes;
pub mod ffi;
pub mod kill_switch;
pub mod network_guard;
pub mod oc_engine;
pub mod pf;
pub mod relay;
pub mod relay_log;
pub mod route_watch;
pub mod rules;
pub mod session;
pub mod state_machine;
pub mod update_check;

#[cfg(feature = "openconnect")]
pub mod openconnect;

/// Children start with every signal at its default and none blocked, as
/// Foundation's Process gave them: the service ignores SIGTERM itself
/// (launchd stops it by message), and an openconnect that inherited that
/// would ignore the user's disconnect; a script cannot even trap a signal
/// it was started with ignored (DESIGN.md §32.13).
pub fn reset_child_signals(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            for sig in 1..32 {
                if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                    libc::signal(sig, libc::SIG_DFL);
                }
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
}
