//! The kill switch for a tunnel the service does not run itself: the
//! Cisco engine (DESIGN.md §二十一; moved from Swift to Rust in §32.12).
//! Cisco owns the tunnel; the App reports what it sees (up → connected,
//! lost → blocking, manual disconnect → off) and this asks the network
//! gate for the matching set. While connected it also watches the tunnel
//! interface itself (routing-socket events), so a drop is blocked at once
//! even with no App.
//!
//! - connected: physical egress passes (Cisco routes the company's
//!   split-exclude networks out the physical interface by policy).
//! - blocking: blocking set plus DNS (port 53): re-establishing a lost
//!   Cisco session resolves the gateway's hostname.

use crate::network_guard::{self, Guard, Inputs, CISCO_HOLDER};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub const OFF: i32 = 0;
pub const CONNECTED: i32 = 1;
pub const BLOCKING: i32 = 2;

const WATCH: Duration = Duration::from_secs(2);

struct State {
    mode: i32,
    tunnel_if: Option<String>,
    gateway_ips: Vec<String>,
    physical_if: String,
    allow_networks: Vec<String>,
    /// Watchdog generation; Some while one runs.
    watch: Option<u64>,
    /// Writing to this wakes the watchdog to end.
    watch_stop: Option<std::os::fd::OwnedFd>,
    watch_generation: u64,
}

pub struct KillSwitch {
    guard: Arc<Guard>,
    state: Mutex<State>,
    wake: Condvar,
}

static SHARED: OnceLock<Arc<KillSwitch>> = OnceLock::new();

pub fn shared(guard: Arc<Guard>) -> Arc<KillSwitch> {
    SHARED.get_or_init(|| Arc::new(KillSwitch::new(guard))).clone()
}

fn interface_exists(name: &str) -> bool {
    std::ffi::CString::new(name).map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) } != 0).unwrap_or(false)
}

/// The interface the routing table uses toward `ip` (the physical one for
/// a gateway Cisco pinned a host route to), never a tunnel.
pub fn interface_toward(ip: &str) -> Option<String> {
    crate::connections::route_interface(ip).filter(|n| !n.is_empty() && !n.starts_with("utun"))
}

/// IPv4 "a.b.c.d/n" (as the App's isValidCIDR: four numbers 0-255, n 0-32).
pub fn is_cidr(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 || !parts[1].parse::<u32>().is_ok_and(|b| b <= 32) {
        return false;
    }
    let octets: Vec<&str> = parts[0].split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u32>().is_ok_and(|n| n <= 255))
}

impl KillSwitch {
    pub fn new(guard: Arc<Guard>) -> KillSwitch {
        KillSwitch {
            guard,
            state: Mutex::new(State {
                mode: OFF,
                tunnel_if: None,
                gateway_ips: Vec::new(),
                physical_if: "en0".into(),
                allow_networks: Vec::new(),
                watch: None,
                watch_stop: None,
                watch_generation: 0,
            }),
            wake: Condvar::new(),
        }
    }

    /// (applied, message); on failure the message is the panel's red pf line.
    pub fn set(self: &Arc<Self>, mode: i32, tunnel_if: &str, gateway_ips: &[String]) -> (bool, String) {
        let mut s = self.state.lock().unwrap();
        if mode == OFF {
            self.disarm_locked(&mut s);
            return (true, String::new());
        }
        if !tunnel_if.is_empty() {
            s.tunnel_if = Some(tunnel_if.to_string());
        }
        let ips: Vec<String> = gateway_ips.iter().filter(|i| network_guard::is_ip(i)).cloned().collect();
        if !ips.is_empty() {
            s.gateway_ips = ips;
        }
        if mode == CONNECTED {
            if let Some(phys) = s.gateway_ips.first().and_then(|gw| interface_toward(gw)) {
                s.physical_if = phys;
            }
        }
        self.load(&mut s, mode)
    }

    pub fn update_allow_networks(self: &Arc<Self>, networks: &[String]) {
        let mut s = self.state.lock().unwrap();
        s.allow_networks = networks.iter().map(|n| n.trim().to_string()).filter(|n| is_cidr(n)).collect();
        if s.mode != OFF {
            let mode = s.mode;
            let _ = self.load(&mut s, mode);
        }
    }

    pub fn is_off(&self) -> bool {
        self.state.lock().unwrap().mode == OFF
    }

    /// (tunnel, gateways, physical) while armed.
    pub fn snapshot(&self) -> Option<(String, Vec<String>, String)> {
        let s = self.state.lock().unwrap();
        if s.mode == OFF {
            return None;
        }
        s.tunnel_if.clone().map(|t| (t, s.gateway_ips.clone(), s.physical_if.clone()))
    }

    /// Manual disconnect, protection off, or the gate's grace ended:
    /// forget the session, stop watching, release the Cisco hold — also
    /// one a restarted service adopted.
    pub fn disarm(&self) {
        let mut s = self.state.lock().unwrap();
        self.disarm_locked(&mut s);
    }

    fn disarm_locked(&self, s: &mut State) {
        self.stop_watch(s);
        self.guard.release(Some(CISCO_HOLDER), network_guard::reason::USER);
        s.mode = OFF;
        s.tunnel_if = None;
        s.gateway_ips.clear();
    }

    fn load(self: &Arc<Self>, s: &mut State, mode: i32) -> (bool, String) {
        let Some(tun) = s.tunnel_if.clone().filter(|_| !s.gateway_ips.is_empty()) else {
            return (false, "pf 兜底未生效：缺少隧道接口或网关 IP".into());
        };
        let blocking = mode == BLOCKING;
        let inputs = Inputs {
            tunnel_if: tun.clone(),
            gateway_ips: s.gateway_ips.clone(),
            physical_if: s.physical_if.clone(),
            allow_networks: s.allow_networks.clone(),
            allow_dns: true,
            local_dns_servers: Vec::new(),
            direct_table: false,
        };
        if let Some(problem) = self.guard.apply(CISCO_HOLDER, !blocking, &inputs) {
            return (false, problem);
        }
        s.mode = mode;
        network_guard::log(&format!("killswitch {} tun={} phys={}", if blocking { "blocking" } else { "connected" }, tun, s.physical_if));
        if blocking {
            self.stop_watch(s);
        } else {
            self.start_watch(s);
        }
        (true, String::new())
    }

    /// While connected, block on our own the moment the tunnel interface
    /// disappears (Cisco tore the session down), App or not. The kernel
    /// announces it on the routing socket (§32.15: no 2 s polling); a check
    /// every 30 s remains as the fallback.
    fn start_watch(self: &Arc<Self>, s: &mut State) {
        self.stop_watch(s);
        s.watch_generation += 1;
        let generation = s.watch_generation;
        s.watch = Some(generation);
        let mut fds = [0i32; 2];
        let piped = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
        let read_end = if piped {
            use std::os::fd::FromRawFd;
            s.watch_stop = Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) });
            Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) })
        } else {
            None
        };
        let me = Arc::clone(self);
        let _ = std::thread::Builder::new().name("ac-killswitch".into()).stack_size(64 * 1024).spawn(move || {
            use std::os::fd::AsRawFd;
            let watch = crate::route_watch::RouteWatch::new();
            loop {
                match (&watch, &read_end) {
                    (Some(w), Some(stop)) => {
                        if let crate::route_watch::Wake::Stopped =
                            w.wait(Duration::from_secs(30), Duration::from_millis(50), Some(stop.as_raw_fd()))
                        {
                            return;
                        }
                    }
                    _ => {
                        let st = me.state.lock().unwrap();
                        drop(me.wake.wait_timeout(st, WATCH).unwrap());
                    }
                }
                let mut st = me.state.lock().unwrap();
                if st.watch != Some(generation) {
                    return;
                }
                if st.mode != CONNECTED {
                    continue;
                }
                let Some(tun) = st.tunnel_if.clone() else { continue };
                if !interface_exists(&tun) {
                    network_guard::log(&format!("killswitch: {tun} gone, blocking"));
                    let _ = me.load(&mut st, BLOCKING);
                }
            }
        });
    }

    fn stop_watch(&self, s: &mut State) {
        s.watch = None;
        if let Some(stop) = s.watch_stop.take() {
            use std::os::fd::AsRawFd;
            unsafe { libc::write(stop.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        }
        self.wake.notify_all();
    }
}
