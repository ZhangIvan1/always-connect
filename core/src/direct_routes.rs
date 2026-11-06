//! Routes that send the split's direct addresses out the physical
//! interface (DESIGN.md §26.5, §26.13, §28.1, §30.2; moved from Swift to
//! Rust in §32.10), kept in their own journal: a line is written before
//! its route is added, so every route ever added can be taken out again —
//! on disconnect, at the next daemon start after a crash (this boot only:
//! routes do not survive a reboot) and by the reset tool. The first line
//! is "boot <id>", then one "<ip> <gateway>" per route; "<ip>" may be a
//! network "a.b.c.d/n" (the list's network rules), routed with -net.
//!
//! Routes go through /sbin/route, exactly as before: `add`, and for a
//! host that already has one `change`; a network route that already
//! exists is not ours and is never changed or recorded.

use crate::dns_forwarder::{cidr_range, ipv4};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub fn is_network(value: &str) -> bool {
    let Some((ip, bits)) = value.split_once('/') else { return false };
    ipv4(ip).is_some() && bits.parse::<u32>().is_ok_and(|b| (1..=32).contains(&b))
}

fn is_entry(value: &str) -> bool {
    ipv4(value).is_some() || is_network(value)
}

/// The IPv4 networks of every wired/Wi-Fi (en*) interface that is up,
/// 169.254 left out (no network yet).
pub fn attached_interfaces() -> Vec<(String, (u32, u32))> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut cursor = list;
    while !cursor.is_null() {
        let e = unsafe { &*cursor };
        cursor = e.ifa_next;
        let name = unsafe { std::ffi::CStr::from_ptr(e.ifa_name) }.to_string_lossy().into_owned();
        if !name.starts_with("en") || e.ifa_flags & libc::IFF_UP as u32 == 0 || e.ifa_addr.is_null() || e.ifa_netmask.is_null()
            || unsafe { (*e.ifa_addr).sa_family } as i32 != libc::AF_INET
        {
            continue;
        }
        let a = u32::from_be(unsafe { (*(e.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr });
        let m = u32::from_be(unsafe { (*(e.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr });
        if a >> 16 == 0xA9FE {
            continue;
        }
        out.push((name, (a & m, (a & m) | !m)));
    }
    unsafe { libc::freeifaddrs(list) };
    out
}

pub fn attached_networks() -> Vec<(u32, u32)> {
    attached_interfaces().into_iter().map(|(_, n)| n).collect()
}

/// Which networks get a route via the physical gateway (§28.5): all but
/// those inside a network the Mac sits on (reached directly; a gateway
/// route would break that LAN). A wider network that merely contains it
/// IS routed: the connected one stays more specific. Every network the
/// Mac sits on counts (Wi-Fi and Ethernet both up, §30.2).
pub fn networks_to_route(networks: &[String], attached: &[(u32, u32)]) -> Vec<String> {
    networks
        .iter()
        .filter(|cidr| {
            if !is_network(cidr) {
                return false;
            }
            let Some((lo, hi)) = cidr_range(cidr) else { return false };
            !attached.iter().any(|a| lo >= a.0 && hi <= a.1)
        })
        .cloned()
        .collect()
}

fn route(args: &[&str]) -> i32 {
    Command::new("/sbin/route")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.code().unwrap_or(-1))
        .unwrap_or(-1)
}

/// Takes one of our routes out. A network the Mac has meanwhile moved
/// onto (ours was there first, so the system could not put its own
/// interface route in) gets that interface route back.
fn delete(entry: &str) {
    if !is_network(entry) {
        route(&["-n", "delete", "-host", entry]);
        return;
    }
    route(&["-n", "delete", "-net", entry]);
    if let Some(r) = cidr_range(entry) {
        if let Some((iface, _)) = attached_interfaces().into_iter().find(|(_, n)| *n == r) {
            route(&["-n", "add", "-net", entry, "-interface", &iface]);
        }
    }
}

fn undo(journal: &Path, no_routes: bool) -> usize {
    let Ok(text) = fs::read_to_string(journal) else { return 0 };
    let mut count = 0;
    for line in text.lines().filter(|l| !l.starts_with("boot ")) {
        let Some(ip) = line.split(' ').next() else { continue };
        if !is_entry(ip) {
            continue;
        }
        if !no_routes {
            delete(ip);
        }
        count += 1;
    }
    let _ = fs::remove_file(journal);
    count
}

/// Daemon start: a journal from this boot is undone (its session died
/// with the previous daemon), one from another boot only dropped.
/// "none", "dropped" or "removed N". `boot` = this boot's id; unknown on
/// either side counts as another boot.
pub fn undo_at_start(journal: &Path, boot: Option<&str>, no_routes: bool) -> String {
    let Ok(text) = fs::read_to_string(journal) else { return "none".into() };
    let recorded = text.lines().next().and_then(|l| l.strip_prefix("boot ")).filter(|s| !s.is_empty());
    let current = matches!((recorded, boot), (Some(r), Some(b)) if r == b);
    if !current {
        let _ = fs::remove_file(journal);
        return "dropped".into();
    }
    format!("removed {}", undo(journal, no_routes))
}

pub struct DirectRoutes {
    journal: PathBuf,
    boot: String,
    no_routes: bool,
    routed: Mutex<HashSet<String>>,
}

impl DirectRoutes {
    pub fn new(journal: PathBuf, boot: String, no_routes: bool) -> Self {
        DirectRoutes { journal, boot, no_routes, routed: Mutex::new(HashSet::new()) }
    }

    /// Route `entries` via `gateway` (the physical default gateway).
    /// Returns once the routes are in place.
    pub fn add(&self, entries: &[String], gateway: &str) {
        let mut routed = self.routed.lock().unwrap();
        let fresh: Vec<&String> = entries.iter().filter(|e| is_entry(e) && !routed.contains(*e)).collect();
        if fresh.is_empty() || ipv4(gateway).is_none() {
            return;
        }
        // Journal first.
        if !self.journal.exists() {
            if let Ok(mut f) = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&self.journal) {
                let _ = f.write_all(format!("boot {}\n", self.boot).as_bytes());
            }
        }
        if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&self.journal) {
            let lines: String = fresh.iter().map(|e| format!("{e} {gateway}\n")).collect();
            let _ = f.write_all(lines.as_bytes());
            let _ = f.sync_all();
        }
        let mut refused: Vec<String> = Vec::new();
        for entry in fresh {
            if is_network(entry) {
                // A network route that already exists is not ours — the
                // subnet of another interface or the system's own: never
                // `change` it, never record it, or its undo deletes the
                // system's route and the LAN is gone (§30.2).
                if !self.no_routes && route(&["-n", "add", "-net", entry, gateway]) != 0 {
                    refused.push(entry.clone());
                    continue;
                }
            } else if !self.no_routes && route(&["-n", "add", "-host", entry, gateway]) != 0 {
                route(&["-n", "change", "-host", entry, gateway]);
            }
            routed.insert(entry.clone());
        }
        if !refused.is_empty() {
            self.forget(&refused);
        }
    }

    /// Journal lines for routes that were never added.
    fn forget(&self, entries: &[String]) {
        let Ok(text) = fs::read_to_string(&self.journal) else { return };
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| !l.is_empty())
            .filter(|l| l.starts_with("boot ") || !entries.iter().any(|e| Some(e.as_str()) == l.split(' ').next()))
            .collect();
        let _ = fs::write(&self.journal, kept.join("\n") + "\n");
    }

    /// The physical network changed (§28.1): every route this session
    /// added now goes via the new gateway. The journal keeps the
    /// destinations, which is all the undo needs.
    pub fn repoint(&self, gateway: &str) {
        let routed = self.routed.lock().unwrap();
        if ipv4(gateway).is_none() || self.no_routes {
            return;
        }
        for entry in routed.iter() {
            let kind = if is_network(entry) { "-net" } else { "-host" };
            if route(&["-n", "change", kind, entry, gateway]) != 0 {
                route(&["-n", "add", kind, entry, gateway]);
            }
        }
    }

    /// Takes routes out again mid-session (a network rule removed from
    /// the list). Their journal lines stay; deleting twice is harmless.
    pub fn remove(&self, entries: &[String]) {
        let mut routed = self.routed.lock().unwrap();
        for entry in entries {
            if routed.remove(entry) && !self.no_routes {
                delete(entry);
            }
        }
    }

    pub fn addresses(&self) -> Vec<String> {
        self.routed.lock().unwrap().iter().cloned().collect()
    }

    /// Every route in the journal out, then the journal.
    pub fn remove_all(&self) {
        let mut routed = self.routed.lock().unwrap();
        undo(&self.journal, self.no_routes);
        routed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ac-routes-{}-{}", name, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir.join("direct-routes")
    }

    #[test]
    fn journal_first_and_undo() {
        let j = temp("undo");
        let r = DirectRoutes::new(j.clone(), "B1".into(), true);
        r.add(&["203.0.113.9".into(), "bad".into(), "198.51.100.0/24".into()], "192.168.1.1");
        r.add(&["203.0.113.9".into()], "192.168.1.1");
        let text = fs::read_to_string(&j).unwrap();
        assert_eq!(text, "boot B1\n203.0.113.9 192.168.1.1\n198.51.100.0/24 192.168.1.1\n");
        let mut a = r.addresses();
        a.sort();
        assert_eq!(a, vec!["198.51.100.0/24", "203.0.113.9"]);
        r.add(&["203.0.113.10".into()], "not-an-ip");
        assert_eq!(r.addresses().len(), 2, "no gateway, no route");
        r.remove(&["203.0.113.9".into()]);
        assert_eq!(r.addresses(), vec!["198.51.100.0/24"]);
        r.remove_all();
        assert!(!j.exists() && r.addresses().is_empty());
    }

    #[test]
    fn start_undo_this_boot_only() {
        let j = temp("start");
        fs::write(&j, "boot B1\n203.0.113.9 192.168.1.1\n10.0.0.0/8 192.168.1.1\n").unwrap();
        assert_eq!(undo_at_start(&j, Some("B1"), true), "removed 2");
        assert_eq!(undo_at_start(&j, Some("B1"), true), "none");
        fs::write(&j, "boot B0\n203.0.113.9 192.168.1.1\n").unwrap();
        assert_eq!(undo_at_start(&j, Some("B1"), true), "dropped");
        fs::write(&j, "boot B1\n203.0.113.9 192.168.1.1\n").unwrap();
        assert_eq!(undo_at_start(&j, None, true), "dropped", "unknown boot counts as another");
    }

    #[test]
    fn which_networks_are_routed() {
        let lan = cidr_range("192.168.50.0/24").unwrap();
        let nets: Vec<String> = ["192.168.0.0/16", "192.168.50.0/24", "192.168.50.128/25", "10.9.0.0/16", "1.2.3.4"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(networks_to_route(&nets, &[lan]), vec!["192.168.0.0/16", "10.9.0.0/16"]);
        let two = [cidr_range("192.168.20.0/22").unwrap(), cidr_range("192.168.30.0/23").unwrap()];
        let nets: Vec<String> = ["192.168.20.0/22", "192.168.30.0/23", "172.16.0.0/12"].iter().map(|s| s.to_string()).collect();
        assert_eq!(networks_to_route(&nets, &two), vec!["172.16.0.0/12"]);
        assert!(is_network("10.0.0.0/8") && !is_network("10.0.0.0/0") && !is_network("10.0.0.0"));
    }
}
