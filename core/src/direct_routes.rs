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

/// DNS-learned gateway routes are for ordinary unicast, including RFC1918.
/// Control, link-local, multicast and reserved addresses retain native routing.
pub(crate) fn ordinary_unicast(ip: std::net::Ipv4Addr) -> bool {
    let first=ip.octets()[0]; first!=0 && first!=127 && first<224 && !ip.is_link_local()
}
pub(crate) fn assigned_ipv4() -> Option<HashSet<std::net::Ipv4Addr>> {
    let mut list=std::ptr::null_mut();
    if unsafe {libc::getifaddrs(&mut list)} != 0 {return None;}
    let mut own=HashSet::new(); let mut at=list;
    while !at.is_null() {
        let entry=unsafe{&*at}; at=entry.ifa_next;
        if !entry.ifa_addr.is_null() && unsafe{(*entry.ifa_addr).sa_family} as i32==libc::AF_INET {
            let addr=unsafe{&*(entry.ifa_addr as *const libc::sockaddr_in)};
            own.insert(std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
        }
    }
    unsafe {libc::freeifaddrs(list)};
    Some(own)
}
fn gateway_entry(entry: &str, own: &HashSet<std::net::Ipv4Addr>) -> bool {
    if let Ok(ip)=entry.parse::<std::net::Ipv4Addr>() {return ordinary_unicast(ip)&&!own.contains(&ip);}
    let Some((lo,hi))=cidr_range(entry) else {return false};
    if lo==hi {return ordinary_unicast(lo.into())&&!own.contains(&lo.into());}
    ![(0x00000000,0x00ffffff),(0x7f000000,0x7fffffff),(0xa9fe0000,0xa9feffff),(0xe0000000,u32::MAX)]
        .iter().any(|(a,b)|lo>=*a &&hi<=*b)
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
            if !is_network(cidr) || !gateway_entry(cidr,&HashSet::new()) {
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
fn delete_with(entry: &str, run: &dyn Fn(&[&str]) -> i32) -> bool {
    if !gateway_entry(entry,&HashSet::new()) {return true;}
    let Some(own)=assigned_ipv4() else {return false};
    if !gateway_entry(entry,&own) {return true;}
    if !is_network(entry) {
        return run(&["-n", "delete", "-host", entry]) == 0;
    }
    if run(&["-n", "delete", "-net", entry]) != 0 { return false; }
    if let Some(r) = cidr_range(entry) {
        if let Some((iface, _)) = attached_interfaces().into_iter().find(|(_, n)| *n == r) {
            run(&["-n", "add", "-net", entry, "-interface", &iface]);
        }
    }
    true
}

fn delete(entry: &str) -> bool { delete_with(entry, &route) }

/// Parse the complete numeric IPv4 table. A failed read or unknown shape is
/// not evidence of absence; a default route is not a host route to this IP.
fn table_contains(text: &str, entry: &str) -> Option<bool> {
    let wanted = cidr_range(&if is_network(entry) { entry.into() } else { format!("{entry}/32") })?;
    let mut header = false; let mut found = false;
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if !header {
            if line.starts_with("Destination") && line.contains("Gateway") && line.contains("Flags") && line.contains("Netif") { header = true; }
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 { return None; }
        if fields[0] == "default" { continue; }
        let (ip,bits) = fields[0].split_once('/').map(|(ip,b)| (ip,Some(b))).unwrap_or((fields[0],None));
        let mut labels: Vec<_> = ip.split('.').collect(); if labels.len()>4 { return None; }
        let prefix = bits.map(str::to_owned).unwrap_or_else(|| (labels.len()*8).to_string());
        while labels.len()<4 { labels.push("0"); }
        let range = cidr_range(&format!("{}/{prefix}",labels.join(".")))?;
        found |= range == wanted;
    }
    header.then_some(found)
}

#[derive(Default)]
struct Cleanup { retired: usize, pending: usize }
fn atomic_journal(journal: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Read;
    let mut random=[0;8]; fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let suffix=random.iter().map(|v|format!("{v:02x}")).collect::<String>();
    let temporary=journal.with_file_name(format!("direct-routes.retire-{suffix}"));
    let result=(|| {
        let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
        file.write_all(contents.as_bytes())?; file.sync_all()?; fs::rename(&temporary,journal)
    })();
    if result.is_err(){let _=fs::remove_file(&temporary);}
    result
}
fn undo_with(journal: &Path, no_routes: bool, remove: &dyn Fn(&str)->bool) -> Cleanup {
    let text=match fs::read_to_string(journal) {
        Ok(text)=>text, Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Cleanup::default(),
        Err(_)=>return Cleanup {retired:0,pending:1},
    };
    let mut result=Cleanup::default(); let mut kept=Vec::new();
    for line in text.lines().filter(|line|!line.is_empty()) {
        if line.starts_with("boot "){kept.push(line.to_owned());continue;}
        let Some(ip)=line.split_whitespace().next() else {continue};
        if !is_entry(ip){continue;}
        if no_routes || remove(ip) {result.retired+=1;}
        else {result.pending+=1;kept.push(line.to_owned());}
    }
    let persisted=if result.pending==0 {fs::remove_file(journal)} else {atomic_journal(journal,&(kept.join("\n")+"\n"))};
    if persisted.is_err(){result.pending=result.pending.max(1);}
    result
}
fn undo(journal: &Path, no_routes: bool) -> Cleanup {
    undo_with(journal,no_routes,&|ip| {
        if delete(ip){return true;}
        let table=crate::network_check::read_command("/usr/sbin/netstat", &["-rn".into(),"-f".into(),"inet".into()],std::time::Duration::from_millis(400));
        table.ok && table_contains(&table.text,ip)==Some(false)
    })
}
fn cleanup_status(result: Cleanup) -> String {
    if result.pending>0 {format!("pending {}",result.pending)} else {format!("removed {}",result.retired)}
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
    cleanup_status(undo(journal,no_routes))
}

pub struct DirectRoutes {
    journal: PathBuf,
    boot: String,
    no_routes: bool,
    routed: Mutex<HashSet<String>>,
    #[cfg(test)]
    test_system: Mutex<Option<(Box<dyn Fn(&[&str]) -> i32 + Send + Sync>, crate::network_check::Output)>>,
}

impl DirectRoutes {
    pub fn new(journal: PathBuf, boot: String, no_routes: bool) -> Self {
        DirectRoutes { journal, boot, no_routes, routed: Mutex::new(HashSet::new()), #[cfg(test)] test_system: Mutex::new(None) }
    }

    fn skip_routes(&self) -> bool {
        #[cfg(test)] if self.test_system.lock().unwrap().is_some() { return false; }
        self.no_routes
    }
    fn command(&self, args: &[&str]) -> i32 {
        #[cfg(test)] if let Some((run,_)) = &*self.test_system.lock().unwrap() { return run(args); }
        route(args)
    }
    fn table(&self) -> crate::network_check::Output {
        #[cfg(test)] if let Some((_,out)) = &*self.test_system.lock().unwrap() { return out.clone(); }
        crate::network_check::read_command("/usr/sbin/netstat", &["-rn".into(),"-f".into(),"inet".into()], std::time::Duration::from_millis(400))
    }
    #[cfg(test)]
    pub(crate) fn test_commands(&self, run: Box<dyn Fn(&[&str]) -> i32 + Send + Sync>, table: crate::network_check::Output) {
        *self.test_system.lock().unwrap() = Some((run,table));
    }

    /// Route `entries` via `gateway` (the physical default gateway).
    /// Returns once the routes are in place.
    pub fn add(&self, entries: &[String], gateway: &str) -> bool {
        let mut routed = self.routed.lock().unwrap();
        let Some(own)=assigned_ipv4() else {return false};
        let fresh: Vec<&String> = entries.iter().filter(|e| is_entry(e) && gateway_entry(e,&own) && !routed.contains(*e)).collect();
        if fresh.is_empty() { return true; }
        if ipv4(gateway).is_none() { return false; }
        // A failed journal write must never be followed by an untracked route.
        let recorded = (|| -> std::io::Result<()> {
            if !self.journal.exists() {
                let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&self.journal)?;
                f.write_all(format!("boot {}\n", self.boot).as_bytes())?;
            }
            let mut f = fs::OpenOptions::new().append(true).open(&self.journal)?;
            let lines: String = fresh.iter().map(|e| format!("{e} {gateway}\n")).collect();
            f.write_all(lines.as_bytes())?;
            f.sync_all()
        })();
        if recorded.is_err() { return false; }
        let mut refused: Vec<String> = Vec::new();
        for entry in fresh {
            if is_network(entry) {
                // A network route that already exists is not ours — the
                // subnet of another interface or the system's own: never
                // `change` it, never record it, or its undo deletes the
                // system's route and the LAN is gone (§30.2).
                if !self.skip_routes() && self.command(&["-n", "add", "-net", entry, gateway]) != 0 {
                    refused.push(entry.clone());
                    continue;
                }
            } else if !self.skip_routes() && self.command(&["-n", "add", "-host", entry, gateway]) != 0 {
                if self.command(&["-n", "change", "-host", entry, gateway]) != 0 {
                    refused.push(entry.clone());
                    continue;
                }
            }
            routed.insert(entry.clone());
        }
        if !refused.is_empty() {
            self.forget(&refused);
        }
        refused.is_empty()
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
        if ipv4(gateway).is_none() || self.skip_routes() {
            return;
        }
        let Some(own)=assigned_ipv4() else {return};
        for entry in routed.iter().filter(|entry|gateway_entry(entry,&own)) {
            let kind = if is_network(entry) { "-net" } else { "-host" };
            if self.command(&["-n", "change", kind, entry, gateway]) != 0 {
                self.command(&["-n", "add", kind, entry, gateway]);
            }
        }
    }

    /// Takes routes out again mid-session (a network rule removed from
    /// the list). Successfully removed routes leave the journal too.
    pub fn remove(&self, entries: &[String]) -> bool {
        let mut routed = self.routed.lock().unwrap();
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        for entry in entries {
            if !routed.contains(entry) { continue; }
            if self.skip_routes() || delete_with(entry, &|args| self.command(args)) {
                routed.remove(entry); removed.push(entry.clone());
            } else { failed.push(entry.clone()); }
        }
        if !failed.is_empty() {
            let actual = self.table();
            failed.retain(|entry| {
                if actual.ok && table_contains(&actual.text, entry) == Some(false) {
                    routed.remove(entry); removed.push(entry.clone()); false
                } else { true }
            });
        }
        if !removed.is_empty() { self.forget(&removed); }
        failed.is_empty()
    }

    pub fn addresses(&self) -> Vec<String> {
        self.routed.lock().unwrap().iter().cloned().collect()
    }

    /// Every route in the journal out, then the journal.
    pub fn remove_all(&self) -> bool {
        let mut routed=self.routed.lock().unwrap();
        #[cfg(test)] let fake=self.test_system.lock().unwrap().is_some();
        #[cfg(not(test))] let fake=false;
        let result=undo(&self.journal,self.no_routes||fake);
        if result.pending==0 {routed.clear();}
        else if let Ok(text)=fs::read_to_string(&self.journal) {
            let pending:HashSet<_>=text.lines().filter_map(|line|line.split_whitespace().next()).collect();
            routed.retain(|entry|pending.contains(entry.as_str()));
        }
        result.pending==0
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
        assert!(!fs::read_to_string(&j).unwrap().contains("203.0.113.9"), "removed routes must leave the journal too");
        r.remove_all();
        assert!(!j.exists() && r.addresses().is_empty());
    }

    #[test]
    fn unknown_or_failed_cleanup_keeps_only_pending_entries_for_retry() {
        let journal=temp("cleanup-pending");
        fs::write(&journal,"boot B1\n203.0.113.9 192.168.1.1\n203.0.113.10 192.168.1.1\n").unwrap();
        let first=undo_with(&journal,false,&|ip|ip=="203.0.113.9");
        assert_eq!(first.retired,1);assert_eq!(cleanup_status(first),"pending 1");
        let text=fs::read_to_string(&journal).unwrap();assert!(!text.contains("203.0.113.9 "));assert!(text.contains("203.0.113.10 "));
        let unknown=undo_with(&journal,false,&|_|false);assert_eq!(cleanup_status(unknown),"pending 1");assert!(journal.exists());
        let done=undo_with(&journal,false,&|_|true);assert_eq!(cleanup_status(done),"removed 1");assert!(!journal.exists());
        fs::remove_dir_all(journal.parent().unwrap()).unwrap();
    }

    #[test]
    fn control_addresses_never_reach_add_change_delete_or_network_routes() {
        let own=HashSet::from([std::net::Ipv4Addr::new(203,0,113,8)]);
        for value in ["0.0.0.0","0.1.2.3","127.0.0.1","127.0.0.2","169.254.1.2","224.0.0.1","240.0.0.1","255.255.255.255","203.0.113.8"] {
            assert!(!gateway_entry(value,&own));
        }
        for value in ["10.0.0.1","172.16.0.1","192.168.1.5","203.0.113.9"] {assert!(gateway_entry(value,&own));}
        assert!(!gateway_entry("127.0.0.1/32",&own));
        assert!(networks_to_route(&["127.0.0.0/8".into(),"224.0.0.0/4".into(),"169.254.0.0/16".into()],&[]).is_empty());
        let journal=temp("control-protection");let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
        routes.test_commands(Box::new(|_|panic!("control route must not issue a system command")),crate::network_check::Output::default());
        assert!(routes.add(&["127.0.0.1".into(),"0.0.0.0".into(),"224.0.0.1".into()],"192.168.1.1"));
        assert!(routes.addresses().is_empty());
        assert!(delete_with("127.0.0.1",&|_|panic!("must not delete loopback")));
        fs::remove_dir_all(journal.parent().unwrap()).unwrap();
    }

    #[test]
    fn already_absent_routes_are_idempotent_but_unknown_or_present_are_not() {
        let header = "Destination Gateway Flags Netif Expire\n";
        for (suffix, expected) in [("default 192.168.1.1 UGSc en0\n",true),("203.0.113.9 192.168.1.1 UGHS en0\n",false)] {
            let journal=temp(if expected {"already-absent"}else{"still-present"});
            let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
            routes.test_commands(Box::new(|args| if args.contains(&"delete") {1}else{0}), crate::network_check::Output {ok:true,text:format!("{header}{suffix}")});
            assert!(routes.add(&["203.0.113.9".into()],"192.168.1.1"));
            assert_eq!(routes.remove(&["203.0.113.9".into()]), expected);
            assert_eq!(routes.addresses().is_empty(),expected);
            assert_eq!(!fs::read_to_string(&journal).unwrap().contains("203.0.113.9"),expected);
            fs::remove_dir_all(journal.parent().unwrap()).unwrap();
        }
        assert_eq!(table_contains("permission denied","203.0.113.9"),None);
        assert_eq!(table_contains(&format!("{header}203.0.113 192.168.1.1 UGS en0\n"),"203.0.113.9"),Some(false));
        assert_eq!(table_contains(&format!("{header}10.20/16 192.168.1.1 UGS en0\n"),"10.20.0.0/16"),Some(true));
    }

    #[test]
    fn failed_journal_does_not_claim_a_route() {
        let j = temp("bad-journal");
        fs::create_dir_all(&j).unwrap();
        let r = DirectRoutes::new(j.clone(), "B1".into(), true);
        assert!(!r.add(&["203.0.113.9".into()], "192.168.1.1"));
        assert!(r.addresses().is_empty());
        fs::remove_dir_all(j.parent().unwrap()).unwrap();
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
