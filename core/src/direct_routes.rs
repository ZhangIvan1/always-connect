//! Routes that send the split's direct addresses out the physical
//! interface (DESIGN.md §26.5, §26.13, §28.1, §30.2; moved from Swift to
//! Rust in §32.10), kept in their own journal: intent is written before
//! mutation, confirmed ownership afterwards. Recovery runs —
//! on disconnect, at the next daemon start after a crash (this boot only:
//! routes do not survive a reboot) and by the reset tool. The first line
//! is "boot <id>", then one "<ip> <gateway>" per route; "<ip>" may be a
//! network "a.b.c.d/n" (the list's network rules), routed with -net.
//! Interrupted `install`/`retire` intents never authorise another deletion.
//!
//! Routes go through /sbin/route. Exclusive add cannot overwrite another
//! owner's route; a matching pre-existing route is borrowed, never deleted.

use crate::dns_forwarder::{cidr_range, ipv4};
use std::collections::{HashMap, HashSet};
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
#[cfg(test)]
fn undo_with(journal: &Path, no_routes: bool, remove: &dyn Fn(&str)->bool) -> Cleanup {
    let text=match fs::read_to_string(journal) {
        Ok(text)=>text, Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Cleanup::default(),
        Err(_)=>return Cleanup {retired:0,pending:1},
    };
    let mut result=Cleanup::default(); let mut kept=Vec::new();
    for line in text.lines().filter(|line|!line.is_empty()) {
        if line.starts_with("boot "){kept.push(line.to_owned());continue;}
        let fields:Vec<_>=line.split_whitespace().collect();
        let (intent,ip)=if fields.first()==Some(&"retire") || fields.first()==Some(&"install") {(true,fields.get(1).copied().unwrap_or(""))}else{(false,fields.first().copied().unwrap_or(""))};
        if !is_entry(ip){continue;}
        if no_routes || (!intent && remove(ip)) {result.retired+=1;}
        else {result.pending+=1;kept.push(line.to_owned());}
    }
    let persisted=if result.pending==0 {fs::remove_file(journal)} else {atomic_journal(journal,&(kept.join("\n")+"\n"))};
    if persisted.is_err(){result.pending=result.pending.max(1);}
    result
}
fn undo(journal:&Path,no_routes:bool)->Cleanup {
    let text=match fs::read_to_string(journal){Ok(text)=>text,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>return Cleanup::default(),Err(_)=>return Cleanup{retired:0,pending:1}};
    let boot=text.lines().find_map(|line|line.strip_prefix("boot ")).unwrap_or("").to_owned();
    let recovery=DirectRoutes::new(journal.to_owned(),boot,no_routes);
    let rows:Vec<_>=text.lines().filter_map(DirectRoutes::row).map(|(kind,entry,gateway)|(kind.to_owned(),entry.to_owned(),gateway.to_owned())).collect();
    let active:Vec<_>=rows.iter().filter(|(kind,_,_)|kind=="active").map(|(_,entry,gateway)|{
        recovery.state.lock().unwrap().active.insert(entry.clone(),OwnedRoute{gateway:gateway.clone(),owned:true});entry.clone()
    }).collect();
    let _=recovery.remove(&active);
    // Interrupted install/retirement records have spent their mutation
    // authority. Only read-only proof can retire them after process restart.
    let current=fs::read_to_string(journal).unwrap_or_default();
    let own=assigned_ipv4();let mut table=None;
    for (kind,entry,gateway) in current.lines().filter_map(DirectRoutes::row) {
        if kind=="active" {continue;}
        let native=!gateway_entry(entry,&HashSet::new()) || own.as_ref().is_some_and(|ips|!gateway_entry(entry,ips));
        let gone=if no_routes||native {true}else{
            let snapshot=table.get_or_insert_with(||recovery.table());
            snapshot.ok&&DirectRoutes::owner(&snapshot.text,entry,gateway)==Some(false)
        };
        if gone {let mut state=recovery.state.lock().unwrap();state.retired.insert(entry.into());state.dirty=true;}
    }
    let _=recovery.reconcile_metadata();
    let remaining=match fs::read_to_string(journal){Ok(text)=>text.lines().filter_map(DirectRoutes::row).count(),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>0,Err(_)=>1};
    if remaining==0 {
        if fs::remove_file(journal).is_err()&&journal.exists(){return Cleanup{retired:rows.len(),pending:1};}
    }
    Cleanup{retired:rows.len().saturating_sub(remaining),pending:remaining}
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

#[derive(Clone)]
struct OwnedRoute { gateway:String, owned:bool }
#[derive(Default)]
struct RouteState { active:HashMap<String,OwnedRoute>, retired:HashSet<String>, dirty:bool }

pub struct DirectRoutes {
    journal:PathBuf, boot:String, no_routes:bool, state:Mutex<RouteState>,
    #[cfg(test)]
    test_system:Mutex<Option<(Box<dyn Fn(&[&str])->i32+Send+Sync>,crate::network_check::Output)>>,
    #[cfg(test)]
    writes_left:Mutex<Option<usize>>,
}
impl DirectRoutes {
    pub fn new(journal:PathBuf,boot:String,no_routes:bool)->Self {
        Self {journal,boot,no_routes,state:Mutex::new(RouteState::default()),
            #[cfg(test)] test_system:Mutex::new(None), #[cfg(test)] writes_left:Mutex::new(None)}
    }
    fn skip_routes(&self)->bool {
        #[cfg(test)] if self.test_system.lock().unwrap().is_some(){return false;}
        self.no_routes
    }
    fn command(&self,args:&[&str])->i32 {
        #[cfg(test)] if let Some((run,_))=&*self.test_system.lock().unwrap(){return run(args);}
        route(args)
    }
    fn table(&self)->crate::network_check::Output {
        #[cfg(test)] if let Some((_,out))=&*self.test_system.lock().unwrap(){return out.clone();}
        crate::network_check::read_command("/usr/sbin/netstat", &["-rn".into(),"-f".into(),"inet".into()],std::time::Duration::from_millis(400))
    }
    #[cfg(test)]
    pub(crate) fn test_commands(&self,run:Box<dyn Fn(&[&str])->i32+Send+Sync>,table:crate::network_check::Output){*self.test_system.lock().unwrap()=Some((run,table));}
    fn write(&self,text:&str)->std::io::Result<()> {
        #[cfg(test)] {
            let mut left=self.writes_left.lock().unwrap();
            if let Some(n)=left.as_mut(){if *n==0{return Err(std::io::Error::other("injected journal write failure"));}*n-=1;}
        }
        atomic_journal(&self.journal,text)
    }
    fn rows(&self)->std::io::Result<Vec<String>> {
        match fs::read_to_string(&self.journal){Ok(s)=>Ok(s.lines().filter(|s|!s.is_empty()).map(str::to_owned).collect()),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(vec![format!("boot {}",self.boot)]),Err(e)=>Err(e)}
    }
    fn row(line:&str)->Option<(&str,&str,&str)> {
        let mut fields=line.split_whitespace();let first=fields.next()?;
        if first=="boot"{return None;}
        let (kind,entry)=if first=="retire"||first=="install"{(first,fields.next()?)}else{("active",first)};
        let gateway=fields.next()?;
        (is_entry(entry)&&ipv4(gateway).is_some()).then_some((kind,entry,gateway))
    }
    fn intent(&self,entries:&[(String,String)],kind:&str)->std::io::Result<()> {
        let mut rows=self.rows()?;
        rows.retain(|line|!Self::row(line).is_some_and(|(_,entry,_)|entries.iter().any(|(e,_)|e==entry)));
        rows.extend(entries.iter().map(|(entry,gateway)|format!("{kind} {entry} {gateway}")));
        self.write(&(rows.join("\n")+"\n"))
    }
    fn flush(&self,state:&mut RouteState)->bool {
        if !state.dirty{return true;}
        let Ok(rows)=self.rows() else {return false;};
        let mut rendered=Vec::new();
        for line in rows {
            if let Some((_,entry,_))=Self::row(&line) {
                if state.retired.contains(entry){continue;}
                if let Some(active)=state.active.get(entry) {
                    if active.owned{rendered.push(format!("{entry} {}",active.gateway));}
                    continue;
                }
            }
            rendered.push(line);
        }
        if self.write(&(rendered.join("\n")+"\n")).is_err(){return false;}
        state.retired.clear();state.dirty=false;true
    }
    pub fn reconcile_metadata(&self)->bool {self.flush(&mut self.state.lock().unwrap())}
    /// Signature comparison is only for current active ownership, never for
    /// replaying an interrupted retirement. Scoped/foreign routes are not ours.
    fn owner(text:&str,entry:&str,gateway:&str)->Option<bool> {
        table_contains(text,entry)?;
        let wanted=cidr_range(&if is_network(entry){entry.into()}else{format!("{entry}/32")})?;
        let mut matched=None;
        for line in text.lines(){let f:Vec<_>=line.split_whitespace().collect();if f.len()<4||f[0]=="default"{continue;}
            let (ip,bits)=f[0].split_once('/').map(|(i,b)|(i,b.to_owned())).unwrap_or((f[0],(f[0].split('.').count()*8).to_string()));
            let mut octets:Vec<_>=ip.split('.').collect();while octets.len()<4{octets.push("0");}
            if cidr_range(&format!("{}/{bits}",octets.join(".")))!=Some(wanted)||f[2].contains('I'){continue;}
            if matched.is_some(){return None;}
            matched=Some(f[1]==gateway);
        }
        matched.or(Some(false))
    }
    pub fn add(&self,entries:&[String],gateway:&str)->bool {
        let mut state=self.state.lock().unwrap();if !self.flush(&mut state){return false;}
        let Some(own)=assigned_ipv4() else{return false;};
        let fresh:Vec<_>=entries.iter().filter(|e|is_entry(e)&&gateway_entry(e,&own)&&!state.active.contains_key(*e)).cloned().map(|e|(e,gateway.to_owned())).collect();
        if fresh.is_empty(){return true;}if ipv4(gateway).is_none(){return false;}
        if self.intent(&fresh,"install").is_err(){return false;}
        let mut ok=true;
        for (entry,_) in &fresh {
            let kind=if is_network(entry){"-net"}else{"-host"};
            let owned=self.skip_routes()||self.command(&["-n","add",kind,entry,gateway])==0;
            let borrowed=if owned{false}else{let t=self.table();t.ok&&Self::owner(&t.text,entry,gateway)==Some(true)};
            if owned||borrowed{state.active.insert(entry.clone(),OwnedRoute{gateway:gateway.into(),owned});}
            else{ok=false;}
            state.dirty=true;
        }
        // Failed installs retain a consumed intent, not delete authority. They
        // are removed from the journal without touching any existing route.
        for (entry,_) in &fresh {if !state.active.contains_key(entry){state.retired.insert(entry.clone());}}
        self.flush(&mut state)&&ok
    }
    pub fn repoint(&self,gateway:&str)->bool {
        let mut state=self.state.lock().unwrap();if ipv4(gateway).is_none()||!self.flush(&mut state){return false;}
        let Some(own)=assigned_ipv4() else{return false;};
        // A borrowed route cannot be moved. Forget it so normal convergence
        // can try an exclusive add through the new gateway instead.
        state.active.retain(|_,route|route.owned);
        // The interface may change while both routers use the same address.
        // Repoint every owned entry on a physical-path event, even then.
        let changes:Vec<_>=state.active.iter().filter(|(entry,route)|route.owned&&gateway_entry(entry,&own)).map(|(e,_)|(e.clone(),gateway.to_owned())).collect();
        if changes.is_empty(){return true;}
        if self.intent(&changes,"install").is_err(){return false;}
        let mut ok=true;
        for (entry,_) in &changes {
            let kind=if is_network(entry){"-net"}else{"-host"};
            let table=if self.skip_routes(){None}else{Some(self.table())};
            let owned=match &table {None=>Some(true),Some(t) if t.ok=>Self::owner(&t.text,entry,&state.active[entry].gateway),_=>None};
            if owned==Some(false) {
                state.active.remove(entry);state.retired.insert(entry.clone());
                // Never change a successor's route. A later exclusive add
                // may borrow a matching signature, or report a conflict.
                continue;
            }
            if owned==Some(true) && (self.skip_routes() || self.command(&["-n","change",kind,entry,gateway])==0) {
                state.active.get_mut(entry).unwrap().gateway=gateway.into();
            }else{ok=false;}
        }
        state.dirty=true;self.flush(&mut state)&&ok
    }
    pub fn remove(&self,entries:&[String])->bool {
        let mut state=self.state.lock().unwrap();if !self.flush(&mut state){return false;}
        let targets:Vec<_>=entries.iter().filter_map(|e|state.active.get(e).map(|r|(e.clone(),r.clone()))).collect();
        let owned:Vec<_>=targets.iter().filter(|(_,r)|r.owned).map(|(e,r)|(e.clone(),r.gateway.clone())).collect();
        if !owned.is_empty()&&self.intent(&owned,"retire").is_err(){return false;}
        let mut ok=true;
        for (entry,route) in targets {
            let completed=if !route.owned||self.skip_routes(){true}else{
                let table=self.table();
                if !table.ok{false}else{match Self::owner(&table.text,&entry,&route.gateway){
                    Some(false)=>true,Some(true)=>{
                        if delete_with(&entry,&|args|self.command(args)){true}else{let t=self.table();t.ok&&table_contains(&t.text,&entry)==Some(false)}
                    },None=>false,
                }}
            };
            if completed{state.active.remove(&entry);state.retired.insert(entry);}else{ok=false;}
            state.dirty=true;
        }
        self.flush(&mut state)&&ok
    }
    pub fn addresses(&self)->Vec<String>{self.state.lock().unwrap().active.keys().cloned().collect()}
    pub fn contains_address(&self,address:&str)->bool {self.state.lock().unwrap().active.contains_key(address)}
    pub fn managed_addresses(&self)->Vec<String>{let state=self.state.lock().unwrap();state.active.keys().chain(state.retired.iter()).cloned().collect()}
    pub fn remove_all(&self)->bool {
        // Live memory knows which mutations completed even if the final
        // journal update failed. Resolve it before reconstructing recovery.
        if !self.remove(&self.addresses()) { return false; }
        let mut state=self.state.lock().unwrap();if !self.flush(&mut state){return false;}
        #[cfg(test)] let fake=self.test_system.lock().unwrap().is_some();
        #[cfg(not(test))] let fake=false;
        let result=undo(&self.journal,self.no_routes||fake);
        if result.pending==0{state.active.clear();}else if let Ok(text)=fs::read_to_string(&self.journal){
            let pending:HashSet<_>=text.lines().filter_map(Self::row).map(|(_,e,_)|e.to_owned()).collect();
            state.active.retain(|e,_|pending.contains(e));
        }
        result.pending==0
    }
}

#[cfg(test)]
pub(crate) fn set_test_journal_write_budget(routes:&DirectRoutes,budget:Option<usize>) {
    *routes.writes_left.lock().unwrap()=budget;
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
    fn completed_delete_with_failed_retirement_never_replays_a_delete() {
        let journal=temp("retirement-transaction");
        let calls=std::sync::Arc::new(Mutex::new(0));let count=calls.clone();
        let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
        routes.test_commands(Box::new(move |args|{if args.contains(&"delete"){*count.lock().unwrap()+=1;}0}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n".into()});
        assert!(routes.add(&["203.0.113.9".into()],"192.168.1.1"));
        *routes.writes_left.lock().unwrap()=Some(1); // intent is durable; final retirement fails
        assert!(!routes.remove(&["203.0.113.9".into()]));
        assert_eq!(*calls.lock().unwrap(),1);assert!(routes.addresses().is_empty());
        assert!(fs::read_to_string(&journal).unwrap().contains("retire 203.0.113.9"));
        assert!(!routes.remove_all());assert_eq!(*calls.lock().unwrap(),1);
        *routes.writes_left.lock().unwrap()=None;
        assert!(routes.remove(&["203.0.113.9".into()]));
        assert_eq!(*calls.lock().unwrap(),1,"a successor route must not be deleted");
        let mut replay=0;
        let _=undo_with(&journal,false,&|_|{false});
        // A durable interrupted intent never invokes a delete callback.
        fs::write(&journal,"boot B1\nretire 203.0.113.9 192.168.1.1\n").unwrap();
        let replay_count=Mutex::new(&mut replay);
        let outcome=undo_with(&journal,false,&|_|{**replay_count.lock().unwrap()+=1;true});
        assert_eq!(outcome.pending,1);assert_eq!(replay,0);
        fs::remove_dir_all(journal.parent().unwrap()).unwrap();
    }

    #[test]
    fn conflicting_and_borrowed_routes_are_never_changed_or_deleted() {
        let journal=temp("foreign-owner"); let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
        let calls=std::sync::Arc::new(Mutex::new(Vec::new()));let seen=calls.clone();
        routes.test_commands(Box::new(move |args|{seen.lock().unwrap().push(args.join(" "));1}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n".into()});
        // An exclusive add conflict with the desired signature is usable,
        // but grants no mutation authority over the existing route.
        assert!(routes.add(&["203.0.113.9".into()],"192.168.1.1"));
        assert!(!fs::read_to_string(&journal).unwrap().contains("203.0.113.9"));
        assert!(routes.repoint("192.168.2.1"));assert!(routes.addresses().is_empty());
        assert!(!routes.add(&["203.0.113.9".into()],"192.168.2.1"));
        assert!(routes.remove_all());
        assert!(calls.lock().unwrap().iter().all(|call|call.contains(" add ")));

        // Even a previously owned entry can have been replaced externally.
        routes.test_commands(Box::new(|_|0),crate::network_check::Output::default());
        assert!(routes.add(&["203.0.113.9".into()],"192.168.1.1"));
        routes.test_commands(Box::new(|_|panic!("successor route must not be mutated")),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.9.1 UGHS en5\n".into()});
        assert!(routes.repoint("192.168.2.1"));assert!(routes.addresses().is_empty());
        assert!(routes.remove_all());fs::remove_dir_all(journal.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_read_and_rename_failures_do_not_mutate_routes_or_truncate_other_data() {
        let journal=temp("journal-io");fs::create_dir_all(&journal).unwrap();
        fs::write(journal.join("sentinel"),"keep").unwrap();
        let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
        routes.test_commands(Box::new(|_|panic!("unreadable journal must prevent mutation")),crate::network_check::Output::default());
        assert!(!routes.add(&["203.0.113.9".into()],"192.168.1.1"));
        assert!(atomic_journal(&journal,"replacement").is_err(),"rename onto a directory must fail");
        assert_eq!(fs::read_to_string(journal.join("sentinel")).unwrap(),"keep");
        assert_eq!(fs::read_dir(journal.parent().unwrap()).unwrap().count(),1,"temporary write must be cleaned up");
        fs::remove_dir_all(journal.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_different_interface_with_the_same_gateway_still_repoints_owned_routes() {
        let journal=temp("same-gateway");let routes=DirectRoutes::new(journal.clone(),"B1".into(),false);
        routes.test_commands(Box::new(|_|0),crate::network_check::Output::default());
        assert!(routes.add(&["203.0.113.9".into()],"192.168.1.1"));
        let changes=std::sync::Arc::new(Mutex::new(0));let count=changes.clone();
        routes.test_commands(Box::new(move |args|{assert!(args.contains(&"change"));*count.lock().unwrap()+=1;0}),crate::network_check::Output{ok:true,text:"Destination Gateway Flags Netif Expire\n203.0.113.9 192.168.1.1 UGHS en0\n".into()});
        assert!(routes.repoint("192.168.1.1"));assert_eq!(*changes.lock().unwrap(),1);
        fs::remove_dir_all(journal.parent().unwrap()).unwrap();
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
