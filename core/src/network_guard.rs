//! The network gate (DESIGN.md §25.2, §25.8, §30.1; moved from Swift to
//! Rust in §32.12): the only code that writes pf.
//!
//! - Holders (the Cisco kill switch, an own-connection engine) only ask:
//!   `apply` a set, or `release` theirs. A replaced engine is stale: its
//!   late applies and releases are ignored (holder "own:<generation>").
//! - One record on disk (guard.json): this boot's session id, the pf
//!   enable token, the holder and the inputs. A restart in the same boot
//!   adopts it (blocking set, token taken over, nothing leaked); a record
//!   from another boot is dropped and nothing is blocked — never block at
//!   boot (§23.12).
//! - A hold needs an owner: an attached App. When the last App goes the
//!   hold lasts at most the grace period; then the service releases
//!   everything as on a quit and keeps the reason for the App.
//! - The direct-address table `<ac_direct>` (§25.8): addresses the DNS
//!   forwarder sends out the local network, in pf before `add_direct`
//!   returns.
//!
//! pfctl runs as before: `-E` once for a reference-counted enable (its
//! token kept and released with `-X`), `-a com.apple/300.AlwaysConnect
//! -f <file>`, `-F rules` / `-F Tables`, `-t ac_direct -T add|delete|flush`.

use crate::pf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub const ANCHOR: &str = "com.apple/300.AlwaysConnect";
pub const DIRECT_TABLE: &str = "ac_direct";
pub const CISCO_HOLDER: &str = "cisco";

pub mod reason {
    pub const USER: &str = "user";
    pub const APP_GONE: &str = "app-gone";
    pub const REBOOT: &str = "reboot";
    pub const UPGRADE: &str = "upgrade";
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Inputs {
    pub tunnel_if: String,
    pub gateway_ips: Vec<String>,
    pub physical_if: String,
    pub allow_networks: Vec<String>,
    #[serde(rename = "allowDNS")]
    pub allow_dns: bool,
    /// Port 53 passes to these only (plan v2, §25.8).
    #[serde(rename = "localDNSServers", default)]
    pub local_dns_servers: Vec<String>,
    /// Declare and pass `<ac_direct>`.
    #[serde(default)]
    pub direct_table: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub boot_session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub holder: String,
    /// Connected set (physical egress open) vs blocking set.
    pub connected: bool,
    pub inputs: Inputs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Release {
    pub reason: String,
    pub at: String,
}

pub struct Settings {
    pub support_dir: PathBuf,
    pub boot: Option<String>,
    pub grace: Duration,
    /// None: no pfctl on this host (every load fails, never a silent pass).
    pub pfctl: Option<String>,
}

pub fn log(line: &str) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let _ = std::io::stderr().write_all(format!("{} {}\n", crate::relay_log::stamp(now), line).as_bytes());
}

pub fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// The anchor text for a set (core/src/pf.rs), or None when refused.
pub fn text(connected: bool, i: &Inputs) -> Option<String> {
    // As the comma-separated C call did: entries trimmed, empty ones dropped.
    let clean = |v: &Vec<String>| -> Vec<String> {
        v.iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty() && !x.contains(',')).collect()
    };
    pf::generate(&pf::PfInput {
        physical_if: i.physical_if.clone(),
        tunnel_if: i.tunnel_if.clone(),
        gateway_ips: clean(&i.gateway_ips),
        allow_networks: clean(&i.allow_networks),
        allow_direct_egress: connected,
        allow_dns: i.allow_dns,
        dns_servers: clean(&i.local_dns_servers),
        direct_table: i.direct_table,
    })
    .ok()
}

// MARK: - pfctl

struct Pfctl {
    path: Option<String>,
    token: Option<String>,
}

impl Pfctl {
    /// stderr on success, Err(stderr) on failure.
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let Some(path) = &self.path else { return Err("pfctl not available on this host".into()) };
        let out = Command::new(path).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
            .map_err(|e| e.to_string())?;
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        if out.status.success() { Ok(err) } else { Err(err.trim().to_string()) }
    }

    fn parse_token(text: &str) -> Option<String> {
        text.lines().filter(|l| l.contains("Token")).find_map(|l| {
            let v = l.rsplit(':').next()?.trim();
            (!v.is_empty()).then(|| v.to_string())
        })
    }

    fn acquire_enable(&mut self) -> Result<(), String> {
        if self.token.is_some() {
            return Ok(());
        }
        let out = self.run(&["-E"])?;
        self.token = Self::parse_token(&out);
        if self.token.is_none() {
            log("PfController: pfctl -E gave no token; pf enabled without a releasable reference");
        }
        Ok(())
    }

    fn release_enable(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = self.run(&["-X", &token]);
        }
    }

    fn load(&mut self, anchor_text: &str) -> Result<(), String> {
        let tmp = std::env::temp_dir().join(format!("alwaysconnect-anchor-{}.pf", std::process::id()));
        let result = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)
                .map_err(|e| e.to_string())?;
            f.write_all(anchor_text.as_bytes()).map_err(|e| e.to_string())?;
            drop(f);
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            self.acquire_enable()?;
            self.run(&["-a", ANCHOR, "-f", &tmp.to_string_lossy()]).map(|_| ())
        })();
        let _ = std::fs::remove_file(&tmp);
        result
    }

    fn unload(&mut self) -> Result<(), String> {
        self.run(&["-a", ANCHOR, "-F", "rules"])?;
        // The anchor's tables too, scoped to our anchor; never `-F all`.
        let _ = self.run(&["-a", ANCHOR, "-F", "Tables"]);
        self.release_enable();
        Ok(())
    }

    fn table(&self, op: &str, addresses: &[String]) -> Result<(), String> {
        let mut args = vec!["-a", ANCHOR, "-t", DIRECT_TABLE, "-T", op];
        args.extend(addresses.iter().map(String::as_str));
        self.run(&args).map(|_| ())
    }
}

// MARK: - The gate

struct State {
    record: Option<Record>,
    own_generation: u64,
    owner_present: bool,
    /// Grace clock: Some(generation) while one runs.
    grace: Option<u64>,
    grace_generation: u64,
    direct: BTreeSet<String>,
    pf: Pfctl,
}

pub struct Guard {
    settings: Settings,
    state: Mutex<State>,
    grace_wake: Condvar,
    on_grace_expired: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

static GUARD: OnceLock<Arc<Guard>> = OnceLock::new();

/// The process's gate (set up once by the service at start).
pub fn init(settings: Settings) -> Arc<Guard> {
    GUARD.get_or_init(|| Arc::new(Guard::new(settings))).clone()
}

pub fn shared() -> Option<Arc<Guard>> {
    GUARD.get().cloned()
}

impl Guard {
    pub fn new(settings: Settings) -> Guard {
        let pf = Pfctl { path: settings.pfctl.clone(), token: None };
        Guard {
            settings,
            state: Mutex::new(State {
                record: None,
                own_generation: 0,
                owner_present: false,
                grace: None,
                grace_generation: 0,
                direct: BTreeSet::new(),
                pf,
            }),
            grace_wake: Condvar::new(),
            on_grace_expired: Mutex::new(None),
        }
    }

    pub fn set_on_grace_expired(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_grace_expired.lock().unwrap() = Some(f);
    }

    fn record_path(&self) -> PathBuf {
        self.settings.support_dir.join("guard.json")
    }

    fn release_path(&self) -> PathBuf {
        self.settings.support_dir.join("last-release.json")
    }

    /// A new own-connection engine: every earlier one becomes stale.
    pub fn new_own_holder(&self) -> String {
        let mut s = self.state.lock().unwrap();
        s.own_generation += 1;
        format!("own:{}", s.own_generation)
    }

    fn is_stale(s: &State, holder: &str) -> bool {
        match holder.strip_prefix("own:").and_then(|g| g.parse::<u64>().ok()) {
            Some(gen) => gen != s.own_generation,
            None => false,
        }
    }

    /// Load the connected or blocking set for `holder`. None on success
    /// (or when the holder is stale), else the panel's red pf line.
    pub fn apply(self: &Arc<Self>, holder: &str, connected: bool, inputs: &Inputs) -> Option<String> {
        let mut s = self.state.lock().unwrap();
        if Self::is_stale(&s, holder) {
            return None;
        }
        let Some(anchor) = text(connected, inputs) else { return Some("pf 兜底未生效：规则生成被拒".into()) };
        if s.pf.load(&anchor).is_err() {
            return Some("pf 兜底未生效，断线时无法封网".into());
        }
        let direct: Vec<String> = s.direct.iter().cloned().collect();
        s.record = Some(Record {
            boot_session: self.settings.boot.clone().unwrap_or_default(),
            token: s.pf.token.clone(),
            holder: holder.to_string(),
            connected,
            inputs: inputs.clone(),
            direct: Some(direct),
        });
        // A rules load empties the declared table: put it back.
        if inputs.direct_table {
            Self::reload_direct(&s);
        }
        self.persist(&s);
        if !s.owner_present {
            self.start_grace(&mut s);
        }
        None
    }

    /// Let go of `holder`'s set; None = whatever is held. A stale or
    /// non-matching holder changes nothing.
    pub fn release(self: &Arc<Self>, holder: Option<&str>, why: &str) {
        let mut s = self.state.lock().unwrap();
        if let Some(h) = holder {
            if Self::is_stale(&s, h) {
                return;
            }
            if s.record.as_ref().is_some_and(|r| r.holder != h) {
                return;
            }
        }
        self.release_locked(&mut s, why);
    }

    pub fn is_holding(&self) -> bool {
        self.state.lock().unwrap().record.is_some()
    }

    pub fn held(&self) -> Option<(String, Inputs)> {
        self.state.lock().unwrap().record.as_ref().map(|r| (r.holder.clone(), r.inputs.clone()))
    }

    pub fn holder(&self) -> Option<String> {
        self.state.lock().unwrap().record.as_ref().map(|r| r.holder.clone())
    }

    /// An engine is being replaced while a set is held (§30.1): every own
    /// engine so far goes stale; the record stays.
    pub fn supersede_own_holders(&self) {
        self.state.lock().unwrap().own_generation += 1;
    }

    /// The App's networks changed while a non-Cisco set is held.
    pub fn update_held_allow_networks(&self, networks: &[String]) {
        let mut s = self.state.lock().unwrap();
        let Some(mut current) = s.record.clone() else { return };
        if current.holder == CISCO_HOLDER || current.inputs.allow_networks == networks {
            return;
        }
        current.inputs.allow_networks = networks.to_vec();
        let Some(anchor) = text(current.connected, &current.inputs) else { return };
        if s.pf.load(&anchor).is_err() {
            return;
        }
        current.token = s.pf.token.clone();
        let table = current.inputs.direct_table;
        s.record = Some(current);
        if table {
            Self::reload_direct(&s);
        }
        self.persist(&s);
    }

    /// Addresses that may leave outside the tunnel. When this returns
    /// true pf already passes them. Invalid entries fail the whole call.
    pub fn add_direct(&self, ips: &[String]) -> bool {
        let mut s = self.state.lock().unwrap();
        if !ips.iter().all(|i| is_ip(i)) {
            return false;
        }
        let new: Vec<String> = ips.iter().filter(|i| !s.direct.contains(*i)).cloned().collect();
        if new.is_empty() {
            return true;
        }
        if s.record.as_ref().is_some_and(|r| r.inputs.direct_table) && s.pf.table("add", &new).is_err() {
            return false;
        }
        s.direct.extend(new);
        let all: Vec<String> = s.direct.iter().cloned().collect();
        if let Some(r) = s.record.as_mut() {
            r.direct = Some(all);
        }
        self.persist(&s);
        true
    }

    pub fn remove_direct(&self, ips: &[String]) {
        let mut s = self.state.lock().unwrap();
        let gone: Vec<String> = ips.iter().filter(|i| s.direct.contains(*i)).cloned().collect();
        if gone.is_empty() {
            return;
        }
        if s.record.as_ref().is_some_and(|r| r.inputs.direct_table) {
            let _ = s.pf.table("delete", &gone);
        }
        for g in &gone {
            s.direct.remove(g);
        }
        let all: Vec<String> = s.direct.iter().cloned().collect();
        if let Some(r) = s.record.as_mut() {
            r.direct = Some(all);
        }
        self.persist(&s);
    }

    pub fn flush_direct(&self) {
        let mut s = self.state.lock().unwrap();
        if s.record.as_ref().is_some_and(|r| r.inputs.direct_table) {
            let _ = s.pf.table("flush", &[]);
        }
        s.direct.clear();
        if let Some(r) = s.record.as_mut() {
            r.direct = Some(Vec::new());
        }
        self.persist(&s);
    }

    pub fn direct_addresses(&self) -> Vec<String> {
        self.state.lock().unwrap().direct.iter().cloned().collect()
    }

    fn reload_direct(s: &State) {
        if s.direct.is_empty() {
            return;
        }
        let all: Vec<String> = s.direct.iter().cloned().collect();
        if s.pf.table("add", &all).is_err() {
            log("guard: direct table reload failed");
        }
    }

    pub fn last_release(&self) -> Option<Release> {
        let data = std::fs::read(self.release_path()).ok()?;
        serde_json::from_slice(&data).ok()
    }

    // MARK: Owner

    pub fn owner_attached(&self) {
        let mut s = self.state.lock().unwrap();
        s.owner_present = true;
        s.grace = None;
        s.grace_generation += 1;
        self.grace_wake.notify_all();
    }

    /// `session_active`: an engine still runs or retries with no pf hold
    /// yet — with no App it gets the grace period too.
    pub fn owner_lost(self: &Arc<Self>, session_active: bool) {
        let mut s = self.state.lock().unwrap();
        s.owner_present = false;
        if s.record.is_some() || session_active {
            self.start_grace(&mut s);
        }
    }

    // MARK: Service start

    /// Same boot: adopt the record (blocking set, token) and start the
    /// grace clock. Another boot: drop it, block nothing. Files of older
    /// builds (pf-state.json) are dropped too.
    pub fn adopt_at_start(self: &Arc<Self>) {
        let mut s = self.state.lock().unwrap();
        let legacy = self.settings.support_dir.join("pf-state.json");
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
            let _ = s.pf.unload();
            self.write_release(reason::UPGRADE);
            log("guard: dropped an older build's pf-state; network direct");
        }
        let saved: Option<Record> = std::fs::read(self.record_path()).ok().and_then(|d| serde_json::from_slice(&d).ok());
        let Some(mut saved) = saved else {
            let _ = std::fs::remove_file(self.record_path());
            // No record, nothing may be held: a crash between a load and
            // its record must not leave an invisible block.
            let _ = s.pf.unload();
            return;
        };
        let current = matches!(&self.settings.boot, Some(b) if *b == saved.boot_session);
        if !current {
            // pf, its references and our routes did not survive the
            // reboot; only the file did.
            let _ = std::fs::remove_file(self.record_path());
            let _ = s.pf.unload();
            self.write_release(reason::REBOOT);
            log("guard: record from an earlier boot dropped; network direct");
            return;
        }
        if s.pf.token.is_none() {
            s.pf.token = saved.token.clone();
        }
        s.direct = saved.direct.clone().unwrap_or_default().into_iter().collect();
        // No owner yet and the tunnel's fate unknown: fail closed.
        if saved.connected {
            if let Some(anchor) = text(false, &saved.inputs) {
                let _ = s.pf.load(&anchor);
                saved.connected = false;
            }
        }
        if saved.inputs.direct_table {
            Self::reload_direct(&s);
        }
        saved.token = s.pf.token.clone();
        let holder = saved.holder.clone();
        s.record = Some(saved);
        self.persist(&s);
        self.start_grace(&mut s);
        log(&format!("guard: adopted {holder} hold after a restart; {} s for an App", self.settings.grace.as_secs()));
    }

    // MARK: Internals

    fn release_locked(self: &Arc<Self>, s: &mut State, why: &str) {
        s.grace = None;
        s.grace_generation += 1;
        self.grace_wake.notify_all();
        if s.record.is_none() && !self.record_path().exists() {
            // Nothing recorded; still make sure our anchor is empty.
            let _ = s.pf.unload();
            return;
        }
        if s.pf.unload().is_err() {
            // Keep the record: never a blocked network that claims to be
            // open. With no App, the grace clock tries again.
            log("guard: pf unload failed, still holding");
            if !s.owner_present {
                self.start_grace(s);
            }
            return;
        }
        s.record = None;
        s.direct.clear();
        let _ = std::fs::remove_file(self.record_path());
        if why != reason::USER {
            self.write_release(why);
        }
        log(&format!("guard: released ({why})"));
    }

    fn start_grace(self: &Arc<Self>, s: &mut State) {
        if s.grace.is_some() {
            return;
        }
        s.grace_generation += 1;
        let generation = s.grace_generation;
        s.grace = Some(generation);
        let me = Arc::clone(self);
        let grace = self.settings.grace;
        let _ = std::thread::Builder::new().name("ac-guard-grace".into()).stack_size(64 * 1024).spawn(move || {
            let deadline = std::time::Instant::now() + grace;
            let mut st = me.state.lock().unwrap();
            loop {
                if st.grace != Some(generation) {
                    return; // cancelled or replaced
                }
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                st = me.grace_wake.wait_timeout(st, left).unwrap().0;
            }
            st.grace = None;
            if st.owner_present {
                return;
            }
            drop(st);
            log(&format!("guard: no App for {} s, releasing", grace.as_secs()));
            let hook = me.on_grace_expired.lock().unwrap().clone();
            if let Some(hook) = hook {
                std::thread::spawn(move || hook());
            }
        });
    }

    fn ensure_dir(&self) {
        let _ = std::fs::create_dir_all(&self.settings.support_dir);
        let _ = std::fs::set_permissions(&self.settings.support_dir, std::fs::Permissions::from_mode(0o700));
    }

    fn persist(&self, s: &State) {
        let Some(record) = &s.record else { return };
        let Ok(data) = serde_json::to_vec(record) else { return };
        self.ensure_dir();
        let path = self.record_path();
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &data).is_ok() {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    fn write_release(&self, why: &str) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let release = Release { reason: why.to_string(), at: crate::relay_log::stamp(now) };
        let Ok(data) = serde_json::to_vec(&release) else { return };
        self.ensure_dir();
        let path = self.release_path();
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &data).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_records_still_decode() {
        let old = r#"{"bootSession":"B","token":"10088","holder":"cisco","connected":false,
            "inputs":{"tunnelIf":"utun99","gatewayIps":["198.51.100.7"],"physicalIf":"en0","allowNetworks":[],"allowDNS":true}}"#;
        let r: Record = serde_json::from_str(old).unwrap();
        assert_eq!(r.inputs.local_dns_servers, Vec::<String>::new());
        assert!(!r.inputs.direct_table && r.direct.is_none() && r.token.as_deref() == Some("10088"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"allowDNS\":true") && json.contains("\"localDNSServers\":[]") && json.contains("\"bootSession\":\"B\""));
        assert_eq!(Pfctl::parse_token("No ALTQ support in kernel\nToken : 10093\n").as_deref(), Some("10093"));
        assert!(is_ip("2001:db8::5") && is_ip("203.0.113.1") && !is_ip("not-an-ip"));
    }
}
