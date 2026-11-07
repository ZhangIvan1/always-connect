//! The server list from the Mac's Cisco Secure Client (DESIGN.md §三十八).
//!
//! Cisco keeps every server the user can pick in profile XML files
//! (`<HostEntry>`: `HostName` is the name Cisco shows, `HostAddress` the
//! gateway, `UserGroup` an optional group path) and the last connection
//! in a preferences file (`DefaultHostName`, `DefaultUser`, ...). This
//! module reads both, read-only, and merges them into the App's own
//! list, so nobody copies addresses by hand:
//!
//! - new Cisco entries are added, a changed address follows Cisco;
//! - an entry gone from Cisco becomes a plain entry with its last
//!   address (nothing the user relies on disappears);
//! - an entry the user removed is remembered and not brought back until
//!   the user asks for a re-import;
//! - a hand-added server with a Cisco entry's address is linked to that
//!   entry instead of being listed twice;
//! - nothing selected yet: Cisco's last server, else the first entry.
//!
//! Nothing here runs in the background: the App calls it at launch, when
//! the server list is shown and on "从 Cisco 重新导入".

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One `<HostEntry>`: the name Cisco shows and what to connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    pub name: String,
    pub address: String,
}

/// What Cisco remembers of the last connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preferences {
    #[serde(default)]
    pub host_name: String,
    #[serde(default)]
    pub host_address: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub group: String,
}

/// One server in the App's list (Swift's ServerEntry; `id` is its UUID,
/// empty for an entry this module adds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub cisco_name: Option<String>,
}

impl Server {
    /// What the engine connects to (ServerEntry.target).
    pub fn target(&self) -> &str {
        self.cisco_name.as_deref().unwrap_or(&self.address)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub selected: String,
    /// Cisco names and addresses the user removed (or detached by
    /// editing the address): not added again by an automatic sync.
    #[serde(default)]
    pub dismissed: Vec<String>,
    /// The user asked for it: forget `dismissed` and take everything.
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub profile_dirs: Vec<String>,
    #[serde(default)]
    pub preference_files: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SyncResult {
    pub servers: Vec<Server>,
    pub selected: String,
    pub dismissed: Vec<String>,
    /// Names of entries added, re-addressed or linked, and of entries
    /// that left Cisco and became plain ones.
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub detached: Vec<String>,
    /// Entries found in Cisco's profiles (after removing duplicates).
    pub found: usize,
    /// Cisco's last-used server, as the list names it (empty = none).
    pub last_used: String,
    /// The list or the selection differs from the request.
    pub changed: bool,
}

// MARK: - Reading

/// The text of a tag's content with XML's five entities decoded.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Element name without a namespace prefix.
fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Walks the elements of `xml`, calling `on_end(path, text)` when an
/// element closes, where `path` is the stack of open element names
/// (closing one last) and `text` its direct text. Comments, CDATA-free
/// declarations and processing instructions are skipped; malformed input
/// ends the walk quietly.
fn walk(xml: &str, mut on_end: impl FnMut(&[String], &str)) {
    let mut stack: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        if let Some(top) = texts.last_mut() {
            top.push_str(&rest[..lt]);
        }
        rest = &rest[lt..];
        if let Some(body) = rest.strip_prefix("<!--") {
            match body.find("-->") {
                Some(end) => rest = &body[end + 3..],
                None => return,
            }
            continue;
        }
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            match body.find("]]>") {
                Some(end) => {
                    if let Some(top) = texts.last_mut() {
                        top.push_str(&body[..end]);
                    }
                    rest = &body[end + 3..];
                }
                None => return,
            }
            continue;
        }
        let Some(gt) = rest.find('>') else { return };
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            let name = local(name.trim()).to_string();
            // Close up to the matching element; a stray end tag is ignored.
            if let Some(pos) = stack.iter().rposition(|n| *n == name) {
                while stack.len() > pos + 1 {
                    stack.pop();
                    texts.pop();
                }
                let text = texts.pop().unwrap_or_default();
                on_end(&stack, &unescape(text.trim()));
                stack.pop();
            }
            continue;
        }
        let self_closing = tag.ends_with('/');
        let name = tag.trim_end_matches('/').split_whitespace().next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        stack.push(local(name).to_string());
        texts.push(String::new());
        if self_closing {
            on_end(&stack, "");
            stack.pop();
            texts.pop();
        }
    }
}

/// The `<HostEntry>`s of one profile, in file order. Only a HostEntry's
/// own HostName / HostAddress / UserGroup count: the HostAddress lines of
/// its backup and load-balancing lists are other gateways. A HostName
/// without HostAddress is itself the address (Cisco's schema). A
/// UserGroup becomes the group path of the address, as Cisco forms its
/// group URL.
pub fn parse_profile(xml: &str) -> Vec<HostEntry> {
    let mut entries = Vec::new();
    let (mut name, mut address, mut group) = (String::new(), String::new(), String::new());
    walk(xml, |path, text| {
        let n = path.len();
        let element = path[n - 1].as_str();
        let parent = if n >= 2 { path[n - 2].as_str() } else { "" };
        match (element, parent) {
            ("HostName", "HostEntry") => name = text.to_string(),
            ("HostAddress", "HostEntry") => address = text.to_string(),
            ("UserGroup", "HostEntry") => group = text.to_string(),
            ("HostEntry", _) => {
                let mut target = if address.is_empty() { name.clone() } else { address.clone() };
                let group_path = group.trim_matches('/');
                if !target.is_empty() && !group_path.is_empty() && !has_path(&target) {
                    target = format!("{}/{}", target.trim_end_matches('/'), group_path);
                }
                if !name.is_empty() && !target.is_empty() {
                    entries.push(HostEntry { name: name.clone(), address: target });
                }
                name.clear();
                address.clear();
                group.clear();
            }
            _ => {}
        }
    });
    entries
}

fn has_path(address: &str) -> bool {
    let rest = address.split_once("://").map(|(_, r)| r).unwrap_or(address);
    rest.trim_end_matches('/').contains('/')
}

/// The last connection as one preferences file records it.
pub fn parse_preferences(xml: &str) -> Preferences {
    let mut prefs = Preferences::default();
    walk(xml, |path, text| match path[path.len() - 1].as_str() {
        "DefaultHostName" => prefs.host_name = text.to_string(),
        "DefaultHostAddress" => prefs.host_address = text.to_string(),
        "DefaultUser" => prefs.user = text.to_string(),
        "DefaultGroup" => prefs.group = text.to_string(),
        _ => {}
    });
    prefs
}

/// Every HostEntry of the top-level `*.xml` files in `dirs`, files in
/// name order, directories in the given order (subdirectories such as a
/// management-tunnel profile are not the user's servers). A name seen
/// before keeps its first address.
pub fn read_profiles(dirs: &[String]) -> Vec<HostEntry> {
    let mut out: Vec<HostEntry> = Vec::new();
    for dir in dirs {
        let Ok(read) = std::fs::read_dir(dir) else { continue };
        let mut files: Vec<_> = read
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("xml")))
            .collect();
        files.sort();
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            for entry in parse_profile(&text) {
                if !out.iter().any(|e| e.name == entry.name) {
                    out.push(entry);
                }
            }
        }
    }
    out
}

/// The most recently written preferences file that names a server (an
/// old AnyConnect's per-user file may linger next to Secure Client's).
/// Fields it leaves empty are taken from the other files.
pub fn read_preferences(files: &[String]) -> Preferences {
    let mut found: Vec<(std::time::SystemTime, Preferences)> = files
        .iter()
        .filter_map(|f| {
            let path = Path::new(f);
            let text = std::fs::read_to_string(path).ok()?;
            let modified = path.metadata().and_then(|m| m.modified()).ok()?;
            Some((modified, parse_preferences(&text)))
        })
        .collect();
    // Files naming a server first, newest first.
    found.sort_by(|a, b| {
        (!b.1.host_name.is_empty())
            .cmp(&!a.1.host_name.is_empty())
            .then(b.0.cmp(&a.0))
    });
    let mut prefs = Preferences::default();
    for (_, p) in found {
        for (mine, theirs) in [
            (&mut prefs.host_name, p.host_name),
            (&mut prefs.host_address, p.host_address),
            (&mut prefs.user, p.user),
            (&mut prefs.group, p.group),
        ] {
            if mine.is_empty() {
                *mine = theirs;
            }
        }
    }
    prefs
}

// MARK: - Merging

/// Host (lower case), port (443 if unsaid) and path of an address, so
/// `https://Host:443/` and `host` compare equal.
fn normalize(address: &str) -> (String, u16, String) {
    let text = address.trim();
    let text = text.split_once("://").map(|(_, r)| r).unwrap_or(text);
    let (authority, path) = match text.find('/') {
        Some(i) => (&text[..i], text[i..].trim_matches('/')),
        None => (text, ""),
    };
    let (host, port) = split_port(authority);
    (host.to_ascii_lowercase(), port.unwrap_or(443), path.to_string())
}

fn split_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(end) = authority.find(']') {
        let host = authority[..=end].trim_start_matches('[').trim_end_matches(']');
        let port = authority[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
        return (host, port);
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()),
        _ => (authority, None),
    }
}

fn same_address(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// `last` (a HostName or an address Cisco recorded) names this server:
/// its Cisco name, its name, or its host (and port, when `last` says one).
fn names(server: &Server, last: &str) -> bool {
    let last = last.trim();
    if last.is_empty() {
        return false;
    }
    if server.cisco_name.as_deref() == Some(last) || server.name == last {
        return true;
    }
    let (host, port, path) = normalize(&server.address);
    let (l_host, l_port, l_path) = normalize(last);
    let said_port = split_port(last.split_once("://").map(|(_, r)| r).unwrap_or(last).split('/').next().unwrap_or(""))
        .1
        .is_some();
    host == l_host && (!said_port || port == l_port) && (l_path.is_empty() || path == l_path)
}

fn looks_like_address(text: &str) -> bool {
    text.contains('.') || text.contains(':')
}

/// Merge Cisco's entries into the App's list (see the module comment).
/// `cisco` empty means Cisco could not be read or has no servers: then
/// existing Cisco entries are left alone, never detached.
pub fn merge(request: &SyncRequest, cisco: &[HostEntry], prefs: &Preferences) -> SyncResult {
    let mut servers = request.servers.clone();
    let mut selected = request.selected.trim().to_string();
    let dismissed: Vec<String> = if request.force { Vec::new() } else { request.dismissed.clone() };
    let mut result = SyncResult { found: cisco.len(), ..Default::default() };

    // An older single-server profile: its server joins the list.
    if !selected.is_empty() && !servers.iter().any(|s| s.target() == selected) {
        servers.insert(0, Server { id: String::new(), name: selected.clone(), address: selected.clone(), cisco_name: None });
    }

    // Entries already from Cisco follow it, or leave it.
    if !cisco.is_empty() {
        for server in servers.iter_mut() {
            let Some(name) = server.cisco_name.clone() else { continue };
            match cisco.iter().find(|e| e.name == name) {
                Some(entry) => {
                    if entry.address != server.address {
                        server.address = entry.address.clone();
                        result.updated.push(server.name.clone());
                    }
                }
                None => {
                    server.cisco_name = None;
                    if selected == name {
                        selected = server.address.clone();
                    }
                    result.detached.push(server.name.clone());
                }
            }
        }
    }

    // New Cisco entries: link a hand-added twin, else add.
    for entry in cisco {
        if servers.iter().any(|s| s.cisco_name.as_deref() == Some(entry.name.as_str())) {
            continue;
        }
        if dismissed.contains(&entry.name) {
            continue;
        }
        if let Some(twin) = servers.iter_mut().find(|s| s.cisco_name.is_none() && same_address(&s.address, &entry.address)) {
            if selected == twin.address {
                selected = entry.name.clone();
            }
            // Unnamed, or the old Cisco name of an entry Cisco renamed.
            if let Some(i) = result.detached.iter().position(|d| *d == twin.name) {
                result.detached.remove(i);
                twin.name = entry.name.clone();
            } else if twin.name == twin.address {
                twin.name = entry.name.clone();
            }
            twin.cisco_name = Some(entry.name.clone());
            twin.address = entry.address.clone();
            result.updated.push(twin.name.clone());
            continue;
        }
        servers.push(Server { id: String::new(), name: entry.name.clone(), address: entry.address.clone(), cisco_name: Some(entry.name.clone()) });
        result.added.push(entry.name.clone());
    }

    // Cisco's last server: found in the list, or added when it is an
    // address typed into Cisco's box rather than a profile entry.
    let mut last = servers.iter().position(|s| names(s, &prefs.host_name));
    if last.is_none() && prefs.host_name.trim().is_empty() {
        last = servers.iter().position(|s| names(s, &prefs.host_address));
    }
    let typed = prefs.host_name.trim();
    if last.is_none() && looks_like_address(typed) && !dismissed.iter().any(|d| same_address(d, typed)) {
        servers.push(Server { id: String::new(), name: typed.to_string(), address: typed.to_string(), cisco_name: None });
        result.added.push(typed.to_string());
        last = Some(servers.len() - 1);
    }
    if let Some(i) = last {
        result.last_used = servers[i].name.clone();
    }

    // Nothing selected (first run) or the selection is gone.
    if selected.is_empty() || !servers.iter().any(|s| s.target() == selected) {
        selected = last.or(if servers.is_empty() { None } else { Some(0) })
            .map(|i| servers[i].target().to_string())
            .unwrap_or_default();
    }

    result.changed = servers != request.servers || selected != request.selected;
    result.servers = servers;
    result.selected = selected;
    result.dismissed = dismissed;
    result
}

/// Read Cisco's files and merge (the App's one call).
pub fn sync(request: &SyncRequest) -> SyncResult {
    let cisco = read_profiles(&request.profile_dirs);
    let prefs = read_preferences(&request.preference_files);
    merge(request, &cisco, &prefs)
}

/// Read-only view of Cisco's files: entries and last connection.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub entries: Vec<HostEntry>,
    pub preferences: Preferences,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SnapshotRequest {
    #[serde(default)]
    pub profile_dirs: Vec<String>,
    #[serde(default)]
    pub preference_files: Vec<String>,
}

pub fn snapshot(request: &SnapshotRequest) -> Snapshot {
    Snapshot {
        entries: read_profiles(&request.profile_dirs),
        preferences: read_preferences(&request.preference_files),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(entries: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- example profile -->
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ClientInitialization><LocalLanAccess UserControllable="true">true</LocalLanAccess></ClientInitialization>
  <ServerList>{entries}</ServerList>
</AnyConnectProfile>"#
        )
    }

    fn host(name: &str, address: &str) -> HostEntry {
        HostEntry { name: name.into(), address: address.into() }
    }

    fn cisco_server(name: &str, address: &str) -> Server {
        Server { id: format!("id-{name}"), name: name.into(), address: address.into(), cisco_name: Some(name.into()) }
    }

    fn plain(name: &str, address: &str) -> Server {
        Server { id: format!("id-{name}"), name: name.into(), address: address.into(), cisco_name: None }
    }

    fn request(servers: Vec<Server>, selected: &str) -> SyncRequest {
        SyncRequest { servers, selected: selected.into(), ..Default::default() }
    }

    #[test]
    fn parses_host_entries_and_skips_backup_servers() {
        let xml = profile(
            r#"
    <HostEntry>
      <HostName>VPN-A</HostName>
      <HostAddress>vpn-a.example.com:8443</HostAddress>
      <BackupServerList><HostAddress>backup.example.com</HostAddress></BackupServerList>
    </HostEntry>
    <HostEntry><HostName>VPN-B &amp; C</HostName><HostAddress>vpn-b.example.com</HostAddress><UserGroup>Staff</UserGroup></HostEntry>
    <HostEntry><HostName>vpn-c.example.com</HostName></HostEntry>
    <HostEntry><HostName></HostName><HostAddress>orphan.example.com</HostAddress></HostEntry>
    <HostEntry><HostName>VPN-D</HostName><HostAddress>https://vpn-d.example.com/Other</HostAddress><UserGroup>Staff</UserGroup></HostEntry>"#,
        );
        assert_eq!(
            parse_profile(&xml),
            vec![
                host("VPN-A", "vpn-a.example.com:8443"),
                host("VPN-B & C", "vpn-b.example.com/Staff"),
                host("vpn-c.example.com", "vpn-c.example.com"),
                host("VPN-D", "https://vpn-d.example.com/Other"),
            ]
        );
    }

    #[test]
    fn parses_namespaced_and_odd_markup() {
        let xml = r#"<ns:AnyConnectProfile xmlns:ns="x"><ns:ServerList><ns:HostEntry>
            <ns:HostName><![CDATA[VPN-A]]></ns:HostName><ns:HostAddress>a.example.com</ns:HostAddress>
            <ns:MobileHostEntryInfo/></ns:HostEntry></ns:ServerList></ns:AnyConnectProfile>"#;
        assert_eq!(parse_profile(xml), vec![host("VPN-A", "a.example.com")]);
        assert!(parse_profile("<HostEntry><HostName>VPN-A").is_empty());
        assert!(parse_profile("not xml at all").is_empty());
    }

    #[test]
    fn parses_preferences() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectPreferences>
<DefaultUser>user1</DefaultUser>
<DefaultHostName>vpn-a.example.com</DefaultHostName>
<DefaultHostAddress>vpn-a2.example.com:443</DefaultHostAddress>
<DefaultGroup>Staff</DefaultGroup>
<ControllablePreferences><LocalLanAccess>true</LocalLanAccess></ControllablePreferences>
</AnyConnectPreferences>"#;
        assert_eq!(
            parse_preferences(xml),
            Preferences {
                host_name: "vpn-a.example.com".into(),
                host_address: "vpn-a2.example.com:443".into(),
                user: "user1".into(),
                group: "Staff".into(),
            }
        );
    }

    #[test]
    fn first_import_adds_all_and_selects_last_used_by_host() {
        let cisco = [host("VPN-A", "a.example.com:8443"), host("VPN-B", "b.example.com:8443")];
        let prefs = Preferences { host_name: "b.example.com".into(), ..Default::default() };
        let r = merge(&request(vec![], ""), &cisco, &prefs);
        assert_eq!(r.servers.iter().map(|s| s.target()).collect::<Vec<_>>(), ["VPN-A", "VPN-B"]);
        assert!(r.servers.iter().all(|s| s.id.is_empty()));
        assert_eq!(r.added, ["VPN-A", "VPN-B"]);
        assert_eq!(r.selected, "VPN-B");
        assert_eq!(r.last_used, "VPN-B");
        assert!(r.changed);
    }

    #[test]
    fn last_used_by_name_port_and_address() {
        let cisco = [host("VPN-A", "a.example.com:8443"), host("VPN-B", "a.example.com:9443")];
        let by_port = Preferences { host_name: "a.example.com:9443".into(), ..Default::default() };
        assert_eq!(merge(&request(vec![], ""), &cisco, &by_port).selected, "VPN-B");
        let by_name = Preferences { host_name: "VPN-B".into(), ..Default::default() };
        assert_eq!(merge(&request(vec![], ""), &cisco, &by_name).selected, "VPN-B");
        let by_address = Preferences { host_address: "a.example.com:9443".into(), ..Default::default() };
        assert_eq!(merge(&request(vec![], ""), &cisco, &by_address).selected, "VPN-B");
        let none = Preferences::default();
        assert_eq!(merge(&request(vec![], ""), &cisco, &none).selected, "VPN-A");
    }

    #[test]
    fn typed_address_in_cisco_is_added_as_plain_entry() {
        let cisco = [host("VPN-A", "a.example.com")];
        let prefs = Preferences { host_name: "other.example.com".into(), ..Default::default() };
        let r = merge(&request(vec![], ""), &cisco, &prefs);
        assert_eq!(r.servers.len(), 2);
        assert_eq!(r.servers[1], plain_new("other.example.com"));
        assert_eq!(r.selected, "other.example.com");
        // An alias that is no entry is no address: not added.
        let alias = Preferences { host_name: "VPN-Z".into(), ..Default::default() };
        let r = merge(&request(vec![], ""), &cisco, &alias);
        assert_eq!(r.servers.len(), 1);
        assert_eq!(r.selected, "VPN-A");
        // Removed by the user: stays removed.
        let mut req = request(vec![], "");
        req.dismissed = vec!["other.example.com".into()];
        assert_eq!(merge(&req, &cisco, &prefs).servers.len(), 1);
    }

    fn plain_new(address: &str) -> Server {
        Server { id: String::new(), name: address.into(), address: address.into(), cisco_name: None }
    }

    #[test]
    fn existing_list_follows_cisco_and_keeps_user_names() {
        let mut renamed = cisco_server("VPN-A", "old.example.com");
        renamed.name = "Office".into();
        let servers = vec![renamed, cisco_server("VPN-B", "b.example.com"), plain("Home", "home.example.com")];
        let cisco = [host("VPN-A", "new.example.com"), host("VPN-C", "c.example.com")];
        let r = merge(&request(servers, "VPN-B"), &cisco, &Preferences::default());
        assert_eq!(r.servers[0].name, "Office");
        assert_eq!(r.servers[0].address, "new.example.com");
        assert_eq!(r.servers[0].id, "id-VPN-A");
        // VPN-B left Cisco: kept, as a plain entry; the selection follows.
        assert_eq!(r.servers[1], plain("VPN-B", "b.example.com"));
        assert_eq!(r.selected, "b.example.com");
        assert_eq!(r.servers[2], plain("Home", "home.example.com"));
        assert_eq!(r.servers[3].target(), "VPN-C");
        assert_eq!((r.updated, r.detached, r.added), (vec!["Office".to_string()], vec!["VPN-B".to_string()], vec!["VPN-C".to_string()]));
    }

    #[test]
    fn entry_renamed_in_cisco_keeps_its_place() {
        let servers = vec![cisco_server("VPN-A", "a.example.com"), plain("Home", "home.example.com")];
        let cisco = [host("VPN-X", "a.example.com")];
        let r = merge(&request(servers, "VPN-A"), &cisco, &Preferences::default());
        assert_eq!(r.servers.len(), 2);
        assert_eq!(r.servers[0].id, "id-VPN-A");
        assert_eq!(r.servers[0].name, "VPN-X");
        assert_eq!(r.servers[0].target(), "VPN-X");
        assert_eq!(r.selected, "VPN-X");
        assert!(r.detached.is_empty() && r.added.is_empty());
    }

    #[test]
    fn unreadable_cisco_changes_nothing() {
        let servers = vec![cisco_server("VPN-A", "a.example.com"), plain("Home", "home.example.com")];
        let r = merge(&request(servers.clone(), "VPN-A"), &[], &Preferences::default());
        assert_eq!(r.servers, servers);
        assert_eq!(r.selected, "VPN-A");
        assert!(!r.changed);
        assert_eq!(r.found, 0);
    }

    #[test]
    fn same_state_again_is_no_change() {
        let cisco = [host("VPN-A", "a.example.com"), host("VPN-B", "b.example.com")];
        let prefs = Preferences { host_name: "b.example.com".into(), ..Default::default() };
        let first = merge(&request(vec![], ""), &cisco, &prefs);
        let again = merge(&request(first.servers.clone(), &first.selected), &cisco, &prefs);
        assert!(!again.changed);
        assert!(again.added.is_empty() && again.updated.is_empty() && again.detached.is_empty());
    }

    #[test]
    fn hand_added_twin_is_linked_not_duplicated() {
        let servers = vec![plain("VPN-A.example.com:443", "VPN-A.example.com:443")];
        let cisco = [host("VPN-A", "https://vpn-a.example.com/")];
        let r = merge(&request(servers, "VPN-A.example.com:443"), &cisco, &Preferences::default());
        assert_eq!(r.servers.len(), 1);
        assert_eq!(r.servers[0].cisco_name.as_deref(), Some("VPN-A"));
        assert_eq!(r.servers[0].name, "VPN-A");
        assert_eq!(r.servers[0].id, "id-VPN-A.example.com:443");
        assert_eq!(r.selected, "VPN-A");
        // A named hand-added twin keeps its name.
        let r = merge(&request(vec![plain("Office", "vpn-a.example.com")], ""), &cisco, &Preferences::default());
        assert_eq!(r.servers[0].name, "Office");
        assert_eq!(r.servers[0].target(), "VPN-A");
    }

    #[test]
    fn removed_entries_stay_removed_until_forced() {
        let cisco = [host("VPN-A", "a.example.com"), host("VPN-B", "b.example.com")];
        let mut req = request(vec![cisco_server("VPN-A", "a.example.com")], "VPN-A");
        req.dismissed = vec!["VPN-B".into()];
        let r = merge(&req, &cisco, &Preferences::default());
        assert_eq!(r.servers.len(), 1);
        assert_eq!(r.dismissed, ["VPN-B"]);
        assert!(!r.changed);
        req.force = true;
        let r = merge(&req, &cisco, &Preferences::default());
        assert_eq!(r.servers.len(), 2);
        assert!(r.dismissed.is_empty());
        assert_eq!(r.selected, "VPN-A");
    }

    #[test]
    fn legacy_single_server_joins_the_list() {
        let cisco = [host("VPN-A", "a.example.com")];
        let r = merge(&request(vec![], "legacy.example.com"), &cisco, &Preferences::default());
        assert_eq!(r.servers[0], plain_new("legacy.example.com"));
        assert_eq!(r.selected, "legacy.example.com");
        assert_eq!(r.servers[1].target(), "VPN-A");
    }

    #[test]
    fn nothing_anywhere_gives_empty_list() {
        let r = merge(&request(vec![], ""), &[], &Preferences::default());
        assert!(r.servers.is_empty());
        assert_eq!(r.selected, "");
        assert!(!r.changed);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ac-cisco-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_files_dedups_and_skips_subdirectories() {
        let dir = temp_dir("read");
        let p = dir.join("profile");
        std::fs::create_dir_all(p.join("mgmttun")).unwrap();
        std::fs::write(p.join("b.xml"), profile("<HostEntry><HostName>VPN-A</HostName><HostAddress>a2.example.com</HostAddress></HostEntry><HostEntry><HostName>VPN-C</HostName><HostAddress>c.example.com</HostAddress></HostEntry>")).unwrap();
        std::fs::write(p.join("a.xml"), profile("<HostEntry><HostName>VPN-A</HostName><HostAddress>a.example.com</HostAddress></HostEntry>")).unwrap();
        std::fs::write(p.join("mgmttun").join("m.xml"), profile("<HostEntry><HostName>VPN-M</HostName><HostAddress>m.example.com</HostAddress></HostEntry>")).unwrap();
        std::fs::write(p.join("notes.txt"), "<HostEntry><HostName>VPN-T</HostName></HostEntry>").unwrap();
        let prefs_file = dir.join(".anyconnect_global");
        std::fs::write(&prefs_file, "<AnyConnectPreferences><DefaultHostName>c.example.com</DefaultHostName><DefaultUser>user1</DefaultUser></AnyConnectPreferences>").unwrap();
        let old = dir.join(".anyconnect");
        std::fs::write(&old, "<AnyConnectPreferences><DefaultHostName></DefaultHostName><DefaultGroup>Staff</DefaultGroup></AnyConnectPreferences>").unwrap();

        let entries = read_profiles(&[p.to_string_lossy().into(), dir.join("missing").to_string_lossy().into()]);
        assert_eq!(entries, vec![host("VPN-A", "a.example.com"), host("VPN-C", "c.example.com")]);
        let files = vec![old.to_string_lossy().to_string(), prefs_file.to_string_lossy().to_string(), "/nonexistent".to_string()];
        let prefs = read_preferences(&files);
        assert_eq!(prefs.host_name, "c.example.com");
        assert_eq!(prefs.user, "user1");
        assert_eq!(prefs.group, "Staff");

        let r = sync(&SyncRequest { profile_dirs: vec![p.to_string_lossy().into()], preference_files: files, ..Default::default() });
        assert_eq!(r.selected, "VPN-C");
        assert_eq!(r.found, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
