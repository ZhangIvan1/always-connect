//! The Mac's live connections for the Settings 连接 page (DESIGN.md
//! §28.7; moved from Swift to Rust in §32.9): which program talks to
//! which address, whether it goes through the VPN or out the local
//! network, and why. The background service (root) sees every
//! process's sockets through lsof; the route of each remote address is
//! the kernel's own answer over a routing socket (no process per
//! address); the reason comes from what the session set up.
//!
//! Runs only while the page is open (it asks every 5 s); nothing here
//! stays in memory between calls.

use crate::dns_forwarder::{cidr_range, Forwarder};
use std::net::Ipv4Addr;
use std::str::FromStr;

pub struct Context<'a> {
    pub gateway_ips: Vec<String>,
    pub direct_addresses: Vec<String>,
    pub direct_networks: Vec<String>,
    pub names: Option<&'a Forwarder>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub process: String,
    pub pid: i64,
    pub proto: String,
    pub remote: String,
    pub port: u16,
    /// The name it was looked up under, when the split forwarder saw it.
    pub host: Option<String>,
    /// "vpn", "direct" or "local".
    pub via: &'static str,
    pub interface: String,
    pub reason: &'static str,
}

/// (pid, command, protocol, remote address, remote port) from
/// `lsof -F pcPn`; IPv4 remotes only (§28.3), unconnected sockets skipped.
pub fn parse_lsof(output: &str) -> Vec<(i64, String, String, String, u16)> {
    let mut out = Vec::new();
    let (mut pid, mut command, mut proto) = (0i64, String::new(), String::new());
    for line in output.lines() {
        let Some(kind) = line.chars().next() else { continue };
        let value = &line[kind.len_utf8()..];
        match kind {
            'p' => pid = value.parse().unwrap_or(0),
            'c' => command = value.to_string(),
            'P' => proto = value.to_string(),
            'n' => {
                // "local->remote"; unconnected sockets have no arrow.
                let Some((_, remote)) = value.split_once("->") else { continue };
                let Some((host, port)) = remote.rsplit_once(':') else { continue };
                if Ipv4Addr::from_str(host).is_err() {
                    continue;
                }
                out.push((pid, command.clone(), proto.clone(), host.to_string(), port.parse().unwrap_or(0)));
            }
            _ => {}
        }
    }
    out
}

fn in_range(ip: u32, cidr: &str) -> bool {
    cidr_range(cidr).is_some_and(|(lo, hi)| lo <= ip && ip <= hi)
}

/// Why `ip` (routed out `iface`) goes where it goes.
pub fn classify(ip: &str, iface: &str, c: &Context, attached: Option<(u32, u32)>) -> (&'static str, &'static str) {
    if iface == "lo0" || ip.starts_with("127.") {
        return ("local", "本机");
    }
    if iface.starts_with("utun") || iface.starts_with("ipsec") || iface.starts_with("ppp") {
        return ("vpn", "VPN");
    }
    if c.gateway_ips.iter().any(|g| g == ip) {
        return ("direct", "VPN 隧道本身");
    }
    if c.direct_addresses.iter().any(|a| a == ip) {
        return ("direct", "名单直连");
    }
    let value = Ipv4Addr::from_str(ip).ok().map(u32::from);
    if let Some(v) = value {
        if c.direct_networks.iter().any(|n| in_range(v, n)) {
            return ("direct", "局域网");
        }
        if let Some((lo, hi)) = attached {
            if lo <= v && v <= hi {
                return ("direct", "本地局域网");
            }
        }
    }
    ("direct", "直连")
}

/// The IPv4 network an interface sits on, from its own address and mask.
pub fn attached_network(interface: &str) -> Option<(u32, u32)> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let e = unsafe { &*cursor };
        cursor = e.ifa_next;
        if e.ifa_addr.is_null() || e.ifa_netmask.is_null() || unsafe { (*e.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        if unsafe { std::ffi::CStr::from_ptr(e.ifa_name) }.to_bytes() != interface.as_bytes() {
            continue;
        }
        let a = u32::from_be(unsafe { (*(e.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr });
        let m = u32::from_be(unsafe { (*(e.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr });
        found = Some((a & m, (a & m) | !m));
        break;
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

/// The interface the kernel routes `ip` through: RTM_GET with RTA_IFP
/// over a routing socket, about 10 µs a lookup; same answer as
/// `route -n get`.
#[cfg(target_os = "macos")]
pub fn route_interface(ip: &str) -> Option<String> {
    lookup(Ipv4Addr::from_str(ip).ok()?, None)
}

/// The default route's interface, exactly as `route -n get default`
/// asks (destination 0.0.0.0 with netmask 0.0.0.0, not a longest-prefix
/// match that a 0/1 tunnel route would win).
#[cfg(target_os = "macos")]
pub fn default_route_interface() -> Option<String> {
    lookup(Ipv4Addr::UNSPECIFIED, Some(Ipv4Addr::UNSPECIFIED))
}

#[cfg(not(target_os = "macos"))]
pub fn default_route_interface() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn lookup(addr: Ipv4Addr, netmask: Option<Ipv4Addr>) -> Option<String> {
    use std::mem::size_of;
    fn pad(n: usize) -> usize {
        if n > 0 { 1 + ((n - 1) | (size_of::<u32>() - 1)) } else { size_of::<u32>() }
    }
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET) };
    if fd < 0 {
        return None;
    }
    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let _guard = Fd(fd);
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void,
                         size_of::<libc::timeval>() as libc::socklen_t)
    };
    let header = size_of::<libc::rt_msghdr>();
    let mut dst: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    dst.sin_len = size_of::<libc::sockaddr_in>() as u8;
    dst.sin_family = libc::AF_INET as u8;
    dst.sin_addr.s_addr = u32::from(addr).to_be();
    let mut ifp: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
    ifp.sdl_len = size_of::<libc::sockaddr_dl>() as u8;
    ifp.sdl_family = libc::AF_LINK as u8;
    let mut mask: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    mask.sin_len = size_of::<libc::sockaddr_in>() as u8;
    mask.sin_family = libc::AF_INET as u8;
    if let Some(m) = netmask {
        mask.sin_addr.s_addr = u32::from(m).to_be();
    }
    let mask_len = if netmask.is_some() { pad(mask.sin_len as usize) } else { 0 };
    let total = header + pad(dst.sin_len as usize) + mask_len + pad(ifp.sdl_len as usize);
    let mut buf = [0u8; 1024];
    let seq: i32 = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(1) | 1) as i32 & i32::MAX;
    let pid = unsafe { libc::getpid() };
    unsafe {
        let h = buf.as_mut_ptr() as *mut libc::rt_msghdr;
        (*h).rtm_msglen = total as u16;
        (*h).rtm_version = libc::RTM_VERSION as u8;
        (*h).rtm_type = libc::RTM_GET as u8;
        (*h).rtm_addrs = libc::RTA_DST | libc::RTA_IFP | if netmask.is_some() { libc::RTA_NETMASK } else { 0 };
        (*h).rtm_seq = seq;
        (*h).rtm_pid = pid;
        std::ptr::copy_nonoverlapping(&dst as *const _ as *const u8, buf.as_mut_ptr().add(header), dst.sin_len as usize);
        // Sockaddrs in RTA bit order: DST (0), NETMASK (2), IFP (4).
        let mut off = header + pad(dst.sin_len as usize);
        if netmask.is_some() {
            std::ptr::copy_nonoverlapping(&mask as *const _ as *const u8, buf.as_mut_ptr().add(off), mask.sin_len as usize);
            off += mask_len;
        }
        std::ptr::copy_nonoverlapping(&ifp as *const _ as *const u8, buf.as_mut_ptr().add(off), ifp.sdl_len as usize);
    }
    if unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, total) } != total as isize {
        return None;
    }
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= header as isize {
            return None;
        }
        let n = n as usize;
        let h = unsafe { &*(buf.as_ptr() as *const libc::rt_msghdr) };
        if h.rtm_seq != seq || h.rtm_pid != pid {
            continue;
        }
        let mut off = header;
        for bit in 0..libc::RTAX_MAX {
            if h.rtm_addrs & (1 << bit) == 0 {
                continue;
            }
            if off >= n {
                break;
            }
            let sa = unsafe { &*(buf.as_ptr().add(off) as *const libc::sockaddr) };
            if 1 << bit == libc::RTA_IFP && sa.sa_family as i32 == libc::AF_LINK {
                let dl = unsafe { &*(buf.as_ptr().add(off) as *const libc::sockaddr_dl) };
                let len = dl.sdl_nlen as usize;
                let start = off + 8; // sdl_data
                if start + len <= n {
                    return Some(String::from_utf8_lossy(&buf[start..start + len]).into_owned());
                }
            }
            off += pad(sa.sa_len as usize);
        }
        return None;
    }
}

#[cfg(not(target_os = "macos"))]
pub fn route_interface(_ip: &str) -> Option<String> {
    None
}

fn lsof() -> String {
    std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-iUDP", "+c", "0", "-F", "pcPn"])
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn rows(lsof_output: &str, c: &Context) -> Vec<Row> {
    let mut attached: std::collections::HashMap<String, Option<(u32, u32)>> = Default::default();
    parse_lsof(lsof_output)
        .into_iter()
        .map(|(pid, process, proto, remote, port)| {
            let iface = route_interface(&remote).unwrap_or_else(|| "?".into());
            let net = *attached.entry(iface.clone()).or_insert_with(|| attached_network(&iface));
            let (via, reason) = classify(&remote, &iface, c, net);
            let host = c.names.and_then(|f| Ipv4Addr::from_str(&remote).ok().and_then(|ip| f.name_for(ip)));
            Row { process, pid, proto, remote, port, host, via, interface: iface, reason }
        })
        .collect()
}

pub fn list(c: &Context) -> Vec<Row> {
    rows(&lsof(), c)
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The rows as the App's ConnectionRow array (Models.swift).
pub fn to_json(rows: &[Row]) -> String {
    let mut out = String::from("[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"process\":");
        json_string(&r.process, &mut out);
        out.push_str(&format!(",\"pid\":{},\"proto\":", r.pid));
        json_string(&r.proto, &mut out);
        out.push_str(",\"remote\":");
        json_string(&r.remote, &mut out);
        out.push_str(&format!(",\"port\":{}", r.port));
        if let Some(h) = &r.host {
            out.push_str(",\"host\":");
            json_string(h, &mut out);
        }
        out.push_str(",\"via\":");
        json_string(r.via, &mut out);
        out.push_str(",\"interface\":");
        json_string(&r.interface, &mut out);
        out.push_str(",\"reason\":");
        json_string(r.reason, &mut out);
        out.push('}');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context<'static> {
        Context {
            gateway_ips: vec!["198.51.100.7".into()],
            direct_addresses: vec!["203.0.113.9".into()],
            direct_networks: vec!["192.168.0.0/16".into()],
            names: None,
        }
    }

    #[test]
    fn classification() {
        let c = ctx();
        assert_eq!(classify("127.0.0.1", "lo0", &c, None), ("local", "本机"));
        assert_eq!(classify("8.8.8.8", "utun6", &c, None), ("vpn", "VPN"));
        assert_eq!(classify("198.51.100.7", "en0", &c, None), ("direct", "VPN 隧道本身"));
        assert_eq!(classify("203.0.113.9", "en0", &c, None), ("direct", "名单直连"));
        assert_eq!(classify("192.168.100.1", "en0", &c, None), ("direct", "局域网"));
        assert_eq!(classify("10.0.0.9", "en0", &c, cidr_range("10.0.0.0/24")), ("direct", "本地局域网"));
        assert_eq!(classify("93.184.216.34", "en9", &c, None), ("direct", "直连"));
    }

    #[test]
    fn lsof_fields_and_json() {
        let out = "p42\ncSafari Helper\nPTCP\nn10.0.0.2:5000->93.184.216.34:443\nn*:5353\nPUDP\nn[::1]:1->[::1]:2\np7\ncdig\nPUDP\nn10.0.0.2:6000->127.0.0.1:53\n";
        let parsed = parse_lsof(out);
        assert_eq!(parsed, vec![
            (42, "Safari Helper".into(), "TCP".into(), "93.184.216.34".into(), 443),
            (7, "dig".into(), "UDP".into(), "127.0.0.1".into(), 53),
        ]);
        let json = to_json(&[Row {
            process: "a\"b".into(), pid: 1, proto: "TCP".into(), remote: "1.2.3.4".into(), port: 443,
            host: Some("x.example".into()), via: "direct", interface: "en0".into(), reason: "直连",
        }]);
        assert_eq!(json, "[{\"process\":\"a\\\"b\",\"pid\":1,\"proto\":\"TCP\",\"remote\":\"1.2.3.4\",\"port\":443,\
\"host\":\"x.example\",\"via\":\"direct\",\"interface\":\"en0\",\"reason\":\"直连\"}]");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_route_lookup() {
        assert_eq!(route_interface("127.0.0.1").as_deref(), Some("lo0"));
        let out = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let want = text.lines().find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string));
        assert_eq!(default_route_interface(), want, "same answer as route -n get default");
        let t = std::time::Instant::now();
        for _ in 0..500 {
            let _ = route_interface("8.8.8.8");
        }
        assert!(t.elapsed().as_secs_f64() < 1.0);
    }
}
