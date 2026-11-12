//! Speeds for the Settings 连接 page and the menu-bar panel (DESIGN.md §四十五): how fast each
//! connection moves data, and the totals through the VPN and out the
//! local network.
//!
//! Per connection: `nettop` (the system's own per-socket byte counters,
//! readable without root) once per page refresh; a socket's speed is its
//! byte count's change since the previous refresh. Totals: the kernel's
//! 64-bit interface counters (sysctl NET_RT_IFLIST2), no process. The
//! VPN total is the tunnel interfaces the VPN rows use; the direct total
//! is the physical interfaces the direct rows use, minus the VPN's own
//! carrier (rows to the gateway), so tunnelled traffic is not counted
//! twice.
//!
//! Runs only while the page is open: the App calls `sample` on each
//! refresh and `stop` when the page closes, which drops the one previous
//! snapshot kept between calls.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

/// One input row, as the background service listed it (ConnectionRow).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RowIn {
    pub pid: i64,
    pub proto: String,
    pub remote: String,
    pub port: u16,
    pub via: String,
    pub interface: String,
    pub reason: String,
}

/// Bytes per second; `rows` is parallel to the input rows.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Speeds {
    /// False on the first sample: nothing to compare with yet.
    pub ready: bool,
    pub rows: Vec<[u64; 2]>,
    pub vpn: [u64; 2],
    pub direct: [u64; 2],
}

/// (pid, "TCP"/"UDP", remote address, remote port): what a page row
/// knows. Several sockets (different local ports) can share one.
type RowKey = (i64, String, String, u16);
/// A socket: the row key plus the local port.
type SocketKey = (RowKey, u16);

/// Per-socket cumulative (in, out) from `nettop -L 1 -n -x -J
/// bytes_in,bytes_out`: a process line "name.pid,in,out," followed by
/// its sockets "tcp4 a.b.c.d:lport<->e.f.g.h:rport,in,out,". IPv4 with a
/// known remote only (the page lists IPv4, §28.3).
pub fn parse_nettop(output: &str) -> HashMap<SocketKey, (u64, u64)> {
    let mut out = HashMap::new();
    let mut pid = 0i64;
    for line in output.lines() {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 || fields[0].is_empty() {
            continue;
        }
        let head = fields[0];
        let (Ok(bytes_in), Ok(bytes_out)) = (fields[1].parse::<u64>(), fields[2].parse::<u64>()) else {
            continue;
        };
        let proto = if head.starts_with("tcp4 ") {
            "TCP"
        } else if head.starts_with("udp4 ") {
            "UDP"
        } else {
            if !head.starts_with("tcp6 ") && !head.starts_with("udp6 ") {
                // A process line: the pid is after the last dot.
                pid = head.rsplit_once('.').and_then(|(_, p)| p.parse().ok()).unwrap_or(0);
            }
            continue;
        };
        let Some((local, remote)) = head[5..].split_once("<->") else { continue };
        let (Some((_, lport)), Some((rip, rport))) = (local.rsplit_once(':'), remote.rsplit_once(':')) else {
            continue;
        };
        let (Ok(lport), Ok(rport)) = (lport.parse::<u16>(), rport.parse::<u16>()) else { continue };
        if rip.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        *out.entry(((pid, proto.to_string(), rip.to_string(), rport), lport)).or_insert((0, 0)) = (bytes_in, bytes_out);
    }
    out
}

/// One interface's cumulative counters, 64-bit.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IfCount {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

/// Every interface's cumulative counters.
#[cfg(target_os = "macos")]
pub fn interface_counters() -> HashMap<String, IfCount> {
    let mut out = HashMap::new();
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    let mut len: libc::size_t = 0;
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return out;
    }
    let mut buffer = vec![0u8; len];
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, buffer.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return out;
    }
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::if_msghdr>() <= len {
        let header = unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::if_msghdr>()) };
        let step = header.ifm_msglen as usize;
        if step == 0 {
            break;
        }
        if header.ifm_type as i32 == libc::RTM_IFINFO2 && offset + std::mem::size_of::<libc::if_msghdr2>() <= len {
            let info = unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::if_msghdr2>()) };
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            if !unsafe { libc::if_indextoname(info.ifm_index as u32, name.as_mut_ptr()) }.is_null() {
                let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned();
                let d = info.ifm_data;
                out.insert(name, IfCount {
                    bytes_in: d.ifi_ibytes,
                    bytes_out: d.ifi_obytes,
                    packets_in: d.ifi_ipackets,
                    packets_out: d.ifi_opackets,
                });
            }
        }
        offset += step;
    }
    out
}

#[cfg(not(target_os = "macos"))]
pub fn interface_counters() -> HashMap<String, IfCount> {
    HashMap::new()
}

/// The previous snapshot: when, sockets, interfaces.
pub struct Snapshot {
    pub at: Instant,
    pub sockets: HashMap<SocketKey, (u64, u64)>,
    pub interfaces: HashMap<String, IfCount>,
}

fn per_second(delta: u64, seconds: f64) -> u64 {
    (delta as f64 / seconds).round() as u64
}

/// The speeds between `before` and `now` for `rows`. A socket new since
/// `before` moved all its bytes in between; a counter that went down (a
/// reused key) counts from zero.
pub fn speeds(before: Option<&Snapshot>, now: &Snapshot, rows: &[RowIn]) -> Speeds {
    let Some(before) = before else {
        return Speeds { ready: false, rows: vec![[0, 0]; rows.len()], vpn: [0, 0], direct: [0, 0] };
    };
    let seconds = now.at.duration_since(before.at).as_secs_f64().max(0.5);
    let delta = |old: Option<&(u64, u64)>, new: &(u64, u64)| -> (u64, u64) {
        let (oi, oo) = old.copied().unwrap_or((0, 0));
        (if new.0 >= oi { new.0 - oi } else { new.0 }, if new.1 >= oo { new.1 - oo } else { new.1 })
    };
    // Sockets summed per row key.
    let mut by_row: HashMap<&RowKey, (u64, u64)> = HashMap::new();
    for (key, counts) in &now.sockets {
        let (d_in, d_out) = delta(before.sockets.get(key), counts);
        let entry = by_row.entry(&key.0).or_insert((0, 0));
        entry.0 += d_in;
        entry.1 += d_out;
    }
    // One rate per key: rows repeating a key (the page groups them) get 0.
    let mut seen: HashSet<RowKey> = HashSet::new();
    let row_rates: Vec<[u64; 2]> = rows
        .iter()
        .map(|r| {
            let key: RowKey = (r.pid, r.proto.to_uppercase(), r.remote.clone(), r.port);
            if !seen.insert(key.clone()) {
                return [0, 0];
            }
            by_row.get(&key).map(|(i, o)| [per_second(*i, seconds), per_second(*o, seconds)]).unwrap_or([0, 0])
        })
        .collect();
    let interface_rate = |names: &HashSet<&str>| -> [u64; 2] {
        let (mut i, mut o) = (0u64, 0u64);
        for name in names {
            if let Some(c) = now.interfaces.get(*name) {
                let old = before.interfaces.get(*name).map(|o| (o.bytes_in, o.bytes_out));
                let (di, dout) = delta(old.as_ref(), &(c.bytes_in, c.bytes_out));
                i += di;
                o += dout;
            }
        }
        [per_second(i, seconds), per_second(o, seconds)]
    };
    let vpn_ifaces: HashSet<&str> = rows.iter().filter(|r| r.via == "vpn").map(|r| r.interface.as_str()).collect();
    let direct_ifaces: HashSet<&str> =
        rows.iter().filter(|r| r.via == "direct" && !vpn_ifaces.contains(r.interface.as_str())).map(|r| r.interface.as_str()).collect();
    let vpn = interface_rate(&vpn_ifaces);
    let physical = interface_rate(&direct_ifaces);
    let carrier = rows.iter().zip(&row_rates).filter(|(r, _)| r.reason == "VPN 隧道本身").fold([0u64, 0u64], |acc, (_, rate)| {
        [acc[0] + rate[0], acc[1] + rate[1]]
    });
    let direct = [physical[0].saturating_sub(carrier[0]), physical[1].saturating_sub(carrier[1])];
    Speeds { ready: true, rows: row_rates, vpn, direct }
}

/// Totals for the menu-bar panel's 网速 card (§45.4), bytes per second: everything on the
/// wired/Wi-Fi interfaces, the tunnel interfaces, and the direct part.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Totals {
    pub ready: bool,
    pub total: [u64; 2],
    pub vpn: [u64; 2],
    pub direct: [u64; 2],
}

/// Bytes a tunnelled packet costs on the wire beyond its own size: IP
/// and UDP headers, the DTLS record and the AES-GCM nonce and tag
/// (20 + 8 + 13 + 8 + 16, plus the 1-byte type). An estimate: the panel
/// does not run nettop, so it cannot see the carrier socket (§45.1).
pub const TUNNEL_OVERHEAD: u64 = 66;

fn is_physical(name: &str) -> bool {
    name.starts_with("en")
}

fn is_tunnel(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("ppp")
}

/// Totals between two interface snapshots `seconds` apart. Direct is the
/// physical traffic minus the tunnel's carrier (tunnel bytes plus the
/// per-packet overhead), never below zero.
pub fn totals(before: Option<&HashMap<String, IfCount>>, now: &HashMap<String, IfCount>, seconds: f64) -> Totals {
    let Some(before) = before else {
        return Totals { ready: false, total: [0, 0], vpn: [0, 0], direct: [0, 0] };
    };
    let seconds = seconds.max(0.5);
    let grow = |new: u64, old: u64| if new >= old { new - old } else { new };
    let (mut physical, mut tunnel, mut packets) = ([0u64; 2], [0u64; 2], [0u64; 2]);
    for (name, c) in now {
        let o = before.get(name).copied().unwrap_or_default();
        let bytes = [grow(c.bytes_in, o.bytes_in), grow(c.bytes_out, o.bytes_out)];
        if is_physical(name) {
            physical = [physical[0] + bytes[0], physical[1] + bytes[1]];
        } else if is_tunnel(name) {
            tunnel = [tunnel[0] + bytes[0], tunnel[1] + bytes[1]];
            packets = [packets[0] + grow(c.packets_in, o.packets_in), packets[1] + grow(c.packets_out, o.packets_out)];
        }
    }
    let carrier = [tunnel[0] + packets[0] * TUNNEL_OVERHEAD, tunnel[1] + packets[1] * TUNNEL_OVERHEAD];
    let rate = |v: [u64; 2]| [per_second(v[0], seconds), per_second(v[1], seconds)];
    Totals {
        ready: true,
        total: rate(physical),
        vpn: rate(tunnel),
        direct: rate([physical[0].saturating_sub(carrier[0]), physical[1].saturating_sub(carrier[1])]),
    }
}

static PREVIOUS_TOTALS: Mutex<Option<(Instant, HashMap<String, IfCount>)>> = Mutex::new(None);

/// The panel's totals since its previous call (no process, one sysctl).
pub fn sample_totals() -> Totals {
    let now = (Instant::now(), interface_counters());
    let mut previous = PREVIOUS_TOTALS.lock().unwrap();
    let result = match previous.as_ref() {
        Some((at, counts)) => totals(Some(counts), &now.1, now.0.duration_since(*at).as_secs_f64()),
        None => totals(None, &now.1, 0.0),
    };
    *previous = Some(now);
    result
}

/// The panel closed: the snapshot goes.
pub fn stop_totals() {
    *PREVIOUS_TOTALS.lock().unwrap() = None;
}

static PREVIOUS: Mutex<Option<Snapshot>> = Mutex::new(None);

fn read_nettop() -> String {
    std::process::Command::new("/usr/bin/nettop")
        .args(["-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Reads the counters now, returns the speeds since the previous call
/// and keeps this snapshot for the next.
pub fn sample(rows: &[RowIn]) -> Speeds {
    let now = Snapshot { at: Instant::now(), sockets: parse_nettop(&read_nettop()), interfaces: interface_counters() };
    let mut previous = PREVIOUS.lock().unwrap();
    let result = speeds(previous.as_ref(), &now, rows);
    *previous = Some(now);
    result
}

/// The page closed: drop the snapshot.
pub fn stop() {
    *PREVIOUS.lock().unwrap() = None;
}

/// JSON in (the ConnectionRow array), JSON out (Speeds); "" on bad input.
pub fn sample_json(rows_json: &str) -> String {
    let Ok(rows) = serde_json::from_str::<Vec<RowIn>>(rows_json) else { return String::new() };
    serde_json::to_string(&sample(&rows)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SAMPLE: &str = ",bytes_in,bytes_out,\n\
        Safari.501,3000,700,\n\
        tcp4 10.0.0.2:50001<->93.184.215.14:443,2000,500,\n\
        tcp4 10.0.0.2:50002<->93.184.215.14:443,1000,200,\n\
        tcp6 fe80::1.50003<->fe80::2.443,9,9,\n\
        com.example.Work.Helper.77,10,10,\n\
        udp4 10.0.0.2:60000<->203.0.113.10:443,10,10,\n\
        udp4 *:5353<->*:*,5,5,\n";

    fn ifc(bytes_in: u64, bytes_out: u64) -> IfCount {
        IfCount { bytes_in, bytes_out, ..Default::default() }
    }

    fn row(pid: i64, proto: &str, remote: &str, port: u16, via: &str, iface: &str, reason: &str) -> RowIn {
        RowIn {
            pid,
            proto: proto.into(),
            remote: remote.into(),
            port,
            via: via.into(),
            interface: iface.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn parses_sockets_under_their_process() {
        let s = parse_nettop(SAMPLE);
        assert_eq!(s.len(), 3);
        assert_eq!(s[&((501, "TCP".into(), "93.184.215.14".into(), 443), 50002)], (1000, 200));
        // A process name with dots: the pid is after the last one.
        assert_eq!(s[&((77, "UDP".into(), "203.0.113.10".into(), 443), 60000)], (10, 10));
    }

    #[test]
    fn first_sample_is_not_ready() {
        let now = Snapshot { at: Instant::now(), sockets: parse_nettop(SAMPLE), interfaces: HashMap::new() };
        let s = speeds(None, &now, &[row(501, "TCP", "93.184.215.14", 443, "vpn", "utun4", "VPN")]);
        assert!(!s.ready);
        assert_eq!(s.rows, vec![[0, 0]]);
    }

    #[test]
    fn rates_per_row_key_and_totals() {
        let t0 = Instant::now();
        let before = Snapshot {
            at: t0,
            sockets: parse_nettop(SAMPLE),
            interfaces: HashMap::from([
                ("utun4".to_string(), ifc(1_000, 1_000)),
                ("en0".to_string(), ifc(10_000, 10_000)),
            ]),
        };
        let later = SAMPLE
            .replace("50001<->93.184.215.14:443,2000,500", "50001<->93.184.215.14:443,12000,2500")
            .replace("60000<->203.0.113.10:443,10,10", "60000<->203.0.113.10:443,5010,1010")
            + "tcp4 10.0.0.2:50100<->192.0.2.1:443,0,0,\n";
        let mut sockets = parse_nettop(&later);
        // The gateway carrier, a socket new since `before`.
        sockets.insert(((9, "UDP".into(), "192.0.2.1".into(), 443), 40000), (20_000, 4_000));
        let now = Snapshot {
            at: t0 + Duration::from_secs(5),
            sockets,
            interfaces: HashMap::from([
                ("utun4".to_string(), ifc(51_000, 11_000)),
                ("en0".to_string(), ifc(60_000, 20_000)),
            ]),
        };
        let rows = vec![
            row(501, "TCP", "93.184.215.14", 443, "vpn", "utun4", "VPN"),
            // The second socket to the same address: the page groups the
            // two rows, so only one carries the rate.
            row(501, "TCP", "93.184.215.14", 443, "vpn", "utun4", "VPN"),
            row(77, "UDP", "203.0.113.10", 443, "direct", "en0", "名单直连"),
            row(9, "UDP", "192.0.2.1", 443, "direct", "en0", "VPN 隧道本身"),
            row(501, "TCP", "198.51.100.1", 443, "vpn", "utun4", "VPN"),
        ];
        let s = speeds(Some(&before), &now, &rows);
        assert!(s.ready);
        assert_eq!(s.rows[0], [2_000, 400]);
        assert_eq!(s.rows[1], [0, 0]);
        assert_eq!(s.rows[2], [1_000, 200]);
        assert_eq!(s.rows[3], [4_000, 800]);
        assert_eq!(s.rows[4], [0, 0], "a row nettop does not list has no speed");
        assert_eq!(s.vpn, [10_000, 2_000]);
        // en0 moved 50000/10000 in 5 s; 4000/800 of it per second was the tunnel.
        assert_eq!(s.direct, [10_000 - 4_000, 2_000 - 800]);
    }

    #[test]
    fn a_counter_that_went_down_counts_from_zero() {
        let t0 = Instant::now();
        let key: SocketKey = ((1, "TCP".into(), "198.51.100.1".into(), 443), 1);
        let before = Snapshot { at: t0, sockets: HashMap::from([(key.clone(), (9_000, 9_000))]), interfaces: HashMap::new() };
        let now = Snapshot {
            at: t0 + Duration::from_secs(2),
            sockets: HashMap::from([(key, (400, 200))]),
            interfaces: HashMap::new(),
        };
        let s = speeds(Some(&before), &now, &[row(1, "TCP", "198.51.100.1", 443, "vpn", "utun4", "VPN")]);
        assert_eq!(s.rows[0], [200, 100]);
    }

    #[test]
    fn bad_json_is_empty() {
        assert_eq!(sample_json("not json"), "");
    }

    #[test]
    fn totals_split_physical_into_tunnel_carrier_and_direct() {
        let before = HashMap::from([
            ("en0".to_string(), IfCount { bytes_in: 0, bytes_out: 0, packets_in: 0, packets_out: 0 }),
            ("utun4".to_string(), IfCount::default()),
            ("lo0".to_string(), IfCount::default()),
        ]);
        let now = HashMap::from([
            // 2 s: en0 got 300 000 in / 60 000 out.
            ("en0".to_string(), IfCount { bytes_in: 300_000, bytes_out: 60_000, packets_in: 250, packets_out: 120 }),
            // The tunnel carried 100 000 in 100 packets / 20 000 out in 50.
            ("utun4".to_string(), IfCount { bytes_in: 100_000, bytes_out: 20_000, packets_in: 100, packets_out: 50 }),
            ("lo0".to_string(), IfCount { bytes_in: 9_999_999, bytes_out: 9_999_999, packets_in: 1, packets_out: 1 }),
        ]);
        let t = totals(Some(&before), &now, 2.0);
        assert!(t.ready);
        assert_eq!(t.total, [150_000, 30_000]);
        assert_eq!(t.vpn, [50_000, 10_000]);
        let carrier_in = 100_000 + 100 * TUNNEL_OVERHEAD;
        let carrier_out = 20_000 + 50 * TUNNEL_OVERHEAD;
        assert_eq!(t.direct, [(300_000 - carrier_in) / 2, (60_000 - carrier_out) / 2]);
        assert!(!totals(None, &now, 0.0).ready);
        // All traffic tunnelled: direct floors at zero, not negative.
        let only_tunnel = HashMap::from([("en0".to_string(), IfCount { bytes_in: 1_000, ..Default::default() }),
            ("utun4".to_string(), IfCount { bytes_in: 1_000, packets_in: 10, ..Default::default() })]);
        assert_eq!(totals(Some(&HashMap::new()), &only_tunnel, 1.0).direct, [0, 0]);
    }

    /// On a real Mac: `cargo test live_totals -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_totals() {
        let start = Instant::now();
        for _ in 0..1000 {
            sample_totals();
        }
        let each = start.elapsed() / 1000;
        println!("sample_totals: {:?} per call; {:?}", each, sample_totals());
        stop_totals();
    }

    /// On a real Mac: `cargo test live_sample -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_sample() {
        let first = sample(&[]);
        std::thread::sleep(Duration::from_secs(2));
        let start = Instant::now();
        let raw = read_nettop();
        let took = start.elapsed();
        let second = sample(&[]);
        println!("first ready={} second ready={} sockets={} nettop {:?}", first.ready, second.ready, parse_nettop(&raw).len(), took);
        assert!(!first.ready && second.ready && !parse_nettop(&raw).is_empty());
        stop();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn interface_counters_include_loopback() {
        assert!(interface_counters().contains_key("lo0"));
    }
}
