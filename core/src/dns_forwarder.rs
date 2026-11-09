//! The domain split's DNS forwarder (DESIGN.md §26.4, §26.13, §28.3;
//! moved from Swift to Rust in §32.6).
//!
//! The system resolver asks this forwarder first (127.0.0.1, with the
//! tunnel's DNS servers listed after it, so a forwarder that is down
//! costs the split, never the network). For a name on the direct list
//! it asks the local network's DNS through the physical interface and,
//! before handing the answer back, reports every IPv4 address in it
//! (`on_direct`), which must return only once they are routed direct.
//! Every other name goes to the tunnel's DNS servers, one after the
//! other, over UDP and then TCP (also when the UDP answer is truncated).
//!
//! The tunnel carries IPv4 only and pf drops IPv6 out of the Mac in
//! split mode, so AAAA answers are empty for every name. HTTPS and SVCB
//! answers pass with their address hints taken out (§42), so a client
//! connects only to what an A query returned, which is routed first.
//!
//! Threads: one waits (poll, no timeout) on the UDP and TCP sockets and
//! drains whatever is ready; queries are answered by pooled workers with
//! a small stack, at most `MAX_INFLIGHT` at a time (more are dropped: the
//! client retries), which leave after 30 s without work. Idle, the
//! forwarder is one parked thread and wakes for nothing.

use regex_lite::Regex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_SRV: u16 = 33;
const TYPE_DNAME: u16 = 39;
/// SvcParamKeys (RFC 9460 §14.3.2).
const SVC_MANDATORY: u16 = 0;
const SVC_IPV4HINT: u16 = 4;
const SVC_IPV6HINT: u16 = 6;

const MAX_INFLIGHT: usize = 64;
const WORKER_STACK: usize = 128 * 1024;
/// How long a worker waits for the next query before it leaves.
const WORKER_IDLE: Duration = Duration::from_secs(30);
/// Recently answered addresses kept for the connections page (§28.7).
const NAME_CACHE_LIMIT: usize = 4096;

// MARK: - Wire format (RFC 1035), just enough for the forwarder

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

/// (name, offset after the name in its own position), following
/// compression pointers with a hop limit.
pub fn read_name(m: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = start;
    let mut end: Option<usize> = None;
    let mut hops = 0;
    while at < m.len() {
        let len = m[at] as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        }
        if len & 0xC0 == 0xC0 {
            if at + 1 >= m.len() || hops >= 16 {
                return None;
            }
            if end.is_none() {
                end = Some(at + 2);
            }
            at = ((len & 0x3F) << 8) | m[at + 1] as usize;
            hops += 1;
            continue;
        }
        if at + 1 + len > m.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&m[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    None
}

pub fn question(m: &[u8]) -> Option<Question> {
    if m.len() < 12 || ((m[4] as usize) << 8 | m[5] as usize) < 1 {
        return None;
    }
    let (name, end) = read_name(m, 12)?;
    if end + 4 > m.len() {
        return None;
    }
    Some(Question { name, qtype: (m[end] as u16) << 8 | m[end + 1] as u16 })
}

pub fn is_truncated(m: &[u8]) -> bool {
    m.len() >= 3 && m[2] & 0x02 != 0
}

/// The query turned into a NOERROR answer with no records.
pub fn empty_answer(query: &[u8]) -> Option<Vec<u8>> {
    let (_, end) = read_name(query, 12)?;
    if end + 4 > query.len() {
        return None;
    }
    let mut out = query[..end + 4].to_vec();
    out[2] = 0x80 | (query[2] & 0x01); // QR, keep RD
    out[3] = 0x80; // RA, NOERROR
    out[4] = 0;
    out[5] = 1; // one question
    for b in &mut out[6..12] {
        *b = 0; // no answer/authority/additional records
    }
    Some(out)
}

/// Every A record in the answer section (CNAME chains included).
pub fn ipv4_answers(m: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if m.len() < 12 {
        return out;
    }
    let qd = (m[4] as usize) << 8 | m[5] as usize;
    let an = (m[6] as usize) << 8 | m[7] as usize;
    let mut at = 12;
    for _ in 0..qd {
        match read_name(m, at) {
            Some((_, end)) => at = end + 4,
            None => return out,
        }
    }
    for _ in 0..an {
        let Some((_, end)) = read_name(m, at) else { break };
        if end + 10 > m.len() {
            break;
        }
        let rtype = (m[end] as u16) << 8 | m[end + 1] as u16;
        let length = (m[end + 8] as usize) << 8 | m[end + 9] as usize;
        let data = end + 10;
        if data + length > m.len() {
            break;
        }
        if rtype == TYPE_A && length == 4 {
            out.push(Ipv4Addr::new(m[data], m[data + 1], m[data + 2], m[data + 3]));
        }
        at = data + length;
    }
    out
}

// MARK: - HTTPS/SVCB answers without addresses (§42)

/// A name as raw labels (compression pointers followed, with a hop
/// limit; 255 bytes at most) and the offset after it in its own place.
fn read_labels(m: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut at = start;
    let mut end = None;
    let mut hops = 0;
    let mut size = 1;
    loop {
        let len = *m.get(at)? as usize;
        if len == 0 {
            return Some((labels, end.unwrap_or(at + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let low = *m.get(at + 1)? as usize;
            if hops >= 16 {
                return None;
            }
            end.get_or_insert(at + 2);
            at = (len & 0x3F) << 8 | low;
            hops += 1;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // extended label types (RFC 6891 obsoleted them)
        }
        let label = m.get(at + 1..at + 1 + len)?;
        size += 1 + len;
        if size > 255 {
            return None;
        }
        labels.push(label.to_vec());
        at += 1 + len;
    }
}

fn is_service(qtype: u16) -> bool {
    qtype == TYPE_HTTPS || qtype == TYPE_SVCB
}

fn same_name(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

type Labels = Vec<Vec<u8>>;

/// A record as it is written back: owner, type/class/TTL, data.
type Record = (Labels, [u8; 8], Vec<Part>);

/// An SVCB record's data: SvcPriority, TargetName, SvcParams, and
/// whether anything was taken out.
type Svcb = (Vec<u8>, Labels, Vec<u8>, bool);

/// A piece of record data as it is written back.
enum Part {
    Bytes(Vec<u8>),
    /// A name that may be compressed (RFC 1035 types).
    Name(Vec<Vec<u8>>),
    /// A name that must not be (SRV, DNAME, SVCB's TargetName).
    Plain(Vec<Vec<u8>>),
}

enum Shape {
    Name(bool),
    Fixed(usize),
}

/// Record data laid out as `shape`, which must cover it exactly.
fn parts(m: &[u8], data: usize, stop: usize, shape: &[Shape]) -> Option<Vec<Part>> {
    let mut at = data;
    let mut out = Vec::new();
    for s in shape {
        match s {
            Shape::Name(compressible) => {
                let (name, end) = read_labels(m, at)?;
                at = end;
                out.push(if *compressible { Part::Name(name) } else { Part::Plain(name) });
            }
            Shape::Fixed(k) => {
                out.push(Part::Bytes(m.get(at..at + k)?.to_vec()));
                at += k;
            }
        }
    }
    (at == stop).then_some(out)
}

/// An SVCB/HTTPS record's data (RFC 9460 §2.2) with ipv4hint and
/// ipv6hint taken out (and out of "mandatory", which may list them).
fn svcb_without_hints(m: &[u8], data: usize, stop: usize) -> Option<Svcb> {
    let priority = m.get(data..data + 2)?.to_vec();
    let (target, mut at) = read_labels(m, data + 2)?;
    let mut params = Vec::new();
    let mut removed = false;
    while at < stop {
        let head = m.get(at..at + 4)?;
        let key = (head[0] as u16) << 8 | head[1] as u16;
        let len = (head[2] as usize) << 8 | head[3] as usize;
        let value = m.get(at + 4..at + 4 + len)?;
        at += 4 + len;
        if key == SVC_IPV4HINT || key == SVC_IPV6HINT {
            removed = true;
            continue;
        }
        let mut value = value.to_vec();
        if key == SVC_MANDATORY {
            if value.len() % 2 != 0 {
                return None;
            }
            let keys: Vec<u8> = value
                .chunks(2)
                .filter(|k| {
                    let k = (k[0] as u16) << 8 | k[1] as u16;
                    k != SVC_IPV4HINT && k != SVC_IPV6HINT
                })
                .flatten()
                .copied()
                .collect();
            if keys.len() != value.len() {
                removed = true;
                if keys.is_empty() {
                    continue;
                }
                value = keys;
            }
        }
        params.extend_from_slice(&[(key >> 8) as u8, key as u8, (value.len() >> 8) as u8, value.len() as u8]);
        params.extend_from_slice(&value);
    }
    (at == stop).then_some((priority, target, params, removed))
}

/// Writes `name`, its longest suffix shared with the question's name as
/// a pointer into the question (the one part whose offsets stay).
fn write_name(out: &mut Vec<u8>, name: &[Vec<u8>], question: &[Vec<u8>], offsets: &[usize]) {
    for i in 0..name.len() {
        let rest = name.len() - i;
        if rest <= question.len() && same_name(&name[i..], &question[question.len() - rest..]) {
            write_plain(out, &name[..i], false);
            let p = offsets[question.len() - rest];
            out.extend_from_slice(&[0xC0 | (p >> 8) as u8, p as u8]);
            return;
        }
    }
    write_plain(out, name, true);
}

fn write_plain(out: &mut Vec<u8>, labels: &[Vec<u8>], terminate: bool) {
    for l in labels {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    if terminate {
        out.push(0);
    }
}

/// The answer to an HTTPS or SVCB query with no addresses left in it
/// (§42): ipv4hint/ipv6hint come out of every HTTPS/SVCB record and A/AAAA
/// records are dropped, so a client connects only to what its own A
/// query returned (which, for a direct name, the forwarder has routed
/// first); everything else (ALPN, ECH, port, ...) passes as sent. The
/// original bytes come back when there is nothing to take out.
///
/// None when the message cannot be read, would come out longer, or, for
/// a name on the direct list (`direct`), holds a record for another name
/// (a CNAME's target, a TargetName other than "."): the client would go
/// on to a name the list may not cover.
pub fn without_addresses(answer: &[u8], direct: bool) -> Option<Vec<u8>> {
    if answer.len() < 12 {
        return None;
    }
    let count = |i: usize| (answer[i] as usize) << 8 | answer[i + 1] as usize;
    if count(4) != 1 {
        return None;
    }
    let (qname, qend) = read_labels(answer, 12)?;
    if qend + 4 > answer.len() {
        return None;
    }
    let mut offsets = Vec::new();
    let mut at = 12;
    for l in &qname {
        offsets.push(at);
        at += 1 + l.len();
    }
    // A question written with a pointer: compress against nothing.
    let anchor: &[Vec<u8>] = if at + 1 == qend { &qname } else { &[] };

    let mut sections: [Vec<Record>; 3] = Default::default();
    let mut changed = false;
    let mut at = qend + 4;
    for (s, section) in sections.iter_mut().enumerate() {
        for _ in 0..count(6 + 2 * s) {
            let (owner, end) = read_labels(answer, at)?;
            let head: [u8; 8] = answer.get(end..end + 8)?.try_into().ok()?;
            let rtype = (head[0] as u16) << 8 | head[1] as u16;
            let length = answer.get(end + 8..end + 10)?;
            let data = end + 10;
            let stop = data + ((length[0] as usize) << 8 | length[1] as usize);
            if stop > answer.len() {
                return None;
            }
            at = stop;
            let p = match rtype {
                TYPE_A | TYPE_AAAA => {
                    changed = true;
                    continue;
                }
                TYPE_SVCB | TYPE_HTTPS => {
                    let (priority, target, params, removed) = svcb_without_hints(answer, data, stop)?;
                    if direct && (!same_name(&owner, &qname) || !target.is_empty()) {
                        return None;
                    }
                    changed |= removed;
                    vec![Part::Bytes(priority), Part::Plain(target), Part::Bytes(params)]
                }
                TYPE_CNAME | TYPE_NS | TYPE_PTR => parts(answer, data, stop, &[Shape::Name(true)])?,
                TYPE_DNAME => parts(answer, data, stop, &[Shape::Name(false)])?,
                TYPE_MX => parts(answer, data, stop, &[Shape::Fixed(2), Shape::Name(true)])?,
                TYPE_SRV => parts(answer, data, stop, &[Shape::Fixed(6), Shape::Name(false)])?,
                TYPE_SOA => parts(answer, data, stop, &[Shape::Name(true), Shape::Name(true), Shape::Fixed(20)])?,
                _ => vec![Part::Bytes(answer[data..stop].to_vec())],
            };
            section.push((owner, head, p));
        }
    }
    if !changed {
        return Some(answer.to_vec());
    }

    let mut out = answer[..12].to_vec();
    for (s, section) in sections.iter().enumerate() {
        out[6 + 2 * s] = (section.len() >> 8) as u8;
        out[7 + 2 * s] = section.len() as u8;
    }
    out.extend_from_slice(&answer[12..qend + 4]);
    for (owner, head, p) in sections.iter().flatten() {
        write_name(&mut out, owner, anchor, &offsets);
        out.extend_from_slice(head);
        let length_at = out.len();
        out.extend_from_slice(&[0, 0]);
        for part in p {
            match part {
                Part::Bytes(b) => out.extend_from_slice(b),
                Part::Name(n) => write_name(&mut out, n, anchor, &offsets),
                Part::Plain(n) => write_plain(&mut out, n, true),
            }
        }
        let length = out.len() - length_at - 2;
        out[length_at] = (length >> 8) as u8;
        out[length_at + 1] = length as u8;
    }
    (out.len() <= answer.len()).then_some(out)
}

// MARK: - The direct list

/// The direct list as the App sends it (§26.13), already expanded from
/// geosite/geoip: "example.com" or "domain:example.com" (the name and
/// its subdomains), "full:" (that name only), "keyword:" (contained
/// anywhere), "regexp:" (a regular expression), and "ipcidr:a.b.c.d/n"
/// (a name whose IPv4 answer falls in it). Anything else is ignored, so
/// an older App's plain list keeps working.
#[derive(Default)]
pub struct SplitRules {
    suffixes: HashSet<String>,
    fulls: HashSet<String>,
    keywords: Vec<String>,
    regexes: Vec<Regex>,
    ranges: Vec<(u32, u32)>,
}

fn trim_domain(s: &str) -> String {
    s.to_lowercase().trim_matches(|c| c == '.' || c == ' ' || c == '*').to_string()
}

fn trim_dots(s: &str) -> String {
    s.to_lowercase().trim_matches('.').to_string()
}

/// "a.b.c.d" as a number.
pub fn ipv4(s: &str) -> Option<u32> {
    Ipv4Addr::from_str(s).ok().map(u32::from)
}

/// "a.b.c.d/n" as (first, last).
pub fn cidr_range(cidr: &str) -> Option<(u32, u32)> {
    let (base, bits) = cidr.split_once('/')?;
    let base = ipv4(base)?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((base & mask, (base & mask) | !mask))
}

/// The last two labels ("www.siteb.com" -> "siteb.com").
pub fn site_name(name: &str) -> String {
    let n = trim_dots(name);
    let labels: Vec<&str> = n.split('.').filter(|l| !l.is_empty()).collect();
    let from = labels.len().saturating_sub(2);
    labels[from..].join(".")
}

impl SplitRules {
    pub fn new<S: AsRef<str>>(list: &[S]) -> Self {
        let mut r = SplitRules::default();
        for raw in list {
            let item = raw.as_ref().trim_matches(|c: char| c == ' ' || c == '\t');
            if let Some(v) = item.strip_prefix("full:") {
                r.fulls.insert(v.to_lowercase());
            } else if let Some(v) = item.strip_prefix("keyword:") {
                if !v.is_empty() {
                    r.keywords.push(v.to_lowercase());
                }
            } else if let Some(v) = item.strip_prefix("regexp:") {
                if let Ok(re) = Regex::new(v) {
                    r.regexes.push(re);
                }
            } else if let Some(v) = item.strip_prefix("ipcidr:") {
                if let Some(range) = cidr_range(v) {
                    r.ranges.push(range);
                }
            } else if let Some(v) = item.strip_prefix("domain:") {
                let d = trim_domain(v);
                if !d.is_empty() {
                    r.suffixes.insert(d);
                }
            } else {
                let d = trim_domain(item);
                if !d.is_empty() && d.contains('.') && !d.contains(':') {
                    r.suffixes.insert(d);
                }
            }
        }
        r.ranges.sort_by_key(|r| r.0);
        r
    }

    pub fn has_ranges(&self) -> bool {
        !self.ranges.is_empty()
    }

    /// What `name` matched, for the panel (the rule's own name where
    /// there is one), or None.
    pub fn matches(&self, name: &str) -> Option<String> {
        let n = trim_dots(name);
        if n.is_empty() {
            return None;
        }
        if self.fulls.contains(&n) {
            return Some(n);
        }
        let mut rest = n.as_str();
        loop {
            if self.suffixes.contains(rest) {
                return Some(rest.to_string());
            }
            match rest.find('.') {
                Some(dot) => rest = &rest[dot + 1..],
                None => break,
            }
        }
        if self.keywords.iter().any(|k| n.contains(k.as_str())) {
            return Some(site_name(&n));
        }
        if self.regexes.iter().any(|re| re.is_match(&n)) {
            return Some(site_name(&n));
        }
        None
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        // The last range starting at or below v.
        let idx = self.ranges.partition_point(|r| r.0 <= v);
        idx > 0 && v <= self.ranges[idx - 1].1
    }
}

// MARK: - Upstream exchanges

/// "a.b.c.d", or "a.b.c.d:port" (the harness's upstreams).
fn server_address(server: &str, port: u16) -> Option<SocketAddrV4> {
    let (host, p) = match server.split_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(port)),
        None => (server, port),
    };
    Some(SocketAddrV4::new(Ipv4Addr::from_str(host).ok()?, p))
}

fn upstream_socket(ty: Type, interface: Option<&str>, timeout: Duration) -> Option<Socket> {
    let proto = if ty == Type::DGRAM { Protocol::UDP } else { Protocol::TCP };
    let s = Socket::new(Domain::IPV4, ty, Some(proto)).ok()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let _ = s.set_nosigpipe(true);
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    if let Some(name) = interface {
        bind_interface(&s, name)?;
    }
    Some(s)
}

/// Pins the socket to one interface: the local DNS is asked out the
/// physical network although the default route is the tunnel.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_interface(s: &Socket, name: &str) -> Option<()> {
    let c = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    let index = std::num::NonZeroU32::new(index)?;
    s.bind_device_by_index_v4(Some(index)).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn bind_interface(s: &Socket, name: &str) -> Option<()> {
    s.bind_device(Some(name.as_bytes())).ok()
}

fn same_id(answer: &[u8], query: &[u8]) -> bool {
    answer.len() >= 2 && query.len() >= 2 && answer[0] == query[0] && answer[1] == query[1]
}

fn udp_exchange(query: &[u8], server: &str, port: u16, interface: Option<&str>, timeout: Duration) -> Option<Vec<u8>> {
    let addr = server_address(server, port)?;
    let s = upstream_socket(Type::DGRAM, interface, timeout)?;
    let sent = s.send_to(query, &SockAddr::from(addr)).ok()?;
    if sent != query.len() {
        return None;
    }
    let socket: UdpSocket = s.into();
    let deadline = Instant::now() + timeout;
    let mut buffer = vec![0u8; 65535];
    while Instant::now() < deadline {
        let n = socket.recv(&mut buffer).ok()?;
        if n == 0 {
            return None;
        }
        // Only the answer to this query (same id), never a stray one.
        if same_id(&buffer[..n], query) {
            buffer.truncate(n);
            return Some(buffer);
        }
    }
    None
}

fn tcp_exchange(query: &[u8], server: &str, port: u16, interface: Option<&str>, timeout: Duration) -> Option<Vec<u8>> {
    let addr = server_address(server, port)?;
    let s = upstream_socket(Type::STREAM, interface, timeout)?;
    s.connect_timeout(&SockAddr::from(addr), timeout).ok()?;
    let mut stream: TcpStream = s.into();
    write_framed(&mut stream, query).ok()?;
    let answer = read_framed(&mut stream)?;
    same_id(&answer, query).then_some(answer)
}

/// Each server in turn: UDP, then TCP (also when the UDP answer is
/// truncated). The first usable answer wins.
pub fn exchange(query: &[u8], servers: &[String], port: u16, interface: Option<&str>, timeout: Duration) -> Option<Vec<u8>> {
    for server in servers {
        if let Some(answer) = udp_exchange(query, server, port, interface, timeout) {
            if !is_truncated(&answer) {
                return Some(answer);
            }
        }
        if let Some(answer) = tcp_exchange(query, server, port, interface, timeout) {
            return Some(answer);
        }
    }
    None
}

pub fn read_framed<R: Read>(r: &mut R) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).ok()?;
    let length = (head[0] as usize) << 8 | head[1] as usize;
    if length == 0 {
        return None;
    }
    let mut out = vec![0u8; length];
    r.read_exact(&mut out).ok()?;
    Some(out)
}

pub fn write_framed<W: Write>(w: &mut W, message: &[u8]) -> io::Result<()> {
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.push((message.len() >> 8) as u8);
    framed.push((message.len() & 0xff) as u8);
    framed.extend_from_slice(message);
    w.write_all(&framed)
}

// MARK: - The forwarder

#[derive(Clone, Debug)]
pub struct Upstreams {
    /// The tunnel's DNS servers (connect hook), for every other name.
    pub tunnel: Vec<String>,
    /// The local network's DNS servers, for direct names.
    pub local: Vec<String>,
    /// Bind the local queries to this interface; None in tests.
    pub physical_if: Option<String>,
}

/// Called with the list entry a direct name matched and its IPv4
/// addresses before the answer is returned; must return only once they
/// are routed direct.
pub type DirectHook = Box<dyn Fn(&str, &[Ipv4Addr]) + Send + Sync>;

pub struct Inner {
    upstream_port: u16,
    timeout: Duration,
    rules: RwLock<Arc<SplitRules>>,
    upstreams: Mutex<Upstreams>,
    names: Mutex<HashMap<Ipv4Addr, String>>,
    on_direct: Option<DirectHook>,
    inflight: AtomicUsize,
    pool: Pool,
}

type Job = Box<dyn FnOnce(&Inner) + Send>;

/// Workers that stay for a while after their last job and then leave:
/// no thread is started per query under load, none is kept when idle.
#[derive(Default)]
struct Pool {
    state: Mutex<PoolState>,
    ready: Condvar,
}

#[derive(Default)]
struct PoolState {
    jobs: std::collections::VecDeque<Job>,
    idle: usize,
    workers: usize,
}

impl Inner {
    fn remember(&self, answer: Option<&Vec<u8>>, name: &str) {
        let Some(answer) = answer else { return };
        let ips = ipv4_answers(answer);
        if ips.is_empty() {
            return;
        }
        let clean = trim_dots(name);
        let mut names = self.names.lock().unwrap();
        if names.len() > NAME_CACHE_LIMIT {
            names.clear();
        }
        for ip in ips {
            names.insert(ip, clean.clone());
        }
    }

    fn direct(&self, entry: &str, ips: &[Ipv4Addr]) {
        if let Some(hook) = &self.on_direct {
            hook(entry, ips);
        }
    }

    /// The answer to send back, or None when there is none to give (the
    /// client then retries or moves on to the next server).
    pub fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = question(query)?;
        let rules = self.rules.read().unwrap().clone();
        let entry = rules.matches(&q.name);
        let up = self.upstreams.lock().unwrap().clone();
        let Some(entry) = entry else {
            if q.qtype == TYPE_AAAA {
                return empty_answer(query);
            }
            let answer = exchange(query, &up.tunnel, self.upstream_port, None, self.timeout);
            if q.qtype == TYPE_A {
                self.remember(answer.as_ref(), &q.name);
            }
            // geoip rules (§26.13): a name that resolves (through the
            // tunnel's DNS) into a listed range goes direct too, its
            // addresses routed before the answer is handed back.
            if let Some(a) = &answer {
                if rules.has_ranges() && q.qtype == TYPE_A {
                    let hits: Vec<Ipv4Addr> = ipv4_answers(a).into_iter().filter(|ip| rules.contains(*ip)).collect();
                    if !hits.is_empty() {
                        self.direct(&site_name(&q.name), &hits);
                    }
                }
            }
            if is_service(q.qtype) {
                return answer.map(|a| without_addresses(&a, false).unwrap_or(a));
            }
            return answer;
        };
        if q.qtype == TYPE_AAAA {
            return empty_answer(query);
        }
        let answer = exchange(query, &up.local, self.upstream_port, up.physical_if.as_deref(), self.timeout)?;
        if is_service(q.qtype) {
            // Nothing to route: no addresses are left in it.
            return without_addresses(&answer, true).or_else(|| empty_answer(query));
        }
        let addresses = ipv4_answers(&answer);
        if !addresses.is_empty() {
            self.direct(&entry, &addresses);
        }
        self.remember(Some(&answer), &q.name);
        Some(answer)
    }

    /// Runs `job` on a pooled worker unless MAX_INFLIGHT are queued or
    /// busy (then it is dropped: the client asks again).
    fn spawn(self: &Arc<Self>, job: impl FnOnce(&Inner) + Send + 'static) {
        if self.inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let mut state = self.pool.state.lock().unwrap();
        state.jobs.push_back(Box::new(job));
        if state.idle > 0 {
            drop(state);
            self.pool.ready.notify_one();
            return;
        }
        state.workers += 1;
        drop(state);
        let inner = Arc::clone(self);
        let started = std::thread::Builder::new()
            .name("ac-dns".into())
            .stack_size(WORKER_STACK)
            .spawn(move || inner.work());
        if started.is_err() {
            let mut state = self.pool.state.lock().unwrap();
            state.workers -= 1;
            if state.workers == 0 {
                let dropped = state.jobs.len();
                state.jobs.clear();
                self.inflight.fetch_sub(dropped, Ordering::AcqRel);
            }
        }
    }

    fn work(&self) {
        let mut state = self.pool.state.lock().unwrap();
        loop {
            if let Some(job) = state.jobs.pop_front() {
                drop(state);
                job(self);
                self.inflight.fetch_sub(1, Ordering::AcqRel);
                state = self.pool.state.lock().unwrap();
                continue;
            }
            state.idle += 1;
            let (next, timeout) = self.pool.ready.wait_timeout(state, WORKER_IDLE).unwrap();
            state = next;
            state.idle -= 1;
            if timeout.timed_out() && state.jobs.is_empty() {
                state.workers -= 1;
                return;
            }
        }
    }
}

struct Listening {
    /// Writing a byte here ends the listening thread.
    wake: std::os::fd::OwnedFd,
    thread: JoinHandle<()>,
}

pub struct Forwarder {
    inner: Arc<Inner>,
    listen: SocketAddrV4,
    listening: Mutex<Option<Listening>>,
}

fn listener(ty: Type, address: SocketAddrV4) -> io::Result<Socket> {
    let proto = if ty == Type::DGRAM { Protocol::UDP } else { Protocol::TCP };
    let s = Socket::new(Domain::IPV4, ty, Some(proto))?;
    s.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    s.set_nosigpipe(true)?;
    s.bind(&SockAddr::from(address))?;
    if ty == Type::STREAM {
        s.listen(16)?;
    }
    Ok(s)
}

impl Forwarder {
    pub fn new(listen: SocketAddrV4, upstream_port: u16, timeout: Duration, direct: Vec<String>,
               upstreams: Upstreams, on_direct: Option<DirectHook>) -> Self {
        Forwarder {
            inner: Arc::new(Inner {
                upstream_port,
                timeout,
                rules: RwLock::new(Arc::new(SplitRules::new(&direct))),
                upstreams: Mutex::new(upstreams),
                names: Mutex::new(HashMap::new()),
                on_direct,
                inflight: AtomicUsize::new(0),
                pool: Pool::default(),
            }),
            listen,
            listening: Mutex::new(None),
        }
    }

    pub fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    pub fn set_rules(&self, direct: &[String]) {
        let parsed = Arc::new(SplitRules::new(direct));
        *self.inner.rules.write().unwrap() = parsed;
    }

    pub fn set_upstreams(&self, upstreams: Upstreams) {
        *self.inner.upstreams.lock().unwrap() = upstreams;
    }

    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner.names.lock().unwrap().get(&ip).cloned()
    }

    /// Listens on UDP and TCP; Err when the port is taken.
    pub fn start(&self) -> io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        self.stop();
        let udp: UdpSocket = listener(Type::DGRAM, self.listen)?.into();
        let tcp: TcpListener = listener(Type::STREAM, self.listen)?.into();
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let inner = Arc::clone(&self.inner);
        // One thread waits on both sockets and the stop pipe; a wake-up
        // drains every datagram and connection that is ready.
        let thread = std::thread::Builder::new().name("ac-dns".into()).stack_size(WORKER_STACK).spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                let mut polled = [
                    libc::pollfd { fd: udp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                    libc::pollfd { fd: tcp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                    libc::pollfd { fd: read_end.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                ];
                if unsafe { libc::poll(polled.as_mut_ptr(), 3, -1) } < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return;
                }
                if polled[2].revents != 0 {
                    return; // stop: the sockets close as this thread ends
                }
                while let Ok((n, from)) = udp.recv_from(&mut buffer) {
                    if n == 0 {
                        continue;
                    }
                    let query = buffer[..n].to_vec();
                    let Ok(reply) = udp.try_clone() else { continue };
                    inner.spawn(move |inner| {
                        if let Some(answer) = inner.resolve(&query) {
                            let _ = reply.send_to(&answer, from);
                        }
                    });
                }
                while let Ok((mut client, _)) = tcp.accept() {
                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    let _ = socket2::SockRef::from(&client).set_nosigpipe(true);
                    let _ = client.set_nonblocking(false);
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    inner.spawn(move |inner| {
                        if let Some(query) = read_framed(&mut client) {
                            if let Some(answer) = inner.resolve(&query) {
                                let _ = write_framed(&mut client, &answer);
                            }
                        }
                    });
                }
            }
        })?;
        *self.listening.lock().unwrap() = Some(Listening { wake: write_end, thread });
        Ok(())
    }

    /// Stops listening and frees the port before returning. Queries
    /// already being answered finish on their own.
    pub fn stop(&self) {
        use std::os::fd::AsRawFd;
        let Some(listening) = self.listening.lock().unwrap().take() else { return };
        unsafe { libc::write(listening.wake.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        let _ = listening.thread.join();
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let mut m = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
        m
    }

    fn wire(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn param(key: u16, value: &[u8]) -> Vec<u8> {
        let mut p = vec![(key >> 8) as u8, key as u8, (value.len() >> 8) as u8, value.len() as u8];
        p.extend_from_slice(value);
        p
    }

    /// alpn h3,h2 + ipv4hint (two) + ech + ipv6hint, the shape a CDN serves.
    fn hinted_params() -> Vec<u8> {
        let mut v6 = vec![0x20, 0x01, 0x0d, 0xb8];
        v6.extend_from_slice(&[0; 11]);
        v6.push(1);
        [
            param(1, b"\x02h3\x02h2"),
            param(4, &[192, 0, 2, 1, 192, 0, 2, 2]),
            param(5, b"ech-config-bytes"),
            param(6, &v6),
        ]
        .concat()
    }

    /// One resource record: `owner` already in wire form (or a pointer).
    fn rr(owner: &[u8], rtype: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut r = owner.to_vec();
        r.extend_from_slice(&[(rtype >> 8) as u8, rtype as u8, 0, 1]);
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[(data.len() >> 8) as u8, data.len() as u8]);
        r.extend_from_slice(data);
        r
    }

    fn svcb_data(priority: u16, target: &str, params: &[u8]) -> Vec<u8> {
        [vec![(priority >> 8) as u8, priority as u8], wire(target), params.to_vec()].concat()
    }

    /// `q` answered with `records` in the three sections.
    fn reply(q: &[u8], an: &[Vec<u8>], ns: &[Vec<u8>], ar: &[Vec<u8>]) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        for (i, n) in [an.len(), ns.len(), ar.len()].into_iter().enumerate() {
            m[6 + 2 * i] = 0;
            m[7 + 2 * i] = n as u8;
        }
        for r in an.iter().chain(ns).chain(ar) {
            m.extend_from_slice(r);
        }
        m
    }

    /// Every record as (owner, type, ttl, data with names expanded for
    /// CNAME/SOA, SvcParamKeys for SVCB/HTTPS), section by section.
    fn records(m: &[u8]) -> Vec<(String, u16, u32, String)> {
        let count = |i: usize| (m[i] as usize) << 8 | m[i + 1] as usize;
        let (_, mut at) = read_name(m, 12).unwrap();
        at += 4;
        let mut out = Vec::new();
        for _ in 0..count(6) + count(8) + count(10) {
            let (owner, end) = read_name(m, at).unwrap();
            let rtype = (m[end] as u16) << 8 | m[end + 1] as u16;
            let ttl = u32::from_be_bytes(m[end + 4..end + 8].try_into().unwrap());
            let data = end + 10;
            let stop = data + ((m[end + 8] as usize) << 8 | m[end + 9] as usize);
            let shown = match rtype {
                TYPE_CNAME => read_name(m, data).unwrap().0,
                TYPE_SOA => {
                    let (a, e) = read_name(m, data).unwrap();
                    let (b, e) = read_name(m, e).unwrap();
                    assert_eq!(e + 20, stop);
                    format!("{a} {b} {:?}", &m[e..e + 4])
                }
                TYPE_HTTPS | TYPE_SVCB => {
                    let (target, mut p) = read_name(m, data + 2).unwrap();
                    let mut keys = vec![format!("prio={} target={target}", (m[data] as u16) << 8 | m[data + 1] as u16)];
                    while p < stop {
                        let key = (m[p] as u16) << 8 | m[p + 1] as u16;
                        let len = (m[p + 2] as usize) << 8 | m[p + 3] as usize;
                        keys.push(format!("{key}:{}", String::from_utf8_lossy(&m[p + 4..p + 4 + len])));
                        p += 4 + len;
                    }
                    assert_eq!(p, stop);
                    keys.join(" ")
                }
                _ => format!("{:?}", &m[data..stop]),
            };
            out.push((owner, rtype, ttl, shown));
            at = stop;
        }
        assert_eq!(at, m.len());
        out
    }

    fn answer(q: &[u8], ip: [u8; 4], truncated: bool) -> Vec<u8> {
        if !truncated && question(q).map(|q| q.qtype) == Some(TYPE_HTTPS) {
            return reply(q, &[rr(&[0xC0, 0x0C], TYPE_HTTPS, 300, &svcb_data(1, ".", &hinted_params()))], &[], &[]);
        }
        let mut m = q.to_vec();
        m[2] = 0x81 | if truncated { 0x02 } else { 0 };
        m[3] = 0x80;
        m[6] = 0;
        m[7] = if truncated { 0 } else { 1 };
        if !truncated {
            m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend_from_slice(&ip);
        }
        m
    }

    #[test]
    fn rule_kinds() {
        let r = SplitRules::new(&[
            "domain:siteb.com", "full:only.example.org", "keyword:taobao",
            "regexp:^cdn[0-9]+\\.example\\.net$", "ipcidr:198.51.100.0/24",
            "ipcidr:203.0.113.128/25", "junk:x", "domain:sitea", "SiteA.com", "*.sitea-cdn.com",
            ".siteb.tv", "nodot",
        ]);
        assert_eq!(r.matches("api.siteb.com").as_deref(), Some("siteb.com"));
        assert_eq!(r.matches("only.example.org").as_deref(), Some("only.example.org"));
        assert_eq!(r.matches("x.only.example.org"), None);
        assert_eq!(r.matches("img.taobaocdn.com").as_deref(), Some("taobaocdn.com"));
        assert_eq!(r.matches("cdn12.example.net").as_deref(), Some("example.net"));
        assert_eq!(r.matches("cdnx.example.net"), None);
        assert_eq!(r.matches("music.sitea").as_deref(), Some("sitea"));
        assert_eq!(r.matches("WWW.SITEA.COM.").as_deref(), Some("sitea.com"));
        assert_eq!(r.matches("notsitea.com"), None);
        assert_eq!(r.matches("r1.sitea-cdn.com").as_deref(), Some("sitea-cdn.com"));
        assert_eq!(r.matches("www.siteb.tv").as_deref(), Some("siteb.tv"));
        assert_eq!(r.matches("nodot"), None);
        assert!(r.contains("198.51.100.77".parse().unwrap()));
        assert!(r.contains("203.0.113.200".parse().unwrap()));
        assert!(!r.contains("203.0.113.5".parse().unwrap()));
        assert!(!r.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn wire_format() {
        let q = query("www.example.com", TYPE_AAAA, 0x1234);
        assert_eq!(question(&q), Some(Question { name: "www.example.com".into(), qtype: TYPE_AAAA }));
        let e = empty_answer(&q).unwrap();
        assert_eq!((e[0], e[1], e[2] & 0x80, e[3] & 0x0F, e[7]), (0x12, 0x34, 0x80, 0, 0));
        let a = answer(&query("x.example", TYPE_A, 7), [203, 0, 113, 9], false);
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(203, 0, 113, 9)]);
        assert!(is_truncated(&answer(&q, [0; 4], true)));
        assert_eq!(cidr_range("10.1.2.3/8"), Some((0x0A00_0000, 0x0AFF_FFFF)));
        assert_eq!(cidr_range("10.0.0.0/33"), None);
        assert_eq!(site_name("WWW.SiteB.com."), "siteb.com");
        // A pointer loop is cut off, not followed forever.
        let mut bad = q.clone();
        bad[12] = 0xC0;
        bad[13] = 12;
        assert_eq!(question(&bad), None);
    }

    #[test]
    fn service_answers_lose_only_their_addresses() {
        let q = query("www.example.com", TYPE_HTTPS, 9);
        let here = [0xC0u8, 0x0C];
        // The usual shape: hints in the record, an OPT and an A in the
        // additional section.
        let opt = rr(&[0], 41, 0, &[]);
        let a = rr(&here, TYPE_A, 60, &[192, 0, 2, 9]);
        let m = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &hinted_params()))], &[], &[a, opt.clone()]);
        for direct in [false, true] {
            let out = without_addresses(&m, direct).unwrap();
            assert!(out.len() < m.len());
            assert_eq!(&out[..6], &m[..6], "id, flags and question count kept");
            assert_eq!(question(&out), question(&m));
            assert_eq!(
                records(&out),
                vec![
                    ("www.example.com".into(), TYPE_HTTPS, 300, "prio=1 target= 1:\u{2}h3\u{2}h2 5:ech-config-bytes".into()),
                    ("".into(), 41, 0, "[]".into()),
                ]
            );
        }

        // "mandatory" naming a hint loses that key; empty, it goes.
        let params = [param(0, &[0, 1, 0, 4]), param(1, b"\x02h2"), param(4, &[192, 0, 2, 1])].concat();
        let m = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &params))], &[], &[]);
        assert_eq!(records(&without_addresses(&m, true).unwrap())[0].3, "prio=1 target= 0:\0\u{1} 1:\u{2}h2");
        let params = [param(0, &[0, 6]), param(6, &[0; 16])].concat();
        let m = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &params))], &[], &[]);
        assert_eq!(records(&without_addresses(&m, true).unwrap())[0].3, "prio=1 target=");

        // Nothing to take out: the very same bytes.
        let soa = [wire("ns.example.com"), vec![0xC0, 16], vec![0, 0, 0, 7], vec![0; 16]].concat();
        let nodata = reply(&q, &[], &[rr(&[0xC0, 16], TYPE_SOA, 900, &soa)], &[]);
        assert_eq!(without_addresses(&nodata, true).unwrap(), nodata);
        let plain = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &param(1, b"\x02h3")))], &[], &[]);
        assert_eq!(without_addresses(&plain, true).unwrap(), plain);

        // A CNAME to another name, or a TargetName other than ".": fine
        // through the tunnel, not for a direct name.
        let cname = rr(&here, TYPE_CNAME, 60, &wire("edge.example.net"));
        let at_target = rr(&wire("edge.example.net"), TYPE_HTTPS, 300, &svcb_data(1, ".", &hinted_params()));
        let soa_rr = rr(&[0xC0, 16], TYPE_SOA, 900, &soa);
        let m = reply(&q, &[cname, at_target], &[soa_rr], &[]);
        assert_eq!(without_addresses(&m, true), None);
        let out = records(&without_addresses(&m, false).unwrap());
        assert_eq!(out[0], ("www.example.com".into(), TYPE_CNAME, 60, "edge.example.net".into()));
        assert_eq!(out[1].3, "prio=1 target= 1:\u{2}h3\u{2}h2 5:ech-config-bytes");
        assert_eq!(out[2], ("example.com".into(), TYPE_SOA, 900, "ns.example.com example.com [0, 0, 0, 7]".into()));
        let m = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, "pool.example.net", &hinted_params()))], &[], &[]);
        assert_eq!(without_addresses(&m, true), None);
        assert_eq!(records(&without_addresses(&m, false).unwrap())[0].3, "prio=1 target=pool.example.net 1:\u{2}h3\u{2}h2 5:ech-config-bytes");

        // Broken messages are not rewritten.
        let mut short = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &hinted_params()))], &[], &[]);
        short.truncate(short.len() - 3);
        assert_eq!(without_addresses(&short, false), None);
        let mut lying = reply(&q, &[rr(&here, TYPE_HTTPS, 300, &svcb_data(1, ".", &hinted_params()))], &[], &[]);
        let last = lying.len() - 1;
        lying[last - 17] = 0xFF; // ipv6hint's length runs past the record
        assert_eq!(without_addresses(&lying, false), None);
        let mut looped = m.clone();
        looped[12] = 0xC0;
        looped[13] = 12;
        assert_eq!(without_addresses(&looped, false), None);
    }

    /// A fake upstream on loopback answering every query with `ip`.
    fn fake_udp(ip: [u8; 4], truncate: bool) -> (u16, Arc<AtomicUsize>) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                c.fetch_add(1, Ordering::SeqCst);
                let _ = s.send_to(&answer(&buf[..n], ip, truncate), from);
            }
        });
        (port, count)
    }

    fn fake_tcp_on(port: u16, ip: [u8; 4]) -> Arc<AtomicUsize> {
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                if let Some(q) = read_framed(&mut s) {
                    c.fetch_add(1, Ordering::SeqCst);
                    let _ = write_framed(&mut s, &answer(&q, ip, false));
                }
            }
        });
        count
    }

    fn ask(q: &[u8], port: u16) -> Option<Vec<u8>> {
        let s = UdpSocket::bind("127.0.0.1:0").ok()?;
        s.set_read_timeout(Some(Duration::from_secs(6))).ok()?;
        s.send_to(q, ("127.0.0.1", port)).ok()?;
        let mut buf = [0u8; 4096];
        let n = s.recv(&mut buf).ok()?;
        Some(buf[..n].to_vec())
    }

    fn free_port() -> u16 {
        // A port free for both UDP and TCP.
        loop {
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            let p = u.local_addr().unwrap().port();
            if TcpListener::bind(("127.0.0.1", p)).is_ok() {
                return p;
            }
        }
    }

    #[test]
    fn forwards_and_routes_before_answering() {
        let (local, local_count) = fake_udp([203, 0, 113, 1], false);
        let (tunnel, tunnel_count) = fake_udp([198, 51, 100, 2], false);
        let (trunc, _) = fake_udp([198, 51, 100, 4], true);
        let trunc_tcp = fake_tcp_on(trunc, [198, 51, 100, 4]);
        let dead = free_port();
        let (tx, rx) = mpsc::channel::<String>();
        let hook_tx = Mutex::new(tx.clone());
        let hook: DirectHook = Box::new(move |entry, ips| {
            std::thread::sleep(Duration::from_millis(100));
            let ips: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
            hook_tx.lock().unwrap().send(format!("direct {} {}", entry, ips.join(","))).unwrap();
        });
        let port = free_port();
        let fwd = Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_millis(500),
            vec!["sitea.com".into()],
            Upstreams {
                tunnel: vec![format!("127.0.0.1:{dead}"), format!("127.0.0.1:{tunnel}")],
                local: vec![format!("127.0.0.1:{local}")],
                physical_if: None,
            },
            Some(hook),
        );
        fwd.start().unwrap();

        let a = ask(&query("www.sitea.com", TYPE_A, 1), port).unwrap();
        tx.send("answer".into()).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(203, 0, 113, 1)]);
        assert_eq!(rx.recv().unwrap(), "direct sitea.com 203.0.113.1");
        assert_eq!(rx.recv().unwrap(), "answer", "routed before the answer came back");
        assert_eq!(fwd.name_for(Ipv4Addr::new(203, 0, 113, 1)).as_deref(), Some("www.sitea.com"));

        let a = ask(&query("www.sitea.com", TYPE_AAAA, 2), port).unwrap();
        assert_eq!(a[7], 0);
        // HTTPS: asked of the local DNS, passed on without its hints.
        let a = ask(&query("www.sitea.com", TYPE_HTTPS, 3), port).unwrap();
        let shown = "prio=1 target= 1:\u{2}h3\u{2}h2 5:ech-config-bytes";
        assert_eq!(records(&a), vec![("www.sitea.com".into(), TYPE_HTTPS, 300, shown.into())]);
        assert_eq!(local_count.load(Ordering::SeqCst), 2);

        let a = ask(&query("intranet.example", TYPE_A, 4), port).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(198, 51, 100, 2)]);
        let before = tunnel_count.load(Ordering::SeqCst);
        let a = ask(&query("intranet.example", TYPE_AAAA, 5), port).unwrap();
        assert_eq!((a[7], a[3] & 0x0F), (0, 0));
        assert_eq!(tunnel_count.load(Ordering::SeqCst), before);
        let a = ask(&query("intranet.example", TYPE_HTTPS, 9), port).unwrap();
        assert_eq!(records(&a), vec![("intranet.example".into(), TYPE_HTTPS, 300, shown.into())]);

        fwd.set_upstreams(Upstreams {
            tunnel: vec![format!("127.0.0.1:{trunc}")],
            local: vec![format!("127.0.0.1:{local}")],
            physical_if: None,
        });
        let a = ask(&query("big.example", TYPE_A, 6), port).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(198, 51, 100, 4)]);
        assert_eq!(trunc_tcp.load(Ordering::SeqCst), 1);

        // TCP clients.
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write_framed(&mut s, &query("m.sitea.com", TYPE_A, 0x4321)).unwrap();
        let a = read_framed(&mut s).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(203, 0, 113, 1)]);
        assert_eq!(rx.recv().unwrap(), "direct sitea.com 203.0.113.1");

        // geoip: through the tunnel, routed direct when in range.
        fwd.set_rules(&["ipcidr:198.51.100.0/24".to_string()]);
        let a = ask(&query("www.siteb.com", TYPE_A, 7), port).unwrap();
        tx.send("answer".into()).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(198, 51, 100, 4)]);
        assert_eq!(rx.recv().unwrap(), "direct siteb.com 198.51.100.4");
        assert_eq!(rx.recv().unwrap(), "answer");

        // Stop frees the port at once; start again works.
        fwd.stop();
        assert!(UdpSocket::bind(("127.0.0.1", port)).is_ok());
        fwd.start().unwrap();
        fwd.set_rules(&[]);
        let _ = ask(&query("www.sitea.com", TYPE_A, 8), port).unwrap();
        assert!(rx.try_recv().is_err(), "a removed rule routes nothing");
        fwd.stop();
    }
}
