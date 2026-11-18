//! The domain split's DNS forwarder (DESIGN.md §26.4, §26.13, §28.3;
//! moved from Swift to Rust in §32.6).
//!
//! The system resolver uses only this forwarder in split mode (§48).
//! Direct names use physical-interface DNS; other names use the current
//! VPN interface's DNS, over UDP then TCP. Unavailable/invalid bindings
//! fail closed. Validated address observations commit through the engine
//! queue before an answer is returned; stale generations are discarded.
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
/// Root DNS on the physical network leaves only from this source-port range
/// (§61.1). The PF exception names the same range, so another root process or
/// a system extension re-sending an ordinary user's query cannot match it.
/// Below the macOS ephemeral range: only explicit binders use these ports.
pub const PHYSICAL_DNS_SOURCE_PORTS: (u16, u16) = (46600, 46855);
static NEXT_SOURCE_PORT: AtomicUsize = AtomicUsize::new(0);

// MARK: - Wire format (RFC 1035), just enough for the forwarder

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

/// (name, offset after the name in its own position), following
/// compression pointers with a hop limit.
pub fn read_name(m: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name=String::with_capacity(64); let mut at=start; let mut end=None; let mut hops=0; let mut size=1;
    while at<m.len() {
        let len=m[at] as usize;
        if len==0 {return Some((name,end.unwrap_or(at+1)));}
        if len & 0xc0 == 0xc0 {
            if at+1>=m.len() || hops>=16 {return None;}
            end.get_or_insert(at+2); at=((len&0x3f)<<8)|m[at+1] as usize; hops+=1; continue;
        }
        if len & 0xc0 != 0 || at+1+len>m.len() {return None;}
        size+=1+len; if size>255 {return None;}
        if !name.is_empty(){name.push('.');}
        name.push_str(&String::from_utf8_lossy(&m[at+1..at+1+len])); at+=1+len;
    }
    None
}

/// Allocation-free common question shape; compressed/opaque names use the
/// full decoder. The accepted characters match the strict address decoder.
fn plain_name_end(m: &[u8], start: usize) -> Option<usize> {
    let mut at=start;
    loop {
        let len=*m.get(at)? as usize;
        if len==0 {return Some(at+1);}
        if len>63 || at+len+2-start>255 {return None;}
        if !m.get(at+1..at+1+len)?.iter().all(|c|c.is_ascii_alphanumeric()||*c==b'-'||*c==b'_') {return None;}
        at+=1+len;
    }
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
    s.trim_matches('.').to_lowercase()
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

fn upstream_socket(ty: Type, interface: Option<&InterfaceBinding>) -> Option<Socket> {
    let proto = if ty == Type::DGRAM { Protocol::UDP } else { Protocol::TCP };
    let s = crate::child_io::socket(Domain::IPV4, ty, Some(proto)).ok()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let _ = s.set_nosigpipe(true);
    if let Some(name) = interface {
        name.bind(&s)?;
        if name.pinned_source { bind_physical_source(&s)?; }
    }
    Some(s)
}

/// Exclusive bind within the PF-named range; no SO_REUSEADDR, so a port still
/// held (including TCP TIME_WAIT) moves on. Exhaustion fails closed.
fn bind_physical_source(socket: &Socket) -> Option<()> {
    let (low, high) = PHYSICAL_DNS_SOURCE_PORTS;
    let size = usize::from(high - low) + 1;
    let start = NEXT_SOURCE_PORT.fetch_add(1, Ordering::Relaxed);
    for offset in 0..size {
        let port = low + ((start + offset) % size) as u16;
        match socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))) {
            Ok(()) => return Some(()),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Resolve the interface once per configuration generation. Repeating
/// if_nametoindex for each packet is expensive on macOS; sockets still bind
/// before connect and an invalid index fails closed.
#[derive(Clone, PartialEq, Eq)]
struct InterfaceBinding {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    index: std::num::NonZeroU32,
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    name: String,
    /// Physical DNS: also bind a source port from PHYSICAL_DNS_SOURCE_PORTS.
    pinned_source: bool,
}
impl InterfaceBinding {
    fn new(name: &str) -> Option<Self> {
        let c = std::ffi::CString::new(name).ok()?;
        let index = std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(c.as_ptr()) })?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        { Some(Self { index, pinned_source: false }) }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        { let _ = index; Some(Self { name: name.into(), pinned_source: false }) }
    }
    /// The physical interface, for root DNS covered by the PF source-port exception.
    fn physical(name: &str) -> Option<Self> {
        Self::new(name).map(|binding| Self { pinned_source: true, ..binding })
    }
    fn pinned(name: &str, index: u32) -> Option<Self> {
        #[cfg(any(target_os="macos",target_os="ios"))]
        { let _=name; Some(Self {index:std::num::NonZeroU32::new(index)?,pinned_source:false}) }
        #[cfg(not(any(target_os="macos",target_os="ios")))]
        { let c=std::ffi::CString::new(name).ok()?; if unsafe{libc::if_nametoindex(c.as_ptr())}!=index{return None;} Self::new(name) }
    }
    fn bind(&self, socket: &Socket) -> Option<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        { socket.bind_device_by_index_v4(Some(self.index)).ok() }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        { socket.bind_device(Some(self.name.as_bytes())).ok() }
    }
}

fn same_id(answer: &[u8], query: &[u8]) -> bool {
    if answer.len() < 12 || query.len() < 12 || answer[..2] != query[..2]
        || answer[2] & 0x80 == 0 || answer[2] & 0x78 != query[2] & 0x78
        || answer[4..6] != [0, 1] || query[4..6] != [0, 1] {
        return false;
    }
    if let Some(qe)=plain_name_end(query,12) {
        if answer.get(12..qe).is_some_and(|name|name.eq_ignore_ascii_case(&query[12..qe])) {
            return answer.get(qe..qe+4)==query.get(qe..qe+4) && query.get(qe..qe+4).is_some();
        }
    }
    let Some((a, ae)) = read_labels(answer, 12) else { return false };
    let Some((q, qe)) = read_labels(query, 12) else { return false };
    same_name(&a, &q) && answer.get(ae..ae + 4) == query.get(qe..qe + 4)
        && query.get(qe..qe + 4).is_some()
}

/// Only addresses belonging to this question's validated IN CNAME chain.
/// Strip the query's EDNS trailer for the shared bounded decoder.
fn answer_addresses(answer: &[u8], query: &[u8]) -> Option<Vec<Ipv4Addr>> {
    // The overwhelmingly common single IN A answer needs no name maps. The
    // general CNAME/section decoder remains the oracle for every other shape.
    if answer.len()>=12 && query.len()>=12 && query[2]&0xf8==0 && answer[2]&0xfa==0x80
        && answer[3]&0x0f==0 && answer[..2]==query[..2] && answer[4..12]==[0,1,0,1,0,0,0,0] && query[4..6]==[0,1] {
        if let Some(qe)=plain_name_end(query,12) {
            if query.get(qe..qe+4)==Some(&[0,1,0,1]) && answer.get(qe..qe+4)==Some(&[0,1,0,1])
                && answer.get(12..qe).is_some_and(|name|name.eq_ignore_ascii_case(&query[12..qe])) {
                let owner=qe+4;
                let head=if answer.get(owner..owner+2)==Some(&[0xc0,12]) {Some(owner+2)}
                    else {plain_name_end(answer,owner).filter(|end|answer[owner..*end].eq_ignore_ascii_case(&query[12..qe]))};
                if let Some(head)=head {
                    if answer.len()==head+14 && answer.get(head..head+4)==Some(&[0,1,0,1])
                        && answer.get(head+8..head+10)==Some(&[0,4]) {
                        return Some(vec![Ipv4Addr::new(answer[head+10],answer[head+11],answer[head+12],answer[head+13])]);
                    }
                }
            }
        }
    }
    strict_answer_addresses(answer,query)
}
fn strict_answer_addresses(answer: &[u8], query: &[u8]) -> Option<Vec<Ipv4Addr>> {
    let (_,end)=read_labels(query,12)?;
    let mut question=query.get(..end+4)?.to_vec(); question[6..12].fill(0);
    crate::on_demand::dns_addresses(answer,&question)?.iter().map(|ip|ip.parse().ok()).collect()
}

fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    (!left.is_zero()).then_some(left)
}
fn read_exact_until(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> Option<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?)).ok()?;
        match stream.read(bytes) {
            Ok(0) => return None,
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(())
}
fn read_framed_until(stream: &mut TcpStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut head = [0;2]; read_exact_until(stream,&mut head,deadline)?;
    let length=u16::from_be_bytes(head) as usize; if length==0 { return None; }
    let mut out=vec![0;length]; read_exact_until(stream,&mut out,deadline)?; Some(out)
}
fn write_framed_until(stream: &mut TcpStream, message: &[u8], deadline: Instant) -> Option<()> {
    let length=u16::try_from(message.len()).ok()?;
    let mut frame=Vec::with_capacity(message.len()+2); frame.extend(length.to_be_bytes()); frame.extend(message);
    let mut bytes=frame.as_slice();
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?)).ok()?;
        match stream.write(bytes) {
            Ok(0) => return None,
            Ok(n) => bytes=&bytes[n..],
            Err(e) if e.kind()==io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(())
}
fn udp_exchange_until(query: &[u8], server: &str, port: u16, interface: Option<&InterfaceBinding>, deadline: Instant) -> Option<Vec<u8>> {
    let addr=server_address(server,port)?;
    let s=upstream_socket(Type::DGRAM,interface)?;
    s.connect(&SockAddr::from(addr)).ok()?;
    s.set_write_timeout(Some(remaining(deadline)?)).ok()?;
    if s.send(query).ok()? != query.len() { return None; }
    // Keep the full datagram capacity without allocating 64 KiB for every
    // small answer. Only recv's initialised prefix is copied into the result.
    let mut buffer=[std::mem::MaybeUninit::<u8>::uninit();65535];
    loop {
        s.set_read_timeout(Some(remaining(deadline)?)).ok()?;
        let n=s.recv(&mut buffer).ok()?; if n==0 { return None; }
        // socket2 guarantees the returned prefix has been initialised by recv.
        // Bytes outside that prefix are never inspected or sent to a client.
        let received=unsafe {std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(),n)};
        if same_id(received,query) {
            return Some(received.to_vec());
        }
    }
}
#[cfg(test)]
fn udp_exchange(query: &[u8], server: &str, port: u16, interface: Option<&InterfaceBinding>, timeout: Duration) -> Option<Vec<u8>> {
    udp_exchange_until(query,server,port,interface,Instant::now()+timeout)
}
fn tcp_exchange_until(query: &[u8], server: &str, port: u16, interface: Option<&InterfaceBinding>, deadline: Instant) -> Option<Vec<u8>> {
    let addr=server_address(server,port)?;
    let s=upstream_socket(Type::STREAM,interface)?;
    s.connect_timeout(&SockAddr::from(addr),remaining(deadline)?).ok()?;
    let mut stream: TcpStream=s.into();
    write_framed_until(&mut stream,query,deadline)?;
    let answer=read_framed_until(&mut stream,deadline)?;
    same_id(&answer,query).then_some(answer)
}

/// Each server in turn, within one absolute budget. Partial TCP reads/writes
/// consume the same budget instead of starting another socket timeout.
pub fn exchange(query: &[u8], servers: &[String], port: u16, interface: Option<&str>, timeout: Duration) -> Option<Vec<u8>> {
    let binding=match interface {Some(name)=>Some(InterfaceBinding::new(name)?),None=>None};
    exchange_bound(query,servers,port,binding.as_ref(),timeout)
}
fn exchange_bound(query: &[u8], servers: &[String], port: u16, interface: Option<&InterfaceBinding>, timeout: Duration) -> Option<Vec<u8>> {
    let attempts=u32::try_from(servers.len().saturating_mul(2)).unwrap_or(u32::MAX);
    let budget=timeout.saturating_mul(attempts).min(Duration::from_secs(8));
    exchange_until(query,servers,port,interface,timeout,Instant::now()+budget)
}
fn exchange_until(query: &[u8], servers: &[String], port: u16, interface: Option<&InterfaceBinding>, attempt: Duration, deadline: Instant) -> Option<Vec<u8>> {
    for server in servers {
        remaining(deadline)?;
        if let Some(answer)=udp_exchange_until(query,server,port,interface,deadline.min(Instant::now()+attempt)) {
            if !is_truncated(&answer) { return Some(answer); }
        }
        remaining(deadline)?;
        if let Some(answer)=tcp_exchange_until(query,server,port,interface,deadline.min(Instant::now()+attempt)) {
            if !is_truncated(&answer) { return Some(answer); }
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

/// Bootstrap exception for the VPN gateway itself, called by the signed App
/// through the root service. Never a general resolver or a system fallback.
/// Direct/company site queries continue through the split forwarder.
static GATEWAY_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_GATEWAY_INFLIGHT: usize = 4;
pub struct GatewayPermit { deadline: Instant }
impl GatewayPermit {
    pub(crate) fn claim() -> Option<Self> {
        let mut count=GATEWAY_INFLIGHT.load(Ordering::Acquire);
        loop {
            if count>=MAX_GATEWAY_INFLIGHT {return None;}
            match GATEWAY_INFLIGHT.compare_exchange_weak(count,count+1,Ordering::AcqRel,Ordering::Acquire) {
                Ok(_) => break, Err(actual) => count=actual,
            }
        }
        Some(Self {deadline: Instant::now()+Duration::from_millis(2400)})
    }
    pub(crate) fn active(&self) -> bool { remaining(self.deadline).is_some() }
}
impl Drop for GatewayPermit { fn drop(&mut self) { GATEWAY_INFLIGHT.fetch_sub(1,Ordering::AcqRel); } }
pub fn resolve_gateway(host: &str, servers: &[String], physical_if: &str) -> Vec<String> {
    let Some(permit)=GatewayPermit::claim() else {return vec![]};
    resolve_gateway_with(&permit,host,servers,physical_if)
}
pub(crate) fn resolve_gateway_with(permit: &GatewayPermit, host: &str, servers: &[String], physical_if: &str) -> Vec<String> {
    if !permit.active() { return vec![]; }
    if let Ok(ip)=host.parse::<Ipv4Addr>() { return vec![ip.to_string()]; }
    let Some(mut query)=crate::on_demand::dns_query(host) else {return vec![]};
    let mut id=[0;2];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut id)).is_err() {return vec![];}
    query[..2].copy_from_slice(&id);
    let servers: Vec<_>=servers.iter().take(2).cloned().collect();
    let Some(binding)=InterfaceBinding::physical(physical_if) else {return vec![]};
    let Some(left)=remaining(permit.deadline) else {return vec![]};
    let slots=(servers.len().max(1)*2) as u32;
    let Some(answer)=exchange_until(&query,&servers,53,Some(&binding),left/slots,permit.deadline) else {return vec![]};
    answer_addresses(&answer,&query).unwrap_or_default().iter().map(ToString::to_string).collect()
}

/// Only a fresh, explicit unheld reply permits system bootstrap. Unknown
/// service state remains fail closed; this applies to the gateway name only.
pub fn gateway_system_bootstrap(held:Option<bool>)->bool {held==Some(false)}

pub(crate) fn dhcp_dns(bytes: &[u8]) -> Vec<String> {
    if bytes.len()%4 != 0 {return vec![];}
    bytes.chunks_exact(4).map(|b| Ipv4Addr::new(b[0],b[1],b[2],b[3]).to_string()).collect()
}

/// Compatibility probe used only for the local port-conflict notice.
pub fn loopback_dns_busy(port:u16,timeout:Duration)->bool {
    if port==0||timeout.is_zero(){return false;}
    let deadline=Instant::now()+timeout.min(Duration::from_millis(500));
    (||->Option<()> {
        let socket=crate::child_io::socket(Domain::IPV4,Type::DGRAM,Some(Protocol::UDP)).ok()?;
        socket.connect(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST,port))).ok()?;
        socket.set_write_timeout(Some(remaining(deadline)?)).ok()?;
        let query=[0x41,0x43,1,0,0,1,0,0,0,0,0,0,9,b'l',b'o',b'c',b'a',b'l',b'h',b'o',b's',b't',0,0,1,0,1];
        if socket.send(&query).ok()?!=query.len(){return None;}
        socket.set_read_timeout(Some(remaining(deadline)?)).ok()?;
        let mut bytes=[std::mem::MaybeUninit::<u8>::uninit();512];
        (socket.recv(&mut bytes).ok()?>0).then_some(())
    })().is_some()
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
    /// Required for VPN queries. None means the tunnel is unavailable.
    pub tunnel_if: Option<String>,
}

/// Called with the list entry a direct name matched and its IPv4
/// addresses before the answer is returned; must return only once they
/// are routed direct.
pub type DirectHook = Box<dyn Fn(&str, &[Ipv4Addr]) + Send + Sync>;

/// A DNS observation is committed by the engine's serial event queue before
/// its answer is published. The epoch rejects old rules, networks and sessions.
pub struct Observation {
    pub epoch: u64,
    pub name: String,
    pub entry: Option<String>,
    pub addresses: Vec<Ipv4Addr>,
    pub direct: Vec<Ipv4Addr>,
}
pub type AnswerHook = Box<dyn Fn(Observation) -> bool + Send + Sync>;
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
struct Settings {
    epoch: u64,
    rules: Arc<SplitRules>,
    upstreams: Upstreams,
    enabled: bool,
    physical_binding: Option<InterfaceBinding>,
    tunnel_binding: Option<InterfaceBinding>,
}

type Acknowledged = (u64, Vec<Ipv4Addr>, Vec<Ipv4Addr>);

pub struct Inner {
    upstream_port: u16,
    timeout: Duration,
    settings: RwLock<Settings>,
    on_answer: Option<AnswerHook>,
    acknowledged: Mutex<HashMap<String, Acknowledged>>,
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
    fn remember(&self, ips: &[Ipv4Addr], name: &str) {
        if ips.is_empty() {
            return;
        }
        let clean = trim_dots(name);
        let mut names = self.names.lock().unwrap();
        if names.len() > NAME_CACHE_LIMIT {
            names.clear();
        }
        if let [ip]=ips { names.insert(*ip,clean); }
        else { for ip in ips { names.insert(*ip,clean.clone()); } }
    }

    fn direct(&self, entry: &str, ips: &[Ipv4Addr]) {
        if let Some(hook) = &self.on_direct {
            hook(entry, ips);
        }
    }

    /// The answer to send back, or None when there is none to give (the
    /// client then retries or moves on to the next server).
    pub fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.resolve_in_session(query, None)
    }

    fn resolve_in_session(&self, query: &[u8], session: Option<&std::sync::atomic::AtomicBool>) -> Option<Vec<u8>> {
        let q = question(query)?;
        let (epoch, rules, up, physical_binding, tunnel_binding) = {
            let settings = self.settings.read().unwrap();
            if !settings.enabled || session.is_some_and(|live| !live.load(Ordering::Acquire)) { return None; }
            (settings.epoch, settings.rules.clone(), settings.upstreams.clone(), settings.physical_binding.clone(), settings.tunnel_binding.clone())
        };
        let entry = rules.matches(&q.name);
        if q.qtype == TYPE_AAAA { return empty_answer(query); }
        let (servers, interface) = if entry.is_some() {
            let binding = if up.physical_if.is_some() { Some(physical_binding.as_ref()?) } else { None };
            (&up.local, binding)
        } else {
            // Never create an unbound VPN socket, including before connect,
            // after a drop, or while an interface change is being confirmed.
            (&up.tunnel, Some(tunnel_binding.as_ref()?))
        };
        let answer = exchange_bound(query, servers, self.upstream_port, interface, self.timeout)?;
        let mut addresses = if q.qtype == TYPE_A && answer[3] & 0x0f == 0 {
            answer_addresses(&answer, query)?
        } else { Vec::new() };
        addresses.sort_unstable(); addresses.dedup();
        let direct: Vec<_> = addresses.iter().copied()
            .filter(|ip| crate::direct_routes::ordinary_unicast(*ip) && (entry.is_some() || rules.contains(*ip))).collect();
        if self.settings.read().unwrap().epoch != epoch { return None; }
        if q.qtype == TYPE_A {
            if let Some(hook) = &self.on_answer {
                let name = trim_dots(&q.name);
                let duplicate = self.acknowledged.lock().unwrap().get(&name)
                    .is_some_and(|(seen,ips,allowed)|*seen==epoch&&*ips==addresses&&*allowed==direct);
                if !duplicate {
                    if !hook(Observation { epoch, name: name.clone(), entry: entry.clone(), addresses: addresses.clone(), direct: direct.clone() }) {
                        self.acknowledged.lock().unwrap().clear();
                        return None;
                    }
                    let current = self.settings.read().unwrap();
                    if current.epoch != epoch { return None; }
                    let mut known = self.acknowledged.lock().unwrap();
                    if known.len() >= NAME_CACHE_LIMIT
                        || known.values().map(|v| v.1.len() + v.2.len()).sum::<usize>() + addresses.len() + direct.len() > 8192 { known.clear(); }
                    known.insert(name, (epoch, addresses.clone(), direct.clone()));
                }
            }
        }

        // Legacy harness hook is protected against concurrent updates too.
        // Production uses on_answer, which commits under the engine's queue.
        let settings = self.settings.read().unwrap();
        if settings.epoch != epoch { return None; }
        if !direct.is_empty() {
            self.direct(entry.as_deref().unwrap_or(&site_name(&q.name)), &direct);
        }
        self.remember(&addresses, &q.name);
        if is_service(q.qtype) {
            return without_addresses(&answer, entry.is_some()).or_else(|| empty_answer(query));
        }
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
    replies: Arc<Replies>,
}

/// Workers own this gate, never a copy of the listener's descriptor. Closing
/// it only waits for a nonblocking UDP send, not DNS or an engine callback.
struct Replies {
    active: std::sync::atomic::AtomicBool,
    udp: Mutex<Option<UdpSocket>>,
}

impl Replies {
    fn close(&self) {
        self.active.store(false, Ordering::Release);
        self.udp.lock().unwrap().take();
    }

    fn send(&self, answer: &[u8], peer: std::net::SocketAddr) {
        if let Some(socket) = self.udp.lock().unwrap().as_ref() {
            let _ = socket.send_to(answer, peer);
        }
    }
}

pub struct Forwarder {
    inner: Arc<Inner>,
    listen: SocketAddrV4,
    listening: Mutex<Option<Listening>>,
}

fn listener(ty: Type, address: SocketAddrV4) -> io::Result<Socket> {
    let proto = if ty == Type::DGRAM { Protocol::UDP } else { Protocol::TCP };
    let s = crate::child_io::socket(Domain::IPV4, ty, Some(proto))?;
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
        Self::with_answer_hook(listen, upstream_port, timeout, direct, upstreams, on_direct, None)
    }

    pub fn with_answer_hook(listen: SocketAddrV4, upstream_port: u16, timeout: Duration,
        direct: Vec<String>, upstreams: Upstreams, on_direct: Option<DirectHook>, on_answer: Option<AnswerHook>) -> Self {
        let physical_binding = upstreams.physical_if.as_deref().and_then(InterfaceBinding::physical);
        let tunnel_binding = upstreams.tunnel_if.as_deref().and_then(InterfaceBinding::new);
        Forwarder {
            inner: Arc::new(Inner {
                upstream_port,
                timeout,
                settings: RwLock::new(Settings { epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
                    rules: Arc::new(SplitRules::new(&direct)), upstreams, enabled: true, physical_binding, tunnel_binding }),
                on_answer,
                acknowledged: Mutex::new(HashMap::new()),
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
        let mut settings = self.inner.settings.write().unwrap();
        settings.rules = parsed;
        self.inner.acknowledged.lock().unwrap().clear();
        settings.epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_upstreams(&self, upstreams: Upstreams) {
        self.update_upstreams(upstreams,None,false);
    }
    pub(crate) fn set_pinned_upstreams(&self, upstreams: Upstreams, index: Option<u32>) {
        self.update_upstreams(upstreams,index,true);
    }
    fn update_upstreams(&self, upstreams: Upstreams, pinned: Option<u32>, require_pin: bool) {
        let mut settings=self.inner.settings.write().unwrap();
        self.inner.acknowledged.lock().unwrap().clear();
        settings.physical_binding=upstreams.physical_if.as_deref().and_then(InterfaceBinding::physical);
        settings.tunnel_binding=upstreams.tunnel_if.as_deref().and_then(|name| {
            if require_pin {pinned.and_then(|index|InterfaceBinding::pinned(name,index))}
            else {InterfaceBinding::new(name)}
        });
        settings.upstreams=upstreams; settings.epoch=NEXT_EPOCH.fetch_add(1,Ordering::Relaxed);
    }

    /// Loaded binding, not the engine's intended interface name. Used only by
    /// the on-demand check, including detecting interface-index replacement.
    pub fn bound_tunnel_interface(&self) -> Option<String> {
        let settings = self.inner.settings.read().unwrap();
        if !settings.enabled { return None; }
        let name = settings.upstreams.tunnel_if.as_ref()?;
        let binding = settings.tunnel_binding.as_ref()?;
        (InterfaceBinding::new(name).as_ref() == Some(binding)).then(|| name.clone())
    }

    pub fn epoch(&self) -> u64 { self.inner.settings.read().unwrap().epoch }

    pub fn is_current(&self, epoch: u64) -> bool {
        self.inner.settings.read().unwrap().epoch == epoch
    }

    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner.names.lock().unwrap().get(&ip).cloned()
    }

    /// Listens on UDP and TCP; Err when the port is taken.
    pub fn start(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut listening = self.listening.lock().unwrap();
        self.stop_locked(&mut listening);
        let udp: UdpSocket = listener(Type::DGRAM, self.listen)?.into();
        let tcp: TcpListener = listener(Type::STREAM, self.listen)?.into();
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let (read_end, write_end) = crate::child_io::pipe()?;
        let inner = Arc::clone(&self.inner);
        let replies = Arc::new(Replies {
            active: std::sync::atomic::AtomicBool::new(true),
            udp: Mutex::new(Some(udp.try_clone()?)),
        });
        let send_gate = Arc::clone(&replies);
        // One thread waits on both sockets and the stop pipe; a wake-up
        // drains every datagram and connection that is ready.
        let thread = std::thread::Builder::new().name("ac-dns".into()).stack_size(WORKER_STACK).spawn(move || {
            let mut buffer = [0u8; 4096];
            while send_gate.active.load(Ordering::Acquire) {
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
                while send_gate.active.load(Ordering::Acquire) {
                    let Ok((n, from)) = udp.recv_from(&mut buffer) else { break };
                    if n == 0 {
                        continue;
                    }
                    let query = buffer[..n].to_vec();
                    let reply = Arc::clone(&send_gate);
                    inner.spawn(move |inner| {
                        if let Some(answer) = inner.resolve_in_session(&query, Some(&reply.active)) {
                            reply.send(&answer, from);
                        }
                    });
                }
                while send_gate.active.load(Ordering::Acquire) {
                    let Ok((mut client, _)) = crate::child_io::accept(&tcp) else { break };
                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    let _ = socket2::SockRef::from(&client).set_nosigpipe(true);
                    let _ = client.set_nonblocking(false);
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    let session = Arc::clone(&send_gate);
                    inner.spawn(move |inner| {
                        if let Some(query) = read_framed_until(&mut client, Instant::now()+Duration::from_secs(5)) {
                            if let Some(answer) = inner.resolve_in_session(&query, Some(&session.active)) {
                                if session.active.load(Ordering::Acquire) {
                                    let _ = write_framed_until(&mut client, &answer, Instant::now()+Duration::from_secs(5));
                                }
                            }
                        }
                    });
                }
            }
        })?;
        self.inner.settings.write().unwrap().enabled = true;
        *listening = Some(Listening { wake: write_end, thread, replies });
        Ok(())
    }

    /// Stops listening and frees the port before returning. Queries
    /// already resolving may finish, but cannot send via the closed listener
    /// or enter a later listener session. Never waits for engine callbacks.
    pub fn stop(&self) {
        self.stop_locked(&mut self.listening.lock().unwrap());
    }

    fn stop_locked(&self, listening: &mut Option<Listening>) {
        use std::os::fd::AsRawFd;
        if let Some(listening) = listening.as_ref() { listening.replies.close(); }
        {
            let mut settings = self.inner.settings.write().unwrap();
            settings.epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
            settings.enabled = false;
        }
        *self.inner.acknowledged.lock().unwrap() = HashMap::new();
        *self.inner.names.lock().unwrap() = HashMap::new();
        let Some(listening) = listening.take() else { return };
        unsafe { libc::write(listening.wake.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        let _ = listening.thread.join();
        drop(listening.wake);
        drop(listening.replies);
        crate::child_io::after_close();
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
    static GATEWAY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn loopback_interface() -> &'static str {
        if cfg!(target_os = "macos") { "lo0" } else { "lo" }
    }

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
        // Keep listener fixtures away from ordinary clients' default ephemeral
        // range. Register the temporary reservations with the same exec fence.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..10000 {
            let port=(20000+(std::process::id() as usize+NEXT.fetch_add(1,Ordering::Relaxed))%10000) as u16;
            let address=SocketAddrV4::new(Ipv4Addr::LOCALHOST,port);
            let Ok(udp)=crate::child_io::udp_bind(address) else {continue};
            if crate::child_io::creation(||TcpListener::bind(address)).is_ok() {drop(udp);return port;}
        }
        panic!("no available loopback test listener port");
    }

    #[test]
    fn rule_change_rejects_late_direct_answer() {
      for change in ["rules", "network", "stop"] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap().to_string();
        let (seen_tx, seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let upstream = std::thread::spawn(move || {
            let mut buf = [0; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            seen_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            socket.send_to(&answer(&buf[..n], [203, 0, 113, 1], false), from).unwrap();
        });
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let fwd = Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), 53,
            Duration::from_secs(1), vec!["example.com".into()],
            Upstreams { tunnel: vec![], local: vec![server], physical_if: None, tunnel_if: Some(loopback_interface().into()) },
            Some(Box::new(move |_, _| { h.fetch_add(1, Ordering::SeqCst); })));
        let inner = fwd.inner().clone();
        let pending = std::thread::spawn(move || inner.resolve(&query("example.com", TYPE_A, 33)));
        seen_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match change {
            "rules" => fwd.set_rules(&[]),
            "network" => fwd.set_upstreams(Upstreams { tunnel: vec![], local: vec![], physical_if: None, tunnel_if: None }),
            _ => fwd.stop(),
        }
        release_tx.send(()).unwrap();
        assert!(pending.join().unwrap().is_none(), "old rules must not publish a late answer");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "old reply must not add a route");
        upstream.join().unwrap();
      }
    }

    #[test]
    fn single_address_fast_path_matches_the_strict_decoder_for_mutations() {
        for name in ["vpn.example", "V_Pn.Example", "xn--example.example"] {
            let q=query(name,TYPE_A,42); let good=answer(&q,[198,51,100,9],false);
            assert_eq!(answer_addresses(&good,&q),strict_answer_addresses(&good,&q));
            for index in 0..good.len() { for value in [0,1,2,0x3f,0x40,0x80,0xc0,0xff] {
                let mut mutated=good.clone(); mutated[index]=value;
                assert_eq!(answer_addresses(&mutated,&q),strict_answer_addresses(&mutated,&q),"{name} at {index}={value}");
            }}
            for length in 0..good.len() {assert_eq!(answer_addresses(&good[..length],&q),strict_answer_addresses(&good[..length],&q));}
        }
    }

    #[test]
    fn same_id_is_not_enough_to_accept_dns_answer() {
        let q = query("vpn.example", TYPE_A, 42);
        let wrong = answer(&query("direct.example", TYPE_A, 42), [203, 0, 113, 9], false);
        assert!(!same_id(&wrong, &q), "a different question must be rejected");
    }

    #[test]
    fn vpn_queries_require_a_current_interface_for_udp_and_tcp() {
        let (port, seen) = fake_udp([198, 51, 100, 2], false);
        let fwd = Forwarder::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), port,
            Duration::from_millis(100), vec!["direct.example".into()],
            Upstreams { tunnel: vec!["127.0.0.1".into()], local: vec!["127.0.0.1".into()],
                physical_if: Some(loopback_interface().into()), tunnel_if: None }, None);
        let q = query("vpn.example", TYPE_A, 1);
        assert!(fwd.inner.resolve(&q).is_none());
        assert!(fwd.bound_tunnel_interface().is_none());
        assert_eq!(seen.load(Ordering::SeqCst), 0);
        // Direct DNS remains on the physical interface while VPN DNS waits.
        assert!(fwd.inner.resolve(&query("direct.example", TYPE_A, 2)).is_some());
        for interface in ["ac-missing-interface", loopback_interface()] {
            fwd.set_upstreams(Upstreams { tunnel: vec!["127.0.0.1".into()], local: vec![],
                physical_if: None, tunnel_if: Some(interface.into()) });
            assert_eq!(fwd.inner.resolve(&q).is_some(), interface == loopback_interface());
            assert_eq!(fwd.bound_tunnel_interface().is_some(), interface == loopback_interface());
            assert_eq!(exchange(&q, &["127.0.0.1".into()], port, Some("ac-missing-interface"), Duration::from_millis(50)), None);
        }
        assert_eq!(seen.load(Ordering::SeqCst), 2, "invalid binding never falls back to an unbound socket");
    }

    #[test]
    fn udp_rejects_a_reply_from_another_source_and_wrong_question() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut buf = [0; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let other = UdpSocket::bind("127.0.0.1:0").unwrap();
            other.send_to(&answer(&buf[..n], [203, 0, 113, 66], false), peer).unwrap();
            let wrong = query("wrong.example", TYPE_A, 77);
            server.send_to(&answer(&wrong, [203, 0, 113, 77], false), peer).unwrap();
            server.send_to(&answer(&buf[..n], [198, 51, 100, 2], false), peer).unwrap();
        });
        let a = udp_exchange(&query("vpn.example", TYPE_A, 77), "127.0.0.1", port,
            InterfaceBinding::new(loopback_interface()).as_ref(), Duration::from_secs(1)).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(198, 51, 100, 2)]);
        t.join().unwrap();
    }

    #[test]
    fn only_related_cname_addresses_can_change_routes() {
        let q = query("direct.example", TYPE_A, 10);
        let here = [0xc0, 12];
        let records = [rr(&here, TYPE_CNAME, 60, &wire("edge.example")),
            rr(&wire("edge.example"), TYPE_A, 60, &[198, 51, 100, 2]),
            rr(&wire("unrelated.example"), TYPE_A, 60, &[203, 0, 113, 9])];
        let a = reply(&q, &records, &[], &[]);
        assert_eq!(answer_addresses(&a, &q), Some(vec![Ipv4Addr::new(198, 51, 100, 2)]));
        let mut bad_class = a.clone();
        let (_, end) = read_labels(&bad_class, q.len()).unwrap();
        bad_class[end + 3] = 3;
        assert_eq!(answer_addresses(&bad_class, &q), None);
    }

    #[test]
    fn repeated_observation_skips_only_engine_work_not_dns_or_epoch_validation() {
        let (port, queries) = fake_udp([198, 51, 100, 2], false);
        let commits = Arc::new(AtomicUsize::new(0)); let count = commits.clone();
        let fwd = Forwarder::with_answer_hook(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), port,
            Duration::from_millis(100), vec![], Upstreams { tunnel: vec!["127.0.0.1".into()], local: vec![],
                physical_if: None, tunnel_if: Some(loopback_interface().into()) }, None,
            Some(Box::new(move |_| { count.fetch_add(1, Ordering::SeqCst); true })));
        let q = query("vpn.example", TYPE_A, 1);
        assert!(fwd.inner.resolve(&q).is_some()); assert!(fwd.inner.resolve(&q).is_some());
        assert_eq!(queries.load(Ordering::SeqCst), 2); assert_eq!(commits.load(Ordering::SeqCst), 1);
        fwd.set_rules(&["another.example".into()]);
        assert!(fwd.inner.resolve(&q).is_some());
        assert_eq!(commits.load(Ordering::SeqCst), 2, "old acknowledgements cannot survive a rule generation");
        fwd.stop(); assert!(fwd.inner.resolve(&q).is_none());
        assert_eq!(fwd.inner.acknowledged.lock().unwrap().capacity(), 0);
        assert_eq!(fwd.inner.names.lock().unwrap().capacity(), 0);
    }

    #[test]
    fn gateway_permits_cap_inflight_work_and_expired_work_does_not_query() {
        let _serial=GATEWAY_TEST_LOCK.lock().unwrap();
        let permits: Vec<_>=(0..MAX_GATEWAY_INFLIGHT).map(|_|GatewayPermit::claim().unwrap()).collect();
        assert!(GatewayPermit::claim().is_none()); drop(permits);
        let mut permit=GatewayPermit::claim().unwrap(); permit.deadline=Instant::now()-Duration::from_millis(1);
        assert!(!permit.active());
        assert!(resolve_gateway_with(&permit,"203.0.113.1",&[],"lo0").is_empty());
    }

    #[test]
    fn slow_tcp_dns_cannot_extend_gateway_budget_or_keep_permits() {
        let _serial=GATEWAY_TEST_LOCK.lock().unwrap();
        let server=TcpListener::bind("127.0.0.1:0").unwrap(); let port=server.local_addr().unwrap().port();
        let udp=UdpSocket::bind(("127.0.0.1",port)).unwrap();
        let u=std::thread::spawn(move || { let mut b=[0;512]; let (n,peer)=udp.recv_from(&mut b).unwrap(); udp.send_to(&answer(&b[..n],[198,51,100,1],true),peer).unwrap(); });
        let t=std::thread::spawn(move || {
            let (mut peer,_)=server.accept().unwrap();
            #[cfg(target_os="macos")] socket2::SockRef::from(&peer).set_nosigpipe(true).unwrap();
            let q=read_framed(&mut peer).unwrap(); let a=answer(&q,[198,51,100,1],false);
            if peer.write_all(&(a.len() as u16).to_be_bytes()).is_ok() { for byte in a { if peer.write_all(&[byte]).is_err(){break;} std::thread::sleep(Duration::from_millis(120)); } }
        });
        let start=Instant::now();
        assert!(resolve_gateway("gw.example",&[format!("127.0.0.1:{port}")],loopback_interface()).is_empty());
        assert!(start.elapsed()<Duration::from_millis(1400));
        u.join().unwrap(); t.join().unwrap();
        assert_eq!(dhcp_dns(&[192,168,1,1,192,168,1,2]),vec!["192.168.1.1","192.168.1.2"]);
        assert!(dhcp_dns(&[1,2,3]).is_empty());
    }

    #[test]
    fn physical_dns_leaves_only_from_the_pf_source_ports() {
        // UDP and the TCP fallback both use the PF-named source range on the
        // physical binding; tunnel DNS keeps ordinary ephemeral ports.
        let (low, high) = PHYSICAL_DNS_SOURCE_PORTS;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let tcp = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let peers = Arc::new(Mutex::new(Vec::<u16>::new()));
        let seen = Arc::clone(&peers);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = server.recv_from(&mut buf) {
                seen.lock().unwrap().push(from.port());
                let _ = server.send_to(&answer(&buf[..n], [198, 51, 100, 7], true), from);
            }
        });
        let tcp_peers = Arc::clone(&peers);
        std::thread::spawn(move || {
            for mut client in tcp.incoming().flatten() {
                tcp_peers.lock().unwrap().push(client.peer_addr().unwrap().port());
                if let Some(q) = read_framed(&mut client) { let _ = write_framed(&mut client, &answer(&q, [198, 51, 100, 7], false)); }
            }
        });
        let q = query("direct.example", TYPE_A, 9);
        let physical = InterfaceBinding::physical(loopback_interface()).unwrap();
        let reply = exchange_bound(&q, &[format!("127.0.0.1:{port}")], 53, Some(&physical), Duration::from_secs(1)).unwrap();
        assert!(!is_truncated(&reply), "the truncated UDP answer must be retried over TCP");
        let pinned = std::mem::take(&mut *peers.lock().unwrap());
        assert_eq!(pinned.len(), 2, "one UDP and one TCP exchange");
        assert!(pinned.iter().all(|p| (low..=high).contains(p)), "physical DNS left from {pinned:?}");
        let tunnel = InterfaceBinding::new(loopback_interface()).unwrap();
        exchange_bound(&q, &[format!("127.0.0.1:{port}")], 53, Some(&tunnel), Duration::from_secs(1)).unwrap();
        assert!(peers.lock().unwrap().iter().all(|p| !(low..=high).contains(p)), "tunnel DNS does not need the physical exception");
    }

    #[test]
    fn gateway_bootstrap_is_bounded_validated_and_interface_bound() {
        let _serial=GATEWAY_TEST_LOCK.lock().unwrap();
        let (port, seen) = fake_udp([198, 51, 100, 2], false);
        let servers = vec![format!("127.0.0.1:{port}")];
        assert_eq!(resolve_gateway("gw.example", &servers, loopback_interface()), vec!["198.51.100.2"]);
        assert!(resolve_gateway("gw.example", &servers, "ac-no-interface").is_empty());
        assert!(resolve_gateway("not a name;command", &servers, loopback_interface()).is_empty());
        assert_eq!(resolve_gateway("203.0.113.1", &[], "ac-no-interface"), vec!["203.0.113.1"]);
        assert_eq!(seen.load(Ordering::SeqCst), 1, "invalid bindings/hosts never fall back to another resolver");
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
                tunnel_if: Some(loopback_interface().into()),
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
            tunnel_if: Some(loopback_interface().into()),
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
    #[test]
    fn stopped_forwarder_releases_listener_while_answer_ack_is_pending() {
        let (upstream,_)=fake_udp([203,0,113,9],false);
        let (entered,ready)=mpsc::channel();let (release,wait)=mpsc::channel();let wait=Mutex::new(wait);
        let hook:AnswerHook=Box::new(move |_|{entered.send(()).unwrap();wait.lock().unwrap().recv_timeout(Duration::from_secs(3)).unwrap();true});
        let port=free_port();
        let forwarder=Forwarder::with_answer_hook(SocketAddrV4::new(Ipv4Addr::LOCALHOST,port),53,Duration::from_millis(500),vec!["direct.example".into()],Upstreams{tunnel:vec![],local:vec![format!("127.0.0.1:{upstream}")],physical_if:None,tunnel_if:None},None,Some(hook));
        forwarder.start().unwrap();
        let client=UdpSocket::bind("127.0.0.1:0").unwrap();client.send_to(&query("direct.example",TYPE_A,1),("127.0.0.1",port)).unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        forwarder.stop();
        let rebound=UdpSocket::bind(("127.0.0.1",port));
        release.send(()).unwrap();
        assert!(rebound.is_ok(),"stop retained the UDP listener through an outstanding policy acknowledgement: {:?}",rebound.err());
    }

    #[test]
    fn worker_forwards_large_udp_answers_without_truncation() {
        let message = query("large.example", 16, 7);
        let mut answer = message.clone();
        answer[2..4].copy_from_slice(&[0x81, 0x80]);
        answer[6..8].copy_from_slice(&[0, 1]);
        let mut text = Vec::new();
        // Stay below Darwin's default UDP send limit; still exceed the old
        // 4096-byte listener buffer while exercising the 128 KiB worker stack.
        for _ in 0..32 { text.push(255); text.extend([b'x'; 255]); }
        answer.extend([0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60]);
        answer.extend((text.len() as u16).to_be_bytes()); answer.extend(text);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let address = server.local_addr().unwrap().to_string();
        let expected = answer.clone();
        let upstream = std::thread::spawn(move || {
            let mut bytes = [0; 512];
            let (n, peer) = server.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], message.as_slice());
            server.send_to(&answer, peer).unwrap();
        });
        let port = free_port();
        let forwarder = Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_secs(1), vec!["large.example".into()],
            Upstreams { tunnel: vec![], local: vec![address], physical_if: None, tunnel_if: None }, None,
        );
        forwarder.start().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.send_to(&query("large.example", 16, 7), ("127.0.0.1", port)).unwrap();
        let mut bytes = vec![0; 65535];
        let (n, _) = client.recv_from(&mut bytes).unwrap();
        assert!(n > 8192);
        assert_eq!(&bytes[..n], expected.as_slice());
        forwarder.stop(); upstream.join().unwrap();
    }

    #[test]
    fn restart_works_before_old_dns_ack_finishes_and_discards_its_answer() {
        let (upstream, _) = fake_udp([203, 0, 113, 9], false);
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let wait = Mutex::new(wait);
        let first = std::sync::atomic::AtomicBool::new(true);
        let hook: AnswerHook = Box::new(move |_| {
            if first.swap(false, Ordering::AcqRel) {
                entered.send(()).unwrap();
                wait.lock().unwrap().recv_timeout(Duration::from_secs(3)).unwrap();
                finished.send(()).unwrap();
            }
            true
        });
        let port = free_port();
        let forwarder = Forwarder::with_answer_hook(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_millis(200),
            vec!["direct.example".into()],
            Upstreams { tunnel: vec![], local: vec![format!("127.0.0.1:{upstream}")], physical_if: None, tunnel_if: None },
            None, Some(hook),
        );
        forwarder.start().unwrap();
        let old = UdpSocket::bind("127.0.0.1:0").unwrap();
        old.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        old.send_to(&query("direct.example", TYPE_A, 1), ("127.0.0.1", port)).unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let old_session = forwarder.listening.lock().unwrap().as_ref().unwrap().replies.clone();
        let began = Instant::now();
        forwarder.stop();
        assert!(began.elapsed() < Duration::from_secs(1), "stop must not wait for an engine acknowledgement");
        forwarder.start().unwrap();
        let new_answer = ask(&query("new.direct.example", TYPE_A, 2), port).unwrap();
        assert_eq!(ipv4_answers(&new_answer), vec![Ipv4Addr::new(203, 0, 113, 9)]);
        // Even a job not yet started when stop ran cannot enter the new
        // session or query its upstream using old work.
        assert!(forwarder.inner.resolve_in_session(&query("direct.example", TYPE_A, 3), Some(&old_session.active)).is_none());
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(old.recv_from(&mut [0; 512]).is_err(), "old listener must never publish through its successor");
        forwarder.stop();
        assert!(UdpSocket::bind(("127.0.0.1", port)).is_ok());
    }

    #[test]
    fn old_tcp_client_cannot_query_the_restarted_forwarder() {
        let (upstream, queries) = fake_udp([203, 0, 113, 9], false);
        let port = free_port();
        let forwarder = Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_millis(200),
            vec!["direct.example".into()],
            Upstreams { tunnel: vec![], local: vec![format!("127.0.0.1:{upstream}")], physical_if: None, tunnel_if: None }, None,
        );
        forwarder.start().unwrap();
        let mut old = TcpStream::connect(("127.0.0.1", port)).unwrap();
        old.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while forwarder.inner.inflight.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < deadline, "TCP client was not accepted");
            std::thread::yield_now();
        }
        forwarder.stop();
        forwarder.start().unwrap();
        write_framed(&mut old, &query("direct.example", TYPE_A, 1)).unwrap();
        assert!(read_framed(&mut old).is_none());
        assert_eq!(queries.load(Ordering::Acquire), 0, "old TCP client must not use the new session's upstream");
        assert!(ask(&query("direct.example", TYPE_A, 2), port).is_some());
        assert_eq!(queries.load(Ordering::Acquire), 1);
        forwarder.stop();
    }

    #[test]
    fn concurrent_start_stop_and_failed_start_leave_no_listener() {
        let port = free_port();
        let forwarder = Arc::new(Forwarder::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 53, Duration::from_millis(50), vec![],
            Upstreams { tunnel: vec![], local: vec![], physical_if: None, tunnel_if: None }, None,
        ));
        let users: Vec<_> = (0..4).map(|_| {
            let forwarder = forwarder.clone();
            std::thread::spawn(move || for _ in 0..10 { forwarder.start().unwrap(); forwarder.stop(); })
        }).collect();
        for user in users { user.join().unwrap(); }
        forwarder.stop();
        let occupied = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        assert!(forwarder.start().is_err());
        assert!(!forwarder.inner.settings.read().unwrap().enabled);
        assert!(forwarder.listening.lock().unwrap().is_none());
        drop(occupied);
        forwarder.start().unwrap();
        forwarder.stop();
        assert!(UdpSocket::bind(("127.0.0.1", port)).is_ok());
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
    }

    #[test]
    fn gateway_bootstrap_accepts_an_ordinary_slow_physical_resolver() {
        let _serial=GATEWAY_TEST_LOCK.lock().unwrap();
        let server=UdpSocket::bind("127.0.0.1:0").unwrap();let address=server.local_addr().unwrap().to_string();
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let responder=std::thread::spawn(move || {let mut bytes=[0;512];let (n,peer)=server.recv_from(&mut bytes).unwrap();
            std::thread::sleep(Duration::from_millis(350));let mut response=bytes[..n].to_vec();response[2..4].copy_from_slice(&[0x81,0x80]);response[6..8].copy_from_slice(&[0,1]);response.extend([0xc0,12,0,1,0,1,0,0,0,60,0,4,198,51,100,9]);let _=server.send_to(&response,peer);});
        let result=resolve_gateway("gateway.example",&[address],loopback_interface());responder.join().unwrap();
        assert_eq!(result,vec!["198.51.100.9"],"normal mobile RTT must fit within the bootstrap budget");
    }

    #[test]
    fn system_gateway_bootstrap_requires_a_fresh_unheld_verdict() {
        assert!(gateway_system_bootstrap(Some(false)));
        assert!(!gateway_system_bootstrap(Some(true)));
        assert!(!gateway_system_bootstrap(None));
    }

    #[test]
    fn local_dns_conflict_probe_uses_its_private_socket_and_short_budget() {
        let server=crate::child_io::udp_bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0)).unwrap();
        server.set_read_timeout(Some(Duration::from_millis(300))).unwrap();let port=server.local_addr().unwrap().port();
        let (tx,rx)=mpsc::channel();
        let worker=std::thread::spawn(move||{let mut bytes=[0;512];if let Ok((n,peer))=server.recv_from(&mut bytes){tx.send(bytes[..n].to_vec()).unwrap();server.send_to(b"busy",peer).unwrap();}});
        let busy=loopback_dns_busy(port,Duration::from_millis(200));worker.join().unwrap();
        assert!(busy,"a local responder must still be classified as port busy");
        assert_eq!(rx.recv().unwrap(),vec![0x41,0x43,1,0,0,1,0,0,0,0,0,0,9,b'l',b'o',b'c',b'a',b'l',b'h',b'o',b's',b't',0,0,1,0,1]);
        let silent=crate::child_io::udp_bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0)).unwrap();let start=Instant::now();
        assert!(!loopback_dns_busy(silent.local_addr().unwrap().port(),Duration::from_millis(40)));
        assert!(start.elapsed()<Duration::from_secs(1));
        assert!(!loopback_dns_busy(0,Duration::from_millis(40)));
    }

}
