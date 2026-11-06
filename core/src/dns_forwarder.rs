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
//! split mode, so AAAA answers are empty for every name, and HTTPS
//! (SVCB) answers too for direct names (no unrouted address hints).
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
pub const TYPE_HTTPS: u16 = 65;

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
            return answer;
        };
        if q.qtype == TYPE_AAAA || q.qtype == TYPE_HTTPS {
            return empty_answer(query);
        }
        let answer = exchange(query, &up.local, self.upstream_port, up.physical_if.as_deref(), self.timeout)?;
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

    fn answer(q: &[u8], ip: [u8; 4], truncated: bool) -> Vec<u8> {
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
        let a = ask(&query("www.sitea.com", TYPE_HTTPS, 3), port).unwrap();
        assert_eq!(a[7], 0);
        assert_eq!(local_count.load(Ordering::SeqCst), 1);

        let a = ask(&query("intranet.example", TYPE_A, 4), port).unwrap();
        assert_eq!(ipv4_answers(&a), vec![Ipv4Addr::new(198, 51, 100, 2)]);
        let before = tunnel_count.load(Ordering::SeqCst);
        let a = ask(&query("intranet.example", TYPE_AAAA, 5), port).unwrap();
        assert_eq!((a[7], a[3] & 0x0F), (0, 0));
        assert_eq!(tunnel_count.load(Ordering::SeqCst), before);

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
