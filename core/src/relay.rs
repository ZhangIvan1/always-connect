//! The certificate relay's logic (DESIGN.md §二十三, §26.10, §30.6,
//! §30.9; moved from Swift to Rust in §32.7).
//!
//! The App keeps the two TLS legs (the gateway's needs the keychain
//! identity, whose private key only Security.framework can use) and hands
//! every plaintext read to a [`Stream`], one per relayed connection:
//!
//! - openconnect's HTTP requests pass through; bodies (the password among
//!   them) at once and never held, headers whole once complete, so the
//!   CONNECT's DTLS offer can lose PSK-NEGOTIATE (keys bound to each TLS
//!   leg, §26.10);
//! - the gateway's answer to CONNECT: on 200 its X-DTLS-Port is pointed at
//!   a local UDP port that forwards datagrams to the gateway's
//!   ([`DatagramRelay`]), and from then on both directions are cut back
//!   into whole CSTP packets, each sent by the App as its own TLS write
//!   (CSTP reads one packet per TLS record, §22.13);
//! - the login's shape goes to the relay log ([`AuthTrace`], §30.9):
//!   request kind, whether the password went, the gateway's wait, status,
//!   form id and message. Never a header, cookie, path or typed value.
//!
//! [`DatagramRelay`] forwards DTLS datagrams between openconnect
//! (127.0.0.1) and the gateway, unchanged, on one thread that waits in
//! poll and drains every ready datagram per wake-up. Its gateway socket
//! is bound to the physical interface the TLS leg uses: never through a
//! tunnel, ours included (§23.6).

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

/// One line for the relay log (~/Library/Logs/AlwaysConnect/relay.log,
/// written by the App).
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    Invalid,
    Oversized,
}

const HEADER_LIMIT: usize = 131072;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// MARK: - CSTP packets

/// Reassembles CSTP packets: "STF\x01", 2-byte big-endian payload
/// length, type, a zero byte, payload.
#[derive(Default)]
pub struct CstpFrames {
    bytes: Vec<u8>,
}

impl CstpFrames {
    /// Appends every whole packet now available to `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Chunks) -> Result<(), FramingError> {
        self.bytes.extend_from_slice(data);
        if self.bytes.len() > 131086 {
            return Err(FramingError::Oversized);
        }
        let mut at = 0;
        let result = loop {
            let rest = &self.bytes[at..];
            if rest.len() < 8 {
                break Ok(());
            }
            if rest[0] != 0x53 || rest[1] != 0x54 || rest[2] != 0x46 || rest[3] != 0x01 || rest[7] != 0 {
                break Err(FramingError::Invalid);
            }
            let count = 8 + (rest[4] as usize) * 256 + rest[5] as usize;
            if rest.len() < count {
                break Ok(());
            }
            out.push(&rest[..count]);
            at += count;
        };
        self.bytes.drain(..at);
        result
    }
}

/// What to send, in order, each as its own write. Reused between reads.
#[derive(Default)]
pub struct Chunks {
    data: Vec<u8>,
    ends: Vec<usize>,
}

impl Chunks {
    pub fn clear(&mut self) {
        self.data.clear();
        self.ends.clear();
    }
    pub fn push(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
        self.ends.push(self.data.len());
    }
    pub fn len(&self) -> usize {
        self.ends.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }
    pub fn get(&self, i: usize) -> &[u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        &self.data[start..self.ends[i]]
    }
    pub fn bytes(&self) -> usize {
        self.data.len()
    }
    pub fn to_vecs(&self) -> Vec<Vec<u8>> {
        (0..self.len()).map(|i| self.get(i).to_vec()).collect()
    }
}

// MARK: - HTTP headers

/// Rewrites single header values byte for byte: every other line,
/// banner bytes included, goes back exactly as it came. `edit(lowercased
/// name, trimmed value)` returns a new value or None to keep the line.
pub fn edit_header(header: &[u8], mut edit: impl FnMut(&str, &str) -> Option<String>) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + 16);
    let mut rest = header;
    while let Some(end) = find(rest, b"\r\n") {
        let line = &rest[..end];
        rest = &rest[end + 2..];
        let replaced = line.iter().position(|&b| b == b':').and_then(|colon| {
            let (name, value) = (&line[..colon], &line[colon + 1..]);
            if !name.is_ascii() || !value.is_ascii() {
                return None;
            }
            let name = std::str::from_utf8(name).ok()?;
            let value = std::str::from_utf8(value).ok()?.trim_matches(|c| c == ' ' || c == '\t');
            edit(&name.to_ascii_lowercase(), value).map(|v| format!("{name}: {v}"))
        });
        match replaced {
            Some(new) => out.extend_from_slice(new.as_bytes()),
            None => out.extend_from_slice(line),
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(rest);
    out
}

/// Passes openconnect's HTTP requests on and spots the CONNECT that
/// starts CSTP. Bodies (the password among them) go through at once and
/// are never held; a header is forwarded whole once it is complete, so
/// the CONNECT's DTLS offer can be edited (§26.10).
#[derive(Default)]
pub struct HttpRequests {
    header: Vec<u8>,
    body_remaining: usize,
}

impl HttpRequests {
    /// Appends what to forward for `data` to `out`; true when a CONNECT
    /// ended in it.
    pub fn pass(&mut self, data: &[u8], out: &mut Chunks) -> Result<bool, FramingError> {
        let mut bytes = data;
        let mut connect = false;
        while !bytes.is_empty() {
            if self.body_remaining > 0 {
                let count = self.body_remaining.min(bytes.len());
                self.body_remaining -= count;
                out.push(&bytes[..count]);
                bytes = &bytes[count..];
                continue;
            }
            self.header.extend_from_slice(bytes);
            if self.header.len() > HEADER_LIMIT {
                return Err(FramingError::Oversized);
            }
            let Some(boundary) = find(&self.header, b"\r\n\r\n").map(|i| i + 4) else {
                return Ok(connect);
            };
            let whole = std::mem::take(&mut self.header);
            let mut head = whole[..boundary].to_vec();
            let text = String::from_utf8_lossy(&head).into_owned();
            let lines: Vec<&str> = text.split("\r\n").collect();
            if lines.first().is_some_and(|l| l.starts_with("CONNECT ")) {
                connect = true;
                head = edit_header(&head, |name, value| {
                    if name != "x-dtls-ciphersuite" {
                        return None;
                    }
                    // PSK-NEGOTIATE derives the DTLS key from the TLS
                    // session, and openconnect's (to the relay) is not
                    // the gateway's: offer only master-secret suites.
                    let kept: Vec<&str> = value.split(':').filter(|s| !s.is_empty() && *s != "PSK-NEGOTIATE").collect();
                    (!kept.is_empty()).then(|| kept.join(":"))
                });
            }
            for line in lines.iter().skip(1) {
                let Some((name, value)) = line.split_once(':') else { continue };
                let name = name.to_ascii_lowercase();
                if name == "content-length" {
                    let count: usize = value.trim_matches(|c| c == ' ' || c == '\t').parse().map_err(|_| FramingError::Invalid)?;
                    if count > 1_048_576 {
                        return Err(FramingError::Invalid);
                    }
                    self.body_remaining = count;
                }
                if name == "transfer-encoding" {
                    return Err(FramingError::Invalid);
                }
            }
            out.push(&head);
            // What came after the header: the body or the next request.
            let tail = whole[boundary..].to_vec();
            return self.pass(&tail, out).map(|more| more || connect);
        }
        Ok(connect)
    }
}

// MARK: - Login trace (§30.9)

pub fn attribute(name: &str, tag: &str, text: &str) -> Option<String> {
    let open = format!("<{tag} {name}=\"");
    let start = text.find(&open)? + open.len();
    let rest = &text[start..];
    rest.find('"').map(|end| rest[..end].to_string())
}

pub fn element(tag: &str, text: &str) -> Option<String> {
    let open = text.find(&format!("<{tag}"))? + tag.len() + 1;
    let rest = &text[open..];
    let gt = rest.find('>')?;
    let close = rest.find(&format!("</{tag}>"))?;
    if gt >= close {
        return None;
    }
    let value = rest[gt + 1..close].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// The login's shape, for the relay log: which kind of request went to
/// the gateway (POST, whether it carried the password), how long the
/// gateway took to answer, its status and the auth form's id and
/// message. The answer to the password arrives only after the phone
/// approval, so the wait is visible without administrator rights.
pub struct AuthTrace {
    pair: u32,
    log: Option<Log>,
    sent_at: Option<Instant>,
    request: String,
    password: bool,
    /// (wait, status, body so far)
    answer: Option<(String, String, String)>,
    logged: bool,
}

impl AuthTrace {
    pub fn new(pair: u32, log: Option<Log>) -> Self {
        AuthTrace { pair, log, sent_at: None, request: String::new(), password: false, answer: None, logged: true }
    }

    fn write(&self, line: String) {
        if let Some(log) = &self.log {
            log(&line);
        }
    }

    pub fn observe(&mut self, data: &[u8], from_client: bool) {
        let text = String::from_utf8_lossy(&data[..data.len().min(16384)]).into_owned();
        if from_client {
            if let Some(method) = ["POST ", "GET "].iter().find(|m| text.starts_with(**m)) {
                self.flush();
                self.sent_at = Some(Instant::now());
                self.request = method.trim().to_string();
                self.password = false;
                self.answer = None;
                self.logged = false;
            }
            if text.contains("<password>") && !self.password && !self.logged {
                self.password = true;
                self.write(format!("pair {} login: {} with the password sent, waiting for the gateway", self.pair, self.request));
            }
            return;
        }
        let Some(sent) = self.sent_at else { return };
        if self.logged {
            return;
        }
        if self.answer.is_none() {
            let status = if text.starts_with("HTTP/") {
                text.split("\r\n").next().and_then(|l| l.split(' ').filter(|s| !s.is_empty()).nth(1)).unwrap_or("?").to_string()
            } else {
                "?".to_string()
            };
            self.answer = Some((format!("{:.1}", sent.elapsed().as_secs_f64()), status, String::new()));
        }
        let body = {
            let answer = self.answer.as_mut().unwrap();
            answer.2.push_str(&text);
            answer.2.clone()
        };
        // An XML answer is logged once its form is in; anything else as
        // soon as its header is.
        let Some(header_end) = body.find("\r\n\r\n") else { return };
        let xml = body[..header_end].to_lowercase().contains("xml");
        if !xml || body.contains("</auth>") || body.contains("</config-auth>") || body.chars().count() > 16384 {
            self.flush();
        }
    }

    /// One line per answered request, as soon as its form is known.
    fn flush(&mut self) {
        if self.logged {
            return;
        }
        let Some((wait, status, body)) = self.answer.clone() else { return };
        self.logged = true;
        let mut form = String::new();
        if let Some(id) = attribute("id", "auth", &body) {
            form += &format!(" auth={id}");
        }
        if let Some(message) = element("message", &body).or_else(|| element("error", &body)) {
            let short: String = message.chars().take(60).collect();
            form += &format!(" message=\"{short}\"");
        }
        let password = if self.password { " (password)" } else { "" };
        self.write(format!("pair {} login: {}{} answered after {}s: {}{}", self.pair, self.request, password, wait, status, form));
    }
}

// MARK: - Gateway address (§30.6)

/// The address for this session: the preferred one while the name still
/// has it, never `avoid` while another exists.
pub fn pick<'a>(addresses: &'a [String], prefer: Option<&str>, avoid: Option<&str>) -> Option<&'a String> {
    let usable: Vec<&String> = addresses.iter().filter(|a| Some(a.as_str()) != avoid).collect();
    let pool: Vec<&String> = if usable.is_empty() { addresses.iter().collect() } else { usable };
    if let Some(p) = prefer {
        if let Some(found) = pool.iter().find(|a| a.as_str() == p) {
            return Some(found);
        }
    }
    pool.first().copied()
}

// MARK: - The DTLS channel

/// The interface that owns `local` (the TLS leg's own address).
pub fn interface_of(local: Ipv4Addr) -> Option<String> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || unsafe { (*entry.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        let addr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        if Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)) == local {
            found = Some(unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned());
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_interface(s: &Socket, name: &str) -> io::Result<()> {
    let c = std::ffi::CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let index = std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(c.as_ptr()) })
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    s.bind_device_by_index_v4(Some(index))
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn bind_interface(s: &Socket, name: &str) -> io::Result<()> {
    if name.starts_with("lo") {
        return Ok(()); // tests: loopback needs no binding (and SO_BINDTODEVICE needs root)
    }
    s.bind_device(Some(name.as_bytes()))
}

#[derive(Default)]
struct Counters {
    up_packets: AtomicU64,
    up_bytes: AtomicU64,
    down_packets: AtomicU64,
    down_bytes: AtomicU64,
}

/// The DTLS half of a relayed session (§26.10): datagrams between
/// openconnect (a UDP socket on 127.0.0.1) and the gateway's DTLS port,
/// unchanged. DTLS is end to end between openconnect and the gateway;
/// nothing here can read it.
pub struct DatagramRelay {
    pub local_port: u16,
    counters: Arc<Counters>,
    wake: Option<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

impl DatagramRelay {
    pub fn open(gateway: SocketAddrV4, interface: &str, pair: u32, log: Option<Log>) -> io::Result<Self> {
        let local = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let local_port = local.local_addr()?.port();
        let upstream = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        bind_interface(&upstream, interface)?;
        upstream.connect(&SockAddr::from(gateway))?;
        let upstream: UdpSocket = upstream.into();
        local.set_nonblocking(true)?;
        upstream.set_nonblocking(true)?;
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let counters = Arc::new(Counters::default());
        let c = Arc::clone(&counters);
        let thread = std::thread::Builder::new()
            .name("ac-relay-udp".into())
            .stack_size(128 * 1024)
            .spawn(move || forward(local, upstream, read_end, c, pair, log))?;
        Ok(DatagramRelay { local_port, counters, wake: Some(write_end), thread: Some(thread) })
    }

    /// Stops forwarding; returns the counters for the pair's log line.
    pub fn close(&mut self) -> String {
        if let Some(wake) = self.wake.take() {
            unsafe { libc::write(wake.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let c = &self.counters;
        format!(
            "udp up {} pkts/{} B, down {} pkts/{} B",
            c.up_packets.load(Ordering::Relaxed),
            c.up_bytes.load(Ordering::Relaxed),
            c.down_packets.load(Ordering::Relaxed),
            c.down_bytes.load(Ordering::Relaxed)
        )
    }
}

impl Drop for DatagramRelay {
    fn drop(&mut self) {
        self.close();
    }
}

fn forward(local: UdpSocket, upstream: UdpSocket, stop: OwnedFd, c: Arc<Counters>, pair: u32, log: Option<Log>) {
    let mut buffer = vec![0u8; 65535];
    let mut client: Option<SocketAddr> = None;
    let mut reported = false;
    loop {
        let mut polled = [
            libc::pollfd { fd: local.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: upstream.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stop.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(polled.as_mut_ptr(), 3, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if polled[2].revents != 0 {
            return;
        }
        // Only the sockets poll found ready (§32.15: a wake-up used to try
        // both, one wasted system call per datagram).
        if polled[0].revents != 0 {
            // openconnect -> gateway. Loopback only: openconnect's socket
            // (its port may change when it restarts DTLS).
            while let Ok((n, from)) = local.recv_from(&mut buffer) {
                let SocketAddr::V4(v4) = from else { continue };
                if !v4.ip().is_loopback() {
                    continue;
                }
                client = Some(from);
                c.up_packets.fetch_add(1, Ordering::Relaxed);
                c.up_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let _ = upstream.send(&buffer[..n]);
            }
        }
        // gateway -> openconnect.
        if polled[1].revents != 0 {
            loop {
                match upstream.recv(&mut buffer) {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }
                        let Some(to) = client else { continue };
                        c.down_packets.fetch_add(1, Ordering::Relaxed);
                        c.down_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        let _ = local.send_to(&buffer[..n], to);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        // openconnect falls back to the TLS channel by
                        // itself; keep listening in case the path comes back.
                        if !reported {
                            reported = true;
                            if let Some(log) = &log {
                                log(&format!("pair {pair} udp channel receive: {e}"));
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

// MARK: - One relayed connection

/// The plaintext side of one relayed connection: plain pass-through
/// until the CSTP CONNECT is answered 200, whole CSTP packets after that.
pub struct Stream {
    pair: u32,
    gateway: Ipv4Addr,
    interface: Option<String>,
    log: Option<Log>,
    requests: HttpRequests,
    auth: AuthTrace,
    connect_requested: bool,
    response_header: Vec<u8>,
    cstp_since: Option<Instant>,
    client_frames: CstpFrames,
    server_frames: CstpFrames,
    datagrams: Option<DatagramRelay>,
    up: (u64, u64),
    down: (u64, u64),
    /// The last read's output, per direction (0 = from openconnect).
    pub out: [Chunks; 2],
}

impl Stream {
    pub fn new(pair: u32, gateway: Ipv4Addr, log: Option<Log>) -> Self {
        Stream {
            pair,
            gateway,
            interface: None,
            auth: AuthTrace::new(pair, log.clone()),
            log,
            requests: HttpRequests::default(),
            connect_requested: false,
            response_header: Vec::new(),
            cstp_since: None,
            client_frames: CstpFrames::default(),
            server_frames: CstpFrames::default(),
            datagrams: None,
            up: (0, 0),
            down: (0, 0),
            out: [Chunks::default(), Chunks::default()],
        }
    }

    fn write(&self, line: String) {
        if let Some(log) = &self.log {
            log(&line);
        }
    }

    /// The gateway connection's local address or interface, once it is
    /// ready: the DTLS channel goes out the same interface.
    pub fn set_path(&mut self, local: Option<&str>, interface: Option<&str>) {
        self.interface = local
            .and_then(|l| Ipv4Addr::from_str(l).ok())
            .and_then(interface_of)
            .or_else(|| interface.filter(|i| !i.is_empty()).map(str::to_string));
    }

    pub fn in_tunnel(&self) -> bool {
        self.cstp_since.is_some()
    }

    /// Processes one read; the chunks to send are in `out[from_client ? 0 : 1]`.
    pub fn feed(&mut self, data: &[u8], from_client: bool) -> Result<usize, FramingError> {
        let side = if from_client { 0 } else { 1 };
        let mut out = std::mem::take(&mut self.out[side]);
        out.clear();
        let result = self.frame(data, from_client, &mut out);
        if result.is_ok() && self.in_tunnel() {
            let counter = if from_client { &mut self.up } else { &mut self.down };
            counter.0 += out.len() as u64;
            counter.1 += out.bytes() as u64;
        }
        let count = out.len();
        self.out[side] = out;
        result.map(|_| count)
    }

    fn frame(&mut self, data: &[u8], from_client: bool, out: &mut Chunks) -> Result<(), FramingError> {
        if self.in_tunnel() {
            return if from_client { self.client_frames.feed(data, out) } else { self.server_frames.feed(data, out) };
        }
        self.auth.observe(data, from_client);
        if from_client {
            let connect = self.requests.pass(data, out)?;
            self.connect_requested = connect || self.connect_requested;
            return Ok(());
        }
        if !self.connect_requested {
            out.push(data);
            return Ok(());
        }
        self.response_header.extend_from_slice(data);
        if self.response_header.len() > HEADER_LIMIT {
            return Err(FramingError::Oversized);
        }
        let Some(boundary) = find(&self.response_header, b"\r\n\r\n").map(|i| i + 4) else { return Ok(()) };
        let whole = std::mem::take(&mut self.response_header);
        let mut header = whole[..boundary].to_vec();
        let status_line = String::from_utf8_lossy(&header).split("\r\n").next().unwrap_or("").to_string();
        let ok = status_line.split(' ').filter(|s| !s.is_empty()).nth(1) == Some("200");
        if ok {
            self.cstp_since = Some(Instant::now());
            header = self.open_datagrams(&header);
        }
        self.connect_requested = false;
        out.push(&header);
        let tail = &whole[boundary..];
        if ok {
            self.server_frames.feed(tail, out)
        } else {
            if !tail.is_empty() {
                out.push(tail);
            }
            Ok(())
        }
    }

    /// The gateway offered DTLS: point openconnect at a local UDP port
    /// that forwards to the gateway's (before openconnect reads the
    /// answer, so the port is bound when its first datagram comes). No
    /// offer, no known interface or no socket: the header goes as it is
    /// and openconnect stays on the TLS channel.
    fn open_datagrams(&mut self, header: &[u8]) -> Vec<u8> {
        let mut opened: Option<(DatagramRelay, u16)> = None;
        let mut failure: Option<String> = None;
        let (gateway, pair, interface, log) = (self.gateway, self.pair, self.interface.clone(), self.log.clone());
        let rewritten = edit_header(header, |name, value| {
            if name != "x-dtls-port" || opened.is_some() {
                return None;
            }
            let port: u16 = value.parse().ok().filter(|p| *p > 0)?;
            let Some(interface) = interface.as_deref() else {
                failure = Some("no udp channel (gateway connection's interface unknown)".into());
                return None;
            };
            match DatagramRelay::open(SocketAddrV4::new(gateway, port), interface, pair, log.clone()) {
                Ok(relay) => {
                    let local = relay.local_port;
                    opened = Some((relay, port));
                    Some(local.to_string())
                }
                Err(e) => {
                    failure = Some(format!("no udp channel ({e})"));
                    None
                }
            }
        });
        let Some((relay, port)) = opened else {
            let why = failure.unwrap_or_else(|| "no udp channel (gateway offered no DTLS port)".into());
            self.write(format!("pair {} {}", self.pair, why));
            return header.to_vec();
        };
        let interface = self.interface.clone().unwrap_or_default();
        self.write(format!("pair {} udp channel to gateway ready ({})", self.pair, interface));
        self.write(format!("pair {} udp channel: local port {} -> gateway port {}", self.pair, relay.local_port, port));
        self.datagrams = Some(relay);
        rewritten
    }

    /// Stops the DTLS channel; the counters for the pair's log line.
    pub fn close(&mut self) -> String {
        let tunnel = match self.cstp_since {
            Some(since) => format!("tunnel {}s, ", since.elapsed().as_secs()),
            None => "no tunnel, ".to_string(),
        };
        let udp = self.datagrams.as_mut().map(|d| format!(", {}", d.close())).unwrap_or_default();
        format!("{}up {} pkts/{} B, down {} pkts/{} B{}", tunnel, self.up.0, self.up.1, self.down.0, self.down.1, udp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn packet(body: usize, byte: u8) -> Vec<u8> {
        let mut p = vec![0x53, 0x54, 0x46, 0x01, (body >> 8) as u8, (body & 0xff) as u8, 0, 0];
        p.extend(std::iter::repeat(byte).take(body));
        p
    }

    fn feed_all(frames: &mut CstpFrames, data: &[u8]) -> Result<Vec<Vec<u8>>, FramingError> {
        let mut out = Chunks::default();
        frames.feed(data, &mut out)?;
        Ok(out.to_vecs())
    }

    #[test]
    fn cstp_packets() {
        let frames = vec![packet(40, 0x61), packet(1300, 0x62), packet(600, 0x63)];
        let all: Vec<u8> = frames.concat();
        let mut split = CstpFrames::default();
        let mut got = Vec::new();
        for cut in all.chunks(7) {
            got.extend(feed_all(&mut split, cut).unwrap());
        }
        assert_eq!(got, frames, "split input comes out as whole packets");
        assert_eq!(feed_all(&mut CstpFrames::default(), &all).unwrap(), frames, "merged input separates");
        assert_eq!(feed_all(&mut CstpFrames::default(), b"HTTP/1.1 200 OK\r\n\r\n"), Err(FramingError::Invalid));
    }

    #[test]
    fn requests_and_connect() {
        let mut r = HttpRequests::default();
        let body = "<password>secret</password>";
        let post = format!("POST /auth HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        let mut out = Chunks::default();
        assert!(!r.pass(post.as_bytes(), &mut out).unwrap());
        assert_eq!(out.to_vecs().concat(), post.as_bytes(), "a POST and its body pass unchanged");
        let mut out = Chunks::default();
        assert!(!r.pass(b"CON", &mut out).unwrap());
        assert!(out.is_empty(), "a CONNECT header is held until complete");
        let tail = "NECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: x\r\nX-DTLS-Master-Secret: 00ff\r\n\
                    X-DTLS-CipherSuite: PSK-NEGOTIATE:OC-DTLS1_2-AES256-GCM:AES128-SHA\r\n\
                    X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n\r\n";
        let mut out = Chunks::default();
        assert!(r.pass(tail.as_bytes(), &mut out).unwrap(), "a fragmented CONNECT is recognised");
        let sent = String::from_utf8(out.to_vecs().concat()).unwrap();
        assert!(sent.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"));
        assert!(sent.contains("X-DTLS-CipherSuite: OC-DTLS1_2-AES256-GCM:AES128-SHA\r\n"));
        assert!(sent.contains("X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n"));
        assert!(sent.contains("X-DTLS-Master-Secret: 00ff\r\n"));
        assert!(!sent.contains("PSK-NEGOTIATE") && sent.ends_with("\r\n\r\n"));
        let mut out = Chunks::default();
        assert_eq!(HttpRequests::default().pass(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &mut out), Err(FramingError::Invalid));
    }

    #[test]
    fn header_edit_keeps_other_bytes() {
        let mut banner = b"HTTP/1.1 200 OK\r\nX-CSTP-Banner: ".to_vec();
        banner.extend_from_slice(&[0xE9, 0xFF]);
        banner.extend_from_slice(b"\r\nx-dtls-port: 443\r\n\r\n");
        let edited = edit_header(&banner, |n, v| (n == "x-dtls-port" && v == "443").then(|| "5000".to_string()));
        let mut want = b"HTTP/1.1 200 OK\r\nX-CSTP-Banner: ".to_vec();
        want.extend_from_slice(&[0xE9, 0xFF]);
        want.extend_from_slice(b"\r\nx-dtls-port: 5000\r\n\r\n");
        assert_eq!(edited, want);
    }

    #[test]
    fn login_trace() {
        let form = "HTTP/1.1 200 OK\r\n\r\n<config-auth><auth id=\"main\"><message>Login failed.</message>\
                    <input type=\"password\" name=\"password\"/></auth></config-auth>";
        assert_eq!(attribute("id", "auth", form).as_deref(), Some("main"));
        assert_eq!(element("message", form).as_deref(), Some("Login failed."));
        assert_eq!(element("error", form), None);
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = Arc::clone(&lines);
        let mut t = AuthTrace::new(3, Some(Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()))));
        t.observe(b"POST /auth HTTP/1.1\r\nContent-Length: 27\r\n\r\n<password>secret</password>", true);
        t.observe(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<config-auth><auth id=\"success\">", false);
        t.observe(b"</auth></config-auth>", false);
        let lines = lines.lock().unwrap();
        assert_eq!(lines[0], "pair 3 login: POST with the password sent, waiting for the gateway");
        assert!(lines[1].starts_with("pair 3 login: POST (password) answered after 0.0s: 200 auth=success"), "{}", lines[1]);
        assert!(!lines.iter().any(|l| l.contains("secret")));
    }

    #[test]
    fn gateway_pick() {
        let two = vec!["198.51.100.7".to_string(), "198.51.100.9".to_string()];
        assert_eq!(pick(&two, Some("198.51.100.9"), None).map(String::as_str), Some("198.51.100.9"));
        assert_eq!(pick(&two, Some("198.51.100.7"), Some("198.51.100.7")).map(String::as_str), Some("198.51.100.9"));
        let one = vec!["198.51.100.7".to_string()];
        assert_eq!(pick(&one, None, Some("198.51.100.7")).map(String::as_str), Some("198.51.100.7"));
        assert_eq!(pick(&two, Some("203.0.113.1"), None).map(String::as_str), Some("198.51.100.7"));
        assert_eq!(pick(&[], Some("198.51.100.7"), None), None);
    }

    #[test]
    fn stream_connect_opens_dtls_and_forwards_datagrams() {
        // The "gateway's" DTLS port on loopback.
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let gport = gateway.local_addr().unwrap().port();
        let mut s = Stream::new(1, Ipv4Addr::LOCALHOST, None);
        s.set_path(Some("127.0.0.1"), None);
        assert_eq!(s.feed(b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-DTLS-CipherSuite: PSK-NEGOTIATE:AES128-SHA\r\n\r\n", true), Ok(1));
        let answer = format!("HTTP/1.1 200 OK\r\nX-DTLS-Port: {gport}\r\n\r\n");
        let mut data = answer.into_bytes();
        data.extend(packet(10, 0x41));
        assert_eq!(s.feed(&data, false), Ok(2), "header, then the first packet on its own");
        let header = String::from_utf8(s.out[1].get(0).to_vec()).unwrap();
        let local: u16 = header.split("X-DTLS-Port: ").nth(1).unwrap().trim().parse().unwrap();
        assert_ne!(local, gport, "openconnect is pointed at the relay's port");
        assert!(s.in_tunnel());

        let oc = UdpSocket::bind("127.0.0.1:0").unwrap();
        oc.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        gateway.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        oc.send_to(b"hello gateway", ("127.0.0.1", local)).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = gateway.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello gateway");
        gateway.send_to(b"hello openconnect", from).unwrap();
        let n = oc.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello openconnect");

        let summary = s.close();
        assert!(summary.contains("udp up 1 pkts/13 B, down 1 pkts/17 B"), "{summary}");
    }
}
