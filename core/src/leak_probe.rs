//! Active leak probes for the self-check (§63). The background service runs
//! them in a short-lived child with an ordinary identity (nobody), so PF's
//! root-only DNS exception cannot make a leak look blocked. Each probe sends
//! at most one small packet or TCP handshake to a fixed public address and
//! succeeds only if something answers; nothing is changed on the system.
use crate::network_check::Item;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Public anycast resolvers: a well-known DNS service and HTTPS endpoint.
pub const EXTERNAL_V4: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
pub const EXTERNAL_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const NAME: &str = "example.com";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub physical: String,
    pub local_dns: Vec<String>,
    /// Test seams; production uses the public constants and ports 53/443.
    #[serde(default)] pub external_v4: Vec<String>,
    #[serde(default)] pub external_v6: Option<String>,
    #[serde(default)] pub dns_port: Option<u16>,
    #[serde(default)] pub tcp_port: Option<u16>,
    pub timeout_ms: u64,
}

/// Answered = a matching DNS reply or a completed TCP handshake came back.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome { Answered, NoAnswer }

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub uid: u32,
    /// An ordinary connection through the normal route works.
    pub control: bool,
    pub external_dns: Vec<Outcome>,
    pub local_dns: Vec<Outcome>,
    pub physical_tcp: Vec<Outcome>,
    pub ipv6_global: bool,
    pub ipv6: Vec<Outcome>,
}

fn interface_index(name: &str) -> Option<std::num::NonZeroU32> {
    let c = std::ffi::CString::new(name).ok()?;
    std::num::NonZeroU32::new(unsafe { libc::if_nametoindex(c.as_ptr()) })
}

fn socket_for(address: &SocketAddr, kind: Type, bound: Option<std::num::NonZeroU32>) -> Option<Socket> {
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let protocol = if kind == Type::DGRAM { Protocol::UDP } else { Protocol::TCP };
    let socket = crate::child_io::socket(domain, kind, Some(protocol)).ok()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let _ = socket.set_nosigpipe(true);
        if let Some(index) = bound {
            if address.is_ipv4() { socket.bind_device_by_index_v4(Some(index)).ok()?; }
            else { socket.bind_device_by_index_v6(Some(index)).ok()?; }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    { let _ = bound; }
    Some(socket)
}

fn query(id: u16) -> Vec<u8> {
    let mut q = crate::on_demand::dns_query(NAME).unwrap_or_default();
    if q.len() >= 2 { q[..2].copy_from_slice(&id.to_be_bytes()); }
    q
}

fn replied(answer: &[u8], id: u16) -> bool { answer.len() >= 12 && answer[..2] == id.to_be_bytes() && answer[2] & 0x80 != 0 }

fn dns_udp(address: SocketAddr, bound: Option<std::num::NonZeroU32>, timeout: Duration, id: u16) -> Outcome {
    let attempt = || -> Option<()> {
        let socket = socket_for(&address, Type::DGRAM, bound)?;
        socket.connect(&SockAddr::from(address)).ok()?;
        socket.set_read_timeout(Some(timeout)).ok()?;
        socket.send(&query(id)).ok()?;
        let deadline = Instant::now() + timeout;
        let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
        while Instant::now() < deadline {
            let n = socket.recv(&mut buffer).ok()?;
            // socket2 guarantees recv initialised the first n bytes.
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
            if replied(bytes, id) { return Some(()); }
        }
        None
    };
    if attempt().is_some() { Outcome::Answered } else { Outcome::NoAnswer }
}

fn dns_tcp(address: SocketAddr, bound: Option<std::num::NonZeroU32>, timeout: Duration, id: u16) -> Outcome {
    let attempt = || -> Option<()> {
        // One budget for connect, write and read together.
        let deadline = Instant::now() + timeout;
        let left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
        let socket = socket_for(&address, Type::STREAM, bound)?;
        socket.connect_timeout(&SockAddr::from(address), left()?).ok()?;
        let mut stream: std::net::TcpStream = socket.into();
        stream.set_read_timeout(Some(left()?)).ok()?;
        stream.set_write_timeout(Some(left()?)).ok()?;
        let q = query(id);
        let mut frame = (q.len() as u16).to_be_bytes().to_vec(); frame.extend(q);
        stream.write_all(&frame).ok()?;
        let mut head = [0u8; 2]; stream.read_exact(&mut head).ok()?;
        let mut body = vec![0u8; u16::from_be_bytes(head) as usize]; stream.read_exact(&mut body).ok()?;
        replied(&body, id).then_some(())
    };
    if attempt().is_some() { Outcome::Answered } else { Outcome::NoAnswer }
}

fn tcp_open(address: SocketAddr, bound: Option<std::num::NonZeroU32>, timeout: Duration) -> Outcome {
    match socket_for(&address, Type::STREAM, bound).map(|s| s.connect_timeout(&SockAddr::from(address), timeout)) {
        Some(Ok(())) => Outcome::Answered,
        _ => Outcome::NoAnswer,
    }
}

/// A global unicast IPv6 address (2000::/3) on the physical interface.
pub fn has_global_ipv6(interface: &str) -> bool {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 { return false; }
    let mut found = false; let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name == interface && !entry.ifa_addr.is_null() && i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_INET6 {
            let raw = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
            found |= raw.sin6_addr.s6_addr[0] & 0xe0 == 0x20;
        }
        cursor = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

/// Runs every probe in parallel; the whole report is bounded by one timeout.
pub fn probe(plan: &Plan) -> Report {
    let timeout = Duration::from_millis(plan.timeout_ms.clamp(100, 2000));
    let physical = interface_index(&plan.physical);
    let dns_port = plan.dns_port.unwrap_or(53);
    let tcp_port = plan.tcp_port.unwrap_or(443);
    let mut v4: Vec<IpAddr> = plan.external_v4.iter().filter_map(|s| s.parse().ok()).collect();
    if v4.is_empty() { v4 = EXTERNAL_V4.iter().map(|ip| IpAddr::V4(*ip)).collect(); }
    let v6: IpAddr = plan.external_v6.as_deref().and_then(|s| s.parse().ok()).unwrap_or(IpAddr::V6(EXTERNAL_V6));
    let local: Vec<IpAddr> = plan.local_dns.iter().filter_map(|s| s.parse().ok()).collect();
    let ipv6_global = plan.external_v6.is_some() || has_global_ipv6(&plan.physical);
    // Every probe in its own thread: the report takes one timeout, not a sum.
    type Job<'a> = Box<dyn FnOnce() -> Outcome + Send + 'a>;
    let first = v4[0];
    let external_target = SocketAddr::new(first, dns_port);
    let mut external: Vec<Job> = vec![
        Box::new(move || dns_udp(external_target, None, timeout, 0x4143)),
        Box::new(move || dns_tcp(external_target, None, timeout, 0x4144)),
    ];
    let mut local_jobs: Vec<Job> = Vec::new();
    let mut direct: Vec<Job> = Vec::new();
    if physical.is_some() {
        // Bound to the physical card: the shape of a leak around the tunnel.
        external.push(Box::new(move || dns_udp(external_target, physical, timeout, 0x4145)));
        for (n, ip) in local.iter().take(2).enumerate() {
            let target = SocketAddr::new(*ip, dns_port);
            local_jobs.push(Box::new(move || dns_udp(target, physical, timeout, 0x4150 + n as u16)));
            local_jobs.push(Box::new(move || dns_tcp(target, physical, timeout, 0x4160 + n as u16)));
        }
        direct.push(Box::new(move || tcp_open(SocketAddr::new(first, tcp_port), physical, timeout)));
    }
    let mut v6_jobs: Vec<Job> = Vec::new();
    if ipv6_global {
        v6_jobs.push(Box::new(move || tcp_open(SocketAddr::new(v6, tcp_port), None, timeout)));
        v6_jobs.push(Box::new(move || dns_udp(SocketAddr::new(v6, dns_port), None, timeout, 0x4170)));
    }
    let control_targets: Vec<SocketAddr> = v4.iter().map(|ip| SocketAddr::new(*ip, tcp_port)).collect();
    std::thread::scope(|scope| {
        let run = |jobs: Vec<Job<'static>>| jobs.into_iter().map(|job| scope.spawn(job)).collect::<Vec<_>>();
        let control = control_targets.iter().map(|t| { let t = *t; scope.spawn(move || tcp_open(t, None, timeout)) }).collect::<Vec<_>>();
        let (external, local_jobs, direct, v6_jobs) = (run(external), run(local_jobs), run(direct), run(v6_jobs));
        let collect = |handles: Vec<std::thread::ScopedJoinHandle<'_, Outcome>>| handles.into_iter().map(|h| h.join().unwrap_or(Outcome::NoAnswer)).collect::<Vec<_>>();
        Report {
            uid: unsafe { libc::geteuid() },
            control: collect(control).contains(&Outcome::Answered),
            external_dns: collect(external),
            local_dns: collect(local_jobs),
            physical_tcp: collect(direct),
            ipv6_global,
            ipv6: collect(v6_jobs),
        }
    })
}

fn row(name: &str, passed: bool, informational: bool, detail: &str) -> Item {
    Item { item: name.into(), passed, informational, detail: detail.into() }
}
fn leaked(outcomes: &[Outcome]) -> bool { outcomes.contains(&Outcome::Answered) }
fn verdict(out: &mut Vec<Item>, reference: bool, protection: bool, name: &str, passed: bool, ok: &str, bad: &str) {
    let text = if passed { ok } else { bad };
    let detail = if protection { text.to_string() } else { format!("断线保护已关闭，只作参考：{text}") };
    out.push(Item { item: name.into(), passed, informational: reference, detail });
}

/// Verdicts. Without drop protection, or when even the ordinary path cannot
/// reach the Internet, the results are shown for reference only.
pub fn items(report: Option<&Report>, protection: bool) -> Vec<Item> {
    let Some(r) = report else {
        return vec![row("主动探测", false, true, "未能运行主动探测（后台服务版本或权限问题），以上配置核对仍有效")];
    };
    let mut out = Vec::new();
    let reference = !protection || !r.control || r.uid == 0;
    out.push(row("主动探测：普通程序经 VPN 上网", r.control, true,
        if r.uid == 0 { "探测未能以普通身份运行，结果只作参考" }
        else if r.control { "以普通程序身份经正常路径连外网成功，下列\"被拦下\"不是因为断网" }
        else { "普通程序经正常路径连不上外网，下列结果只作参考" }));
    verdict(&mut out, reference, protection, "主动探测：DNS 不能绕过本机转发器", !leaked(&r.external_dns),
        "普通程序直接问外部 DNS（UDP/TCP，经 VPN 或物理网卡）都没有得到回应",
        "普通程序直接问外部 DNS 得到了回应：DNS 可能绕过 VPN 泄漏");
    verdict(&mut out, reference, protection, "主动探测：物理网卡不能直连外网", !leaked(&r.physical_tcp),
        "普通程序绑定物理网卡连外网被拦下",
        "普通程序绑定物理网卡能连上外网：断线保护没有拦住");
    if !r.ipv6_global {
        out.push(row("主动探测：IPv6 外网", true, true, "当前网络没有公网 IPv6，无需拦截"));
    } else {
        verdict(&mut out, reference, protection, "主动探测：IPv6 外网被拦", !leaked(&r.ipv6),
            "当前网络有公网 IPv6；普通程序连 IPv6 外网（TCP/DNS）都被拦下",
            "普通程序能经 IPv6 连外网：IPv6 可能绕过 VPN 泄漏");
    }
    if r.local_dns.is_empty() {
        out.push(row("主动探测：本地 DNS", true, true, "没有取得本地 DNS 地址，未探测"));
    } else if leaked(&r.local_dns) {
        // PF only lets root reach the local DNS; an ordinary program getting
        // an answer means another component re-sent it as root (§61.1).
        out.push(row("主动探测：本地 DNS", false, true,
            "普通程序手工指定本地 DNS 能得到回应：本项目只放行管理员身份，通常是其他网络组件以管理员身份代发；正常上网的查询仍经本机转发器走 VPN"));
    } else {
        verdict(&mut out, reference, protection, "主动探测：本地 DNS", true, "普通程序手工指定本地 DNS 被拦下", "");
    }
    out
}

/// Production entry: the background service (root) runs its own verified
/// binary as `nobody` with a cleared environment and reads one JSON report.
pub fn run_child(plan: &Plan, deadline: Duration) -> Option<Report> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().ok()?;
    let meta = std::fs::metadata(&exe).ok()?;
    // Only a root-owned, not group/world-writable binary of ours is run.
    if unsafe { libc::geteuid() } != 0 || meta.uid() != 0 || meta.mode() & 0o022 != 0 { return None; }
    let nobody = unsafe { libc::getpwnam(c"nobody".as_ptr()) };
    if nobody.is_null() { return None; }
    let (uid, gid) = unsafe { ((*nobody).pw_uid, (*nobody).pw_gid) };
    let mut command = std::process::Command::new(&exe);
    command.arg("leak-probe").arg(serde_json::to_string(plan).ok()?).env_clear().current_dir("/")
        .uid(uid).gid(gid).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    crate::reset_child_signals(&mut command);
    let mut child = crate::child_io::spawn(&mut command).ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || { let mut text = String::new(); let _ = (&mut stdout).take(64 * 1024).read_to_string(&mut text); text });
    let stop = Instant::now() + deadline;
    let ok = loop {
        if let Ok(Some(status)) = child.try_wait() { break status.success(); }
        if Instant::now() >= stop { let _ = child.kill(); let _ = child.wait(); break false; }
        std::thread::sleep(Duration::from_millis(10));
    };
    let text = reader.join().ok()?;
    if !ok { return None; }
    serde_json::from_str(text.trim()).ok()
}

/// Child entry (`AlwaysConnectHelper leak-probe <plan>`): refuses to run as root.
pub fn child_main(plan_json: &str) -> Option<String> {
    if unsafe { libc::geteuid() } == 0 { return None; }
    let plan: Plan = serde_json::from_str(plan_json).ok()?;
    serde_json::to_string(&probe(&plan)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    fn answering_dns() -> (u16, std::thread::JoinHandle<()>) {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let tcp = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let handle = std::thread::spawn(move || {
            udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = udp.recv_from(&mut buf) { let mut a = buf[..n].to_vec(); a[2] |= 0x80; let _ = udp.send_to(&a, from); }
            tcp.set_nonblocking(false).unwrap();
            if let Ok((mut s, _)) = tcp.accept() {
                let mut head = [0u8; 2]; if s.read_exact(&mut head).is_ok() {
                    let mut body = vec![0u8; u16::from_be_bytes(head) as usize];
                    if s.read_exact(&mut body).is_ok() { body[2] |= 0x80; let _ = s.write_all(&head); let _ = s.write_all(&body); }
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn answered_and_silent_targets_are_told_apart() {
        let (port, handle) = answering_dns();
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(dns_udp(target, None, Duration::from_millis(500), 7), Outcome::Answered);
        assert_eq!(dns_tcp(target, None, Duration::from_millis(500), 8), Outcome::Answered);
        handle.join().unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let quiet: SocketAddr = silent.local_addr().unwrap();
        assert_eq!(dns_udp(quiet, None, Duration::from_millis(150), 9), Outcome::NoAnswer);
        assert_eq!(dns_tcp(quiet, None, Duration::from_millis(150), 10), Outcome::NoAnswer, "nothing listens on TCP");
        let open = TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(tcp_open(open.local_addr().unwrap(), None, Duration::from_millis(300)), Outcome::Answered);
    }

    #[test]
    fn a_reply_with_another_id_is_not_an_answer() {
        assert!(replied(&[0, 7, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0], 7));
        assert!(!replied(&[0, 8, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0], 7));
        assert!(!replied(&[0, 7, 0x00, 0, 0, 1, 0, 0, 0, 0, 0, 0], 7), "a query echoed back is not a reply");
    }

    fn report() -> Report {
        Report { uid: 501, control: true, external_dns: vec![Outcome::NoAnswer; 3], local_dns: vec![Outcome::NoAnswer; 2],
            physical_tcp: vec![Outcome::NoAnswer], ipv6_global: true, ipv6: vec![Outcome::NoAnswer; 2] }
    }
    fn find<'a>(rows: &'a [Item], name: &str) -> &'a Item { rows.iter().find(|r| r.item.contains(name)).unwrap() }

    #[test]
    fn verdicts_fail_on_any_leak_and_stay_honest_about_limits() {
        let clean = items(Some(&report()), true);
        assert!(clean.iter().filter(|r| !r.informational).all(|r| r.passed));
        for (field, name) in [("dns", "DNS 不能绕过"), ("tcp", "物理网卡不能直连"), ("v6", "IPv6 外网被拦")] {
            let mut r = report();
            match field { "dns" => r.external_dns[2] = Outcome::Answered, "tcp" => r.physical_tcp[0] = Outcome::Answered, _ => r.ipv6[0] = Outcome::Answered }
            let rows = items(Some(&r), true);
            let row = find(&rows, name);
            assert!(!row.passed && !row.informational, "{name} must be a visible failure");
        }
        let mut r = report(); r.local_dns[1] = Outcome::Answered;
        let row = items(Some(&r), true).into_iter().find(|r| r.item.contains("本地 DNS")).unwrap();
        assert!(!row.passed && row.informational && row.detail.contains("代发"), "known third-party re-send is shown, not hidden");
        let mut r = report(); r.ipv6_global = false; r.ipv6.clear();
        let row = items(Some(&r), true).into_iter().find(|r| r.item.contains("IPv6")).unwrap();
        assert!(row.passed && row.informational && row.detail.contains("没有公网 IPv6"));
    }

    #[test]
    fn without_protection_or_reachability_results_are_reference_only() {
        let mut leaking = report(); leaking.external_dns[0] = Outcome::Answered;
        assert!(items(Some(&leaking), false).iter().all(|r| r.informational), "protection off: never a red verdict");
        let mut offline = report(); offline.control = false;
        assert!(items(Some(&offline), true).iter().all(|r| r.informational), "offline: blocked results prove nothing");
        let mut root = report(); root.uid = 0;
        assert!(items(Some(&root), true).iter().all(|r| r.informational), "root bypasses the DNS barrier: reference only");
        let missing = items(None, true);
        assert_eq!(missing.len(), 1); assert!(missing[0].informational && !missing[0].passed);
    }

    #[test]
    fn probe_reports_loopback_targets_and_child_refuses_root_plans() {
        let (port, handle) = answering_dns();
        let open = TcpListener::bind("127.0.0.1:0").unwrap();
        let plan = Plan { physical: "ac-missing".into(), local_dns: vec![], external_v4: vec!["127.0.0.1".into()],
            external_v6: None, dns_port: Some(port), tcp_port: Some(open.local_addr().unwrap().port()), timeout_ms: 500 };
        let r = probe(&plan);
        handle.join().unwrap();
        assert!(r.control);
        assert_eq!(r.external_dns, vec![Outcome::Answered, Outcome::Answered], "unbound UDP and TCP only, no physical card");
        assert!(r.physical_tcp.is_empty() && r.local_dns.is_empty());
        assert!(child_main("not json").is_none());
    }
}
