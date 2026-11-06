import AppKit
import Darwin
import SystemConfiguration

/// Other VPNs and proxies on this Mac (DESIGN.md §27.2): Clash, sing-box
/// and the like. Two VPNs that each take over all traffic (TUN mode)
/// fight over the default route and DNS, as Cisco would with them too;
/// a proxy in system-proxy mode coexists. Nothing here blocks or changes
/// anything: it only says what it sees, so the user knows why the
/// network misbehaves and what to switch off.
struct NeighborNotice: Equatable {
    enum Level { case info, warning }
    let level: Level
    let text: String
}

enum NetworkNeighbors {
    /// What the checks saw; filled by `observe()`, pure input to `notices`.
    struct Observation {
        var defaultInterface: String?
        /// Our own session is up (its tunnel may be the default route).
        var oursActive: Bool
        /// Cisco Secure Client holds the tunnel (expected in Cisco mode).
        var ciscoTunnel: Bool
        var apps: [String]
        var systemProxy: String?
        var port53Busy: Bool
        var splitOn: Bool
    }

    /// Known VPN / proxy clients, by bundle identifier prefix or name.
    static let knownApps: [(match: String, name: String)] = [
        ("com.west2online.ClashX", "ClashX"), ("com.metacubex.ClashX", "ClashX Meta"),
        ("io.github.clash-verge-rev", "Clash Verge"), ("com.clash-verge", "Clash Verge"),
        ("party.mihomo", "Mihomo Party"), ("com.follow.clash", "FlClash"),
        ("io.nekohasekai.sfavt", "sing-box"), ("io.nekohasekai.sfa", "sing-box"),
        ("com.nssurge.surge-mac", "Surge"), ("com.stash.stash-mac", "Stash"),
        ("com.v2rayu", "V2rayU"), ("com.yanue.V2rayU", "V2rayU"),
        ("com.crossutility.quantumult-x", "Quantumult X"), ("com.shadowrocket", "Shadowrocket"),
        ("net.tunnelblick", "Tunnelblick"), ("com.wireguard.macos", "WireGuard"),
    ]
    /// Command-line cores that run without an app.
    static let knownDaemons = ["clash", "mihomo", "sing-box", "xray", "v2ray", "hysteria", "tun2socks"]

    static func notices(_ o: Observation) -> [NeighborNotice] {
        var out: [NeighborNotice] = []
        let names = o.apps.joined(separator: "、")
        if let tun = o.defaultInterface, tun.hasPrefix("utun"), !o.oursActive, !o.ciscoTunnel {
            let who = names.isEmpty ? "另一个 VPN" : names
            out.append(NeighborNotice(level: .warning,
                text: "\(who) 正在接管全部流量（\(tun)），和 VPN 会互相抢网络。连接前请先关掉它的 TUN/增强模式。"))
        } else if !names.isEmpty {
            out.append(NeighborNotice(level: .info,
                text: "检测到 \(names) 在运行：只开系统代理可以共存；TUN/增强模式会和 VPN 抢网络，请关掉。"))
        }
        if o.port53Busy, o.splitOn, !o.oursActive {
            out.append(NeighborNotice(level: .warning,
                text: "本机 53 端口被其他程序占用（常见于 Clash 的 DNS）：连上后按网站分流会暂停，其余照常走 VPN。"))
        }
        if let proxy = o.systemProxy, names.isEmpty {
            out.append(NeighborNotice(level: .info, text: "系统代理已开（\(proxy)），一般可以和 VPN 共存。"))
        }
        return out
    }

    /// Reads the Mac's current state. Cheap enough for each panel open.
    static func observe(oursActive: Bool, ciscoTunnel: Bool, splitOn: Bool) -> Observation {
        Observation(defaultInterface: defaultInterface(), oursActive: oursActive, ciscoTunnel: ciscoTunnel,
                    apps: runningClients(), systemProxy: systemProxy(),
                    port53Busy: oursActive ? false : port53Busy(), splitOn: splitOn)
    }

    private static func runningClients() -> [String] {
        var names: [String] = []
        for app in NSWorkspace.shared.runningApplications {
            let id = app.bundleIdentifier ?? ""
            if let hit = knownApps.first(where: { id.hasPrefix($0.match) }), !names.contains(hit.name) {
                names.append(hit.name)
            }
        }
        for daemon in knownDaemons where processRunning(daemon) {
            if !names.contains(daemon) { names.append(daemon) }
        }
        return names
    }

    private static func processRunning(_ name: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        p.arguments = ["-x", name]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    private static func defaultInterface() -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/route")
        p.arguments = ["-n", "get", "default"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("interface:") {
                return t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    private static func systemProxy() -> String? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return nil }
        for (enable, host, port, label) in [
            (kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPProxy, kSCPropNetProxiesHTTPPort, "HTTP"),
            (kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesHTTPSProxy, kSCPropNetProxiesHTTPSPort, "HTTPS"),
            (kSCPropNetProxiesSOCKSEnable, kSCPropNetProxiesSOCKSProxy, kSCPropNetProxiesSOCKSPort, "SOCKS"),
        ] where (proxies[enable as String] as? Int) == 1 {
            let h = proxies[host as String] as? String ?? "?"
            let p = proxies[port as String] as? Int
            return "\(label) \(h)" + (p.map { ":\($0)" } ?? "")
        }
        return nil
    }

    /// Whether something already answers DNS on 127.0.0.1:53 (our
    /// forwarder's address) while our session is down: a single query
    /// with a short wait. (A test bind cannot tell: a normal user may
    /// not bind port 53 at all, EACCES.)
    private static func port53Busy() -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: 0, tv_usec: 500_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(53).bigEndian
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return false }
        // "localhost. IN A", id 0x4143.
        let query: [UInt8] = [0x41, 0x43, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              9] + Array("localhost".utf8) + [0, 0x00, 0x01, 0x00, 0x01]
        guard send(fd, query, query.count, 0) == query.count else { return false }
        var buffer = [UInt8](repeating: 0, count: 512)
        return recv(fd, &buffer, buffer.count, 0) > 0
    }
}
