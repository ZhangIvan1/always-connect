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
        guard let pipe = PrivatePipe() else { return nil }
        p.standardOutput = pipe.fileHandleForWriting
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        try? pipe.fileHandleForWriting.close()
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
        ac_loopback_dns_busy(53, 500)
    }
}

@_silgen_name("ac_loopback_dns_busy")
private func ac_loopback_dns_busy(_ port: UInt16, _ timeoutMilliseconds: UInt32) -> Bool
