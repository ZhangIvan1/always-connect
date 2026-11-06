import Foundation

/// Root-side system checks for the Diagnostics page (UI-DESIGN.md
/// §五诊断页). All of these need the Helper's privilege (pfctl,
/// route) or its engine state (tunnel interface), so they live here,
/// not in the App.
enum SystemChecks {
    /// Bytes in/out on the named interface via getifaddrs, or (0, 0)
    /// when the interface is absent.
    static func interfaceBytes(_ name: String) -> (Int64, Int64) {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let start = head else { return (0, 0) }
        defer { freeifaddrs(start) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = start
        while let current = cursor {
            let ifa = current.pointee
            if let cName = ifa.ifa_name, String(cString: cName) == name,
               let data = ifa.ifa_data {
                let stats = data.assumingMemoryBound(to: if_data.self).pointee
                return (Int64(stats.ifi_ibytes), Int64(stats.ifi_obytes))
            }
            cursor = ifa.ifa_next
        }
        return (0, 0)
    }

    /// The leak self-check. tunnelIf/gatewayIps/physicalIf come from
    /// the engine's last pf inputs; a nil tunnelIf means "not
    /// connected" and every item reports that instead of a verdict.
    /// tunnelDns is the DNS set the gateway sent on the connect
    /// hook (DESIGN.md §十九): when it is empty the DNS row is
    /// informational, never a verdict.
    static func runLeakCheck(
        tunnelIf: String?,
        gatewayIps: [String],
        physicalIf: String,
        tunnelDns: [String]
    ) -> [LeakCheckItem] {
        guard let tunnelIf else {
            return [
                LeakCheckItem(item: "默认路由指向隧道", passed: false, detail: "未连接，连接后才能检查"),
                LeakCheckItem(item: "pf 锚点已装载", passed: false, detail: "未连接，连接后才能检查"),
                LeakCheckItem(item: "网关经物理口直连", passed: false, detail: "未连接，连接后才能检查"),
            ]
        }
        var items: [LeakCheckItem] = []

        let (_, defaultOut) = run("/sbin/route", ["-n", "get", "default"])
        let defaultIf = interfaceName(from: defaultOut)
        items.append(LeakCheckItem(
            item: "默认路由指向隧道",
            passed: defaultIf == tunnelIf,
            detail: defaultIf.map { "默认路由经 \($0)，隧道口为 \(tunnelIf)" } ?? "无默认路由"))

        let (pfStatus, pfOut) = run(
            "/sbin/pfctl", ["-a", PfController.anchor, "-s", "rules"])
        let ruleLines = pfOut.split(separator: "\n").filter { !$0.isEmpty }
        let pfRules = ruleLines.count
        let blocking = ruleLines.contains { $0.contains("block drop out") }
        items.append(LeakCheckItem(
            item: "pf 锚点已装载",
            passed: pfStatus == 0 && pfRules > 0,
            detail: pfStatus == 0
                ? "锚点内 \(pfRules) 条规则（\(blocking ? "封堵态：物理口只放行网关、局域网、DNS" : "连接态：物理口放行")）"
                : "pfctl 读取失败"))
        // An anchor only filters when pf itself is on (DESIGN.md §20.5).
        let (_, info) = run("/sbin/pfctl", ["-s", "info"])
        let enabled = info.contains("Status: Enabled")
        items.append(LeakCheckItem(
            item: "pf 已开启",
            passed: enabled,
            detail: enabled ? "pf 正在过滤" : "pf 未开启，锚点规则不生效"))

        if gatewayIps.isEmpty {
            items.append(LeakCheckItem(
                item: "网关经物理口直连",
                passed: false,
                detail: "无网关信息"))
        } else {
            var ok = true
            var parts: [String] = []
            for gateway in gatewayIps {
                let (_, out) = run("/sbin/route", ["-n", "get", gateway])
                let gwIf = interfaceName(from: out)
                if gwIf != physicalIf { ok = false }
                parts.append("\(gateway) → \(gwIf ?? "无路由")")
            }
            items.append(LeakCheckItem(
                item: "网关经物理口直连",
                passed: ok,
                detail: "物理口为 \(physicalIf)；" + parts.joined(separator: "，")))
        }

        // "  nameserver[0] : 10.0.0.1" -> "10.0.0.1" (the old parse kept
        // "[0] : …" and never matched; a non-UTF-8 byte in the output
        // read as nothing at all: the red "未读到", user 2026-11-05).
        let (_, dnsOut) = run("/usr/sbin/scutil", ["--dns"])
        var servers: [String] = []
        for line in dnsOut.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("nameserver"), let colon = t.firstIndex(of: ":") else { continue }
            let server = t[t.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if !server.isEmpty, !servers.contains(server) { servers.append(server) }
        }
        let resolverText = servers.isEmpty ? "未读到" : servers.joined(separator: "，")
        // Split mode (§26.5): the system asks the local forwarder first,
        // which hands every name not on the list to the tunnel's DNS.
        let viaForwarder = servers.first == "127.0.0.1"
        if tunnelDns.isEmpty {
            items.append(LeakCheckItem(
                item: "隧道 DNS 已生效",
                passed: false,
                informational: true,
                detail: "网关未下发隧道 DNS；系统解析器：\(resolverText)"))
        } else {
            let covered = tunnelDns.contains { servers.contains($0) }
            items.append(LeakCheckItem(
                item: "隧道 DNS 已生效",
                passed: covered,
                detail: viaForwarder && covered
                    ? "系统先问本机分流转发器（127.0.0.1），名单外的域名交给隧道 DNS：\(tunnelDns.joined(separator: "，"))"
                    : "隧道 DNS：\(tunnelDns.joined(separator: "，"))；系统解析器：\(resolverText)"))
        }
        return items
    }

    private static func interfaceName(from routeOutput: String) -> String? {
        for line in routeOutput.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                return trimmed.replacingOccurrences(of: "interface:", with: "")
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    private static func run(_ path: String, _ args: [String]) -> (Int32, String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
        } catch {
            return (-1, "")
        }
        // Read before waiting: a full pipe would block the child forever.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (proc.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
