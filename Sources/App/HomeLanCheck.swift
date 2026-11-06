import Foundation

/// "Can I reach my home router right now?" (DESIGN.md §21.9). Runs in
/// the App as the user, no root: for each physical interface's DHCP
/// router, which interface the routing table sends it to and whether a
/// ping comes back. Meant for the case the user hit at home — 192.168
/// unreachable while Cisco was connected even with Cisco's LAN option
/// on — so the next occurrence leaves evidence instead of a guess.
enum HomeLanCheck {
    struct Result {
        var router: String
        var routeInterface: String
        var reachable: Bool
    }

    static func run() -> [Result] {
        var results: [Result] = []
        for index in 0..<10 {
            let iface = "en\(index)"
            let router = output("/usr/sbin/ipconfig", ["getoption", iface, "router"])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !router.isEmpty, !results.contains(where: { $0.router == router }) else { continue }
            let route = output("/sbin/route", ["-n", "get", router])
            let routeIf = route.split(separator: "\n")
                .first { $0.contains("interface:") }
                .map { $0.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces) } ?? "" } ?? "?"
            // Ping first; many routers also (or only) answer on their
            // admin web page or DNS port, so try those before saying no.
            var reachable = status("/sbin/ping", ["-c", "2", "-t", "3", router]) == 0
            for port in ["80", "443", "53"] where !reachable {
                reachable = status("/usr/bin/nc", ["-z", "-G", "2", router, port]) == 0
            }
            results.append(Result(router: router, routeInterface: routeIf ?? "?", reachable: reachable))
        }
        return results
    }

    static func describe(_ results: [Result]) -> String {
        guard !results.isEmpty else { return "没找到本地路由器（当前不在有路由器的网络上）。" }
        return results.map { r in
            let path = r.routeInterface.hasPrefix("utun") ? "走 VPN 隧道（\(r.routeInterface)）" : "走本地网卡 \(r.routeInterface)"
            return "路由器 \(r.router)：\(path)，\(r.reachable ? "能连通 ✓" : "连不通 ✗")"
        }.joined(separator: "\n")
    }

    private static func output(_ tool: String, _ args: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private static func status(_ tool: String, _ args: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return -1 }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
