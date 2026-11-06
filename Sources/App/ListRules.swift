import Darwin
import Foundation

/// One line of the "不走 VPN" list (DESIGN.md §26.13). The user types
/// any of:
///   example.com          the site and all its subdomains
///   geosite:github       a ready-made site list (v2fly domain-list-
///   geosite:google@cn    community, as v2ray uses), optionally
///                        only its rules with that attribute
///   geoip:cn             any name whose address is in China mainland
///   192.168.0.0/16       a network (also a single address)
/// Names and site lists are expanded here into the background service's
/// rule kinds; networks go to the drop-protection allowlist (and, in
/// split mode, direct routes), so they also work under Cisco.
enum ListRule: Equatable {
    case domain(String)
    case geosite(String, attribute: String?)
    case geoip(String)
    case network(String)

    static func parse(_ input: String) -> ListRule? {
        let s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = s.lowercased()
        if lower.hasPrefix("geosite:") {
            let parts = lower.dropFirst("geosite:".count).split(separator: "@", maxSplits: 1)
            guard let name = parts.first.map(String.init), GeoData.hasList(name) else { return nil }
            return .geosite(name, attribute: parts.count == 2 ? String(parts[1]) : nil)
        }
        if lower.hasPrefix("geoip:") {
            let code = String(lower.dropFirst("geoip:".count))
            return GeoData.geoipCountries.contains(code) ? .geoip(code) : nil
        }
        if isValidCIDR(s) { return .network(s) }
        if isValidIPv4Address(s) { return .network(s + "/32") }
        if let domain = DirectSites.clean(s) { return .domain(domain) }
        return nil
    }

    /// Why `input` is not a rule, in the user's words; nil when it is.
    static func problem(_ input: String) -> String? {
        let lower = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !lower.isEmpty, parse(input) == nil else { return nil }
        if lower.hasPrefix("geosite:") { return "没有叫这个名字的网站清单" }
        if lower.hasPrefix("geoip:") { return "目前只支持 geoip:cn" }
        return "认不出来：可以写网址、geosite:清单名、geoip 或网段"
    }

    var text: String {
        switch self {
        case .domain(let d): return d
        case .geosite(let name, let attribute): return "geosite:" + name + (attribute.map { "@" + $0 } ?? "")
        case .geoip(let code): return "geoip:" + code
        case .network(let cidr): return cidr
        }
    }

    /// What kind of line it is, shown under it.
    var kind: String {
        switch self {
        case .domain: return "网站（含子域名）"
        case .geosite(let name, _):
            return "网站清单 · \(GeoData.ruleCount(name)) 条规则"
        case .geoip: return "国家 IP · 解析到这些地址的网站直连"
        case .network: return "网段 · 断线时也照常可用"
        }
    }

    var isNetwork: Bool { if case .network = self { return true } else { return false } }

    /// The background service's rule kinds (DNSForwarder's SplitRules).
    var expanded: [String] {
        switch self {
        case .domain(let d): return [d]
        case .geosite(let name, let attribute): return GeoData.geosite(name, attribute: attribute)
        case .geoip(let code): return GeoData.geoip(code).map { "ipcidr:" + $0 }
        case .network: return []
        }
    }
}

func isValidIPv4Address(_ value: String) -> Bool {
    var a = in_addr()
    return inet_pton(AF_INET, value, &a) == 1
}

/// The bundled data (scripts/make-geo-data.py): Resources/geosite.txt
/// and geoip-cn.txt. Read once, on first use.
enum GeoData {
    static let geoipCountries: Set<String> = ["cn"]

    private static let lock = NSLock()
    /// The geosite file, memory-mapped (clean pages the system can drop),
    /// and where each list's lines sit in it. Only the lists asked for
    /// are ever turned into strings, and those are not kept (§27.4: the
    /// whole file parsed and cached cost the App ~20 MB).
    private static var mapped: Data?
    private static var index: [String: Range<Int>]?

    private static func url(_ name: String) -> URL? {
        if let dir = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEODATA"] {
            return URL(fileURLWithPath: dir).appendingPathComponent(name)
        }
        let base = (name as NSString).deletingPathExtension
        return Bundle.main.url(forResource: base, withExtension: "txt")
            ?? Bundle.main.url(forResource: base, withExtension: "txt", subdirectory: "GeoData")
    }

    private static func loadIndex() -> (Data, [String: Range<Int>]) {
        lock.lock(); defer { lock.unlock() }
        if let mapped, let index { return (mapped, index) }
        let data = url("geosite.txt").flatMap { try? Data(contentsOf: $0, options: .alwaysMapped) } ?? Data()
        var found: [String: Range<Int>] = [:]
        var current: String?
        var bodyStart = 0
        var lineStart = 0
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            for i in 0...bytes.count {
                guard i == bytes.count || bytes[i] == 0x0A else { continue }
                if i > lineStart, bytes[lineStart] == UInt8(ascii: "["), bytes[i - 1] == UInt8(ascii: "]") {
                    if let current { found[current] = bodyStart..<lineStart }
                    current = String(decoding: UnsafeRawBufferPointer(rebasing: raw[(lineStart + 1)..<(i - 1)]),
                                     as: UTF8.self)
                    bodyStart = i + 1
                }
                lineStart = i + 1
            }
        }
        if let current { found[current] = bodyStart..<max(bodyStart, data.count) }
        mapped = data
        index = found
        return (data, found)
    }

    static func hasList(_ name: String) -> Bool { loadIndex().1[name] != nil }

    static var listNames: [String] { loadIndex().1.keys.sorted() }

    private static func lines(_ name: String) -> [Substring] {
        let (data, index) = loadIndex()
        guard let range = index[name], !range.isEmpty, range.upperBound <= data.count else { return [] }
        return String(decoding: data[range], as: UTF8.self).split(separator: "\n")
    }

    /// How many rules a list has, without keeping them.
    static func ruleCount(_ name: String) -> Int { lines(name).count }

    /// "d:x @a" -> "domain:x", "f:" -> "full:", "k:" -> "keyword:",
    /// "r:" -> "regexp:"; with an attribute, only lines carrying it.
    static func geosite(_ name: String, attribute: String?) -> [String] {
        let kinds: [Character: String] = ["d": "domain:", "f": "full:", "k": "keyword:", "r": "regexp:"]
        return lines(name).compactMap { line in
            let parts = line.split(separator: " ")
            guard let head = parts.first, head.count > 2, let prefix = kinds[head.first!] else { return nil }
            if let attribute, !parts.dropFirst().contains(Substring("@" + attribute)) { return nil }
            return prefix + head.dropFirst(2)
        }
    }

    /// Read when asked and not kept, like the site lists (§32.4): it is
    /// needed only when the list is sent to the background service.
    static func geoip(_ code: String) -> [String] {
        guard code == "cn" else { return [] }
        let text = url("geoip-cn.txt").flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
        return text.split(separator: "\n").map(String.init).filter(isValidCIDR)
    }
}

/// The networks the Mac sits on right now, for "本地局域网直连"
/// (§26.13, user: not a fixed 192.168): every wired/Wi-Fi interface's
/// own subnet, never wider than a /16.
enum LocalNetwork {
    static func current() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            guard name.hasPrefix("en"), entry.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == sa_family_t(AF_INET),
                  let mask = entry.pointee.ifa_netmask else { continue }
            let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            var m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            if a >> 16 == 0xA9FE { continue }  // 169.254 link-local: no real network
            if m < 0xFFFF_0000 { m = 0xFFFF_0000 }
            let bits = m.nonzeroBitCount
            let net = a & m
            let cidr = "\(net >> 24).\(net >> 16 & 0xFF).\(net >> 8 & 0xFF).\(net & 0xFF)/\(bits)"
            if !out.contains(cidr) { out.append(cidr) }
        }
        return out
    }
}

extension AppSettings {
    /// "本地局域网直连", on unless switched off.
    var isAutoLANOn: Bool { autoLAN ?? true }

    /// The list's parsed rules, in order.
    var listRules: [ListRule] {
        DirectSites.sites(self).flatMap(\.domains).compactMap(ListRule.parse)
    }

    /// What the drop-protection allowlist (and split-mode direct routes)
    /// get: the list's networks, plus the local network when on.
    var effectiveAllowNetworks: [String] {
        var out = listRules.compactMap { rule -> String? in
            if case .network(let cidr) = rule { return cidr } else { return nil }
        }
        if isAutoLANOn { out += LocalNetwork.current().filter { !out.contains($0) } }
        return out
    }
}
