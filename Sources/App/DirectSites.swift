import Darwin
import Foundation

/// One entry of the user's "不走 VPN 的网站" list (DESIGN.md §26.12): a
/// name to show and the domains it covers (each with its subdomains).
/// A typed domain is an entry of its own; an old preset group migrated
/// as one entry with the domains it needed.
struct DirectSite: Codable, Equatable, Identifiable {
    var name: String
    var domains: [String]
    var id: String { name + "|" + domains.joined(separator: ",") }
}

/// The list's helpers (DESIGN.md §26.5, §26.12). Only the own connection
/// (按网站分流 on) uses it; under Cisco the company's split list decides.
enum DirectSites {
    /// The list as stored, or (first time) the user's own names from the
    /// old page. The old ready-made groups are not carried over (user,
    /// 2026-11-05: no entries the user did not write).
    static func sites(_ settings: AppSettings) -> [DirectSite] {
        if let sites = settings.directSites { return sites }
        return (settings.directCustom ?? []).map { DirectSite(name: $0, domains: [$0]) }
    }

    /// A name the user typed, cleaned: lower case, no scheme, path,
    /// port, leading "*." or dots. Nil when it cannot be a domain.
    static func clean(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        s = String(s.split(separator: "/").first ?? "")
        s = String(s.split(separator: ":").first ?? "")
        s = s.trimmingCharacters(in: CharacterSet(charactersIn: "*."))
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-.")
        guard s.contains("."), !s.contains(".."), s.unicodeScalars.allSatisfy(allowed.contains) else { return nil }
        return s
    }
}

/// Adding to the list from a connection row (Settings → 连接,
/// DESIGN.md §四十四): which entries to offer, and whether an entry the
/// user wrote already covers the row. Pure logic, no settings or UI.
extension DirectSites {
    struct Choice: Equatable {
        /// The list line, exactly as the 分流 page would store it.
        var rule: String
        /// What the menu says.
        var label: String
    }

    /// Second-level labels that are part of a country's suffix
    /// ("example.com.cn", "example.co.uk"): the whole site is then three
    /// labels, not two. A heuristic, not the public suffix list.
    private static let secondLevel: Set<String> = ["com", "net", "org", "gov", "edu", "co", "ac", "or", "ne", "go"]

    /// The site a name belongs to: "www.example.com" -> "example.com",
    /// "a.example.com.cn" -> "example.com.cn".
    static func site(of host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }
        let n = labels.count
        let take = labels[n - 1].count == 2 && secondLevel.contains(labels[n - 2]) ? 3 : 2
        return labels.suffix(min(take, n)).joined(separator: ".")
    }

    /// The menu for one row: the whole site first, each level in between,
    /// the name itself, then the bare address. Without a name only the
    /// address is offered (the program did not ask the system's DNS).
    static func choices(host: String?, address: String) -> [Choice] {
        var out: [Choice] = []
        if let host, let name = clean(host) {
            let whole = site(of: name)
            out.append(Choice(rule: whole, label: whole + "  整个网站"))
            var labels = name.split(separator: ".").map(String.init)
            var levels: [String] = []
            while labels.count > whole.split(separator: ".").count {
                levels.append(labels.joined(separator: "."))
                labels.removeFirst()
            }
            for (i, level) in levels.reversed().enumerated() {
                let last = i == levels.count - 1
                out.append(Choice(rule: level, label: level + (last ? "  只这一个" : "  和它的子域名")))
            }
        }
        if isValidIPv4Address(address) {
            out.append(Choice(rule: address + "/32", label: "只这个地址  " + address))
        }
        return out
    }

    /// The list line (a plain name or network) that already covers this
    /// name or address, nil when none does. Site lists and geoip are not
    /// looked into: expanding them costs memory for a table cell.
    static func covering(_ sites: [DirectSite], host: String?, address: String) -> String? {
        let name = host.flatMap(clean)
        for line in sites.flatMap(\.domains) {
            switch ListRule.parse(line) {
            case .domain(let d)?:
                if let name, name == d || name.hasSuffix("." + d) { return line }
            case .network(let cidr)?:
                if contains(cidr, address) { return line }
            default: break
            }
        }
        return nil
    }

    /// The list with `rule` added at the end, unless already there.
    static func adding(_ rule: String, to sites: [DirectSite]) -> [DirectSite] {
        guard let parsed = ListRule.parse(rule) else { return sites }
        let text = parsed.text
        if sites.contains(where: { $0.domains == [text] || (!parsed.isNetwork && $0.domains.contains(text)) }) { return sites }
        return sites + [DirectSite(name: text, domains: [text])]
    }

    /// The list without the entry `line` (a one-line entry goes; a
    /// migrated group loses only that line).
    static func removing(_ line: String, from sites: [DirectSite]) -> [DirectSite] {
        sites.compactMap { site in
            guard site.domains.contains(line) else { return site }
            let rest = site.domains.filter { $0 != line }
            return rest.isEmpty ? nil : DirectSite(name: site.name, domains: rest)
        }
    }

    private static func contains(_ cidr: String, _ address: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let bits = UInt32(parts[1]), bits <= 32,
              let net = ipv4Value(String(parts[0])), let ip = ipv4Value(address) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        return net & mask == ip & mask
    }

    private static func ipv4Value(_ s: String) -> UInt32? {
        var a = in_addr()
        guard inet_pton(AF_INET, s, &a) == 1 else { return nil }
        return UInt32(bigEndian: a.s_addr)
    }
}

extension AppSettings {
    /// The rules the own connection's DNS forwarder gets: names, site
    /// lists and geoip expanded (§26.13); networks go elsewhere.
    var directDomains: [String] {
        var seen = Set<String>()
        return listRules.flatMap(\.expanded).filter { seen.insert($0).inserted }
    }
}
