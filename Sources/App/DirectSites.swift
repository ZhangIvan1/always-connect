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

extension AppSettings {
    /// The rules the own connection's DNS forwarder gets: names, site
    /// lists and geoip expanded (§26.13); networks go elsewhere.
    var directDomains: [String] {
        var seen = Set<String>()
        return listRules.flatMap(\.expanded).filter { seen.insert($0).inserted }
    }
}
