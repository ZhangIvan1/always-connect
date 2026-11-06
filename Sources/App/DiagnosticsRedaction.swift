import Foundation

/// What the diagnostics file leaves out (DESIGN.md §36.3). People post
/// it in public issues, so it must not name the user's VPN: the server
/// address and host, the Cisco entry names, the group. Every occurrence
/// in the free-form lines (the background service's detail, a drop's
/// failure reason) is replaced as well, case-insensitively; the split
/// list's entries are not written at all (they may name internal sites).
enum DiagnosticsRedaction {
    static let placeholder = "<已隐去>"

    /// The strings to hide for this profile, longest first so a host
    /// inside a full address is not half-replaced.
    static func secrets(server: String, group: String,
                        entries: [(name: String, address: String, ciscoName: String?)]) -> [String] {
        var all = [server, group]
        for entry in entries {
            all += [entry.name, entry.address, entry.ciscoName ?? ""]
        }
        var expanded: [String] = []
        for value in all {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            expanded.append(trimmed)
            if let host = Self.host(of: trimmed) { expanded.append(host) }
        }
        // Too short to be specific, and replacing it would shred the text.
        let kept = Set(expanded.filter { $0.count >= 3 })
        return kept.sorted { $0.count != $1.count ? $0.count > $1.count : $0 < $1 }
    }

    static func redact(_ text: String, secrets: [String]) -> String {
        var out = text
        for secret in secrets {
            out = out.replacingOccurrences(of: secret, with: placeholder, options: .caseInsensitive)
        }
        return out
    }

    /// "https://vpn.example.com:443/path" or "vpn.example.com/x" -> "vpn.example.com".
    static func host(of value: String) -> String? {
        var rest = Substring(value)
        if let scheme = rest.range(of: "://") { rest = rest[scheme.upperBound...] }
        if let end = rest.firstIndex(where: { $0 == "/" || $0 == ":" }) { rest = rest[..<end] }
        let host = String(rest)
        return host.isEmpty || host == value ? nil : host
    }
}
