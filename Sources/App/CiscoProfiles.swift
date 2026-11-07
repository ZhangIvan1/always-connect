import Foundation

/// Server entry names from the local Cisco Secure Client profiles
/// (DESIGN.md §20.6). "VPN-A" is a profile entry's HostName, not a
/// host: openconnect cannot resolve it. Cisco keeps the mapping to
/// the real HostAddress in its profile XML on this Mac, so the App
/// looks the name up there at connect time instead of the repository
/// carrying company hostnames. A server that already looks like an
/// address (has a dot or a colon), or a name no profile knows, is
/// passed through unchanged.
enum CiscoProfiles {
    static let directories = [
        "/opt/cisco/secureclient/vpn/profile",
        "/opt/cisco/anyconnect/profile",
    ]

    static func resolve(_ server: String) -> String {
        let name = server.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !name.contains("."), !name.contains(":") else {
            return name
        }
        return hostEntries()[name] ?? name
    }

    /// The user's Cisco "Allow local (LAN) access" preference. Cisco
    /// Secure Client 5 keeps it in the machine-wide preferences file
    /// (/opt/cisco/secureclient/vpn/.anyconnect_global, observed
    /// 2026-11-03 with the box ticked); older AnyConnect used
    /// ~/.anyconnect. The first file that mentions it wins. nil = no
    /// preferences file mentions it yet (the profile default, off).
    static func localLanAccessEnabled() -> Bool? {
        for path in preferenceFiles {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  text.contains("<LocalLanAccess")
            else { continue }
            return localLanAccess(in: text)
        }
        return nil
    }

    private static func localLanAccess(in text: String) -> Bool {
        guard let open = text.range(of: "<LocalLanAccess"),
              let close = text.range(of: "</LocalLanAccess>", range: open.upperBound..<text.endIndex),
              let gt = text.range(of: ">", range: open.upperBound..<close.lowerBound)
        else { return false }
        return text[gt.upperBound..<close.lowerBound]
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "true"
    }

    /// Cisco's preferences files, newest wins for the last connection
    /// (DESIGN.md §三十八): Secure Client 5's machine-wide file, an older
    /// AnyConnect's per-user and machine-wide ones.
    static var preferenceFiles: [String] {
        [
            "/opt/cisco/secureclient/vpn/.anyconnect_global",
            FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".anyconnect").path,
            "/opt/cisco/anyconnect/.anyconnect_global",
        ]
    }

    /// Cisco is installed here, or once was (a profile folder exists).
    static var isPresent: Bool {
        directories.contains { FileManager.default.fileExists(atPath: $0) }
    }

    struct Snapshot: Decodable {
        struct Entry: Decodable { var name: String; var address: String }
        struct Preferences: Decodable {
            var host_name: String
            var host_address: String
            var user: String
            var group: String
        }
        var entries: [Entry]
        var preferences: Preferences
    }

    /// Cisco's entries and last connection, read by the Rust core
    /// (core/src/cisco_import.rs). Cisco's files are only read.
    static func snapshot() -> Snapshot? {
        let request: [String: [String]] = ["profile_dirs": directories, "preference_files": preferenceFiles]
        return callJSON(ac_cisco_snapshot, request)
    }

    /// HostName -> HostAddress across every profile; the first
    /// profile (by file name) to define a name wins.
    static func hostEntries() -> [String: String] {
        var entries: [String: String] = [:]
        for entry in snapshot()?.entries ?? [] where entries[entry.name] == nil {
            entries[entry.name] = entry.address
        }
        return entries
    }

    /// The user name Cisco last logged in with ("" = none).
    static func lastUser() -> String { snapshot()?.preferences.user ?? "" }

    /// The group Cisco last used ("" = the gateway's default).
    static func lastGroup() -> String { snapshot()?.preferences.group ?? "" }

    /// One JSON request to the core, one JSON answer back.
    static func callJSON<Request: Encodable, Answer: Decodable>(
        _ function: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?, _ request: Request
    ) -> Answer? {
        guard let data = try? JSONEncoder().encode(request),
              let text = String(data: data, encoding: .utf8) else { return nil }
        guard let reply = text.withCString({ function($0) }) else { return nil }
        defer { cisco_string_free(reply) }
        return try? JSONDecoder().decode(Answer.self, from: Data(String(cString: reply).utf8))
    }
}

@_silgen_name("ac_cisco_snapshot")
func ac_cisco_snapshot(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
// Same symbol as CertificateRelay's ac_string_free, declared here too so
// this file builds alone in the test harnesses.
@_silgen_name("ac_string_free")
private func cisco_string_free(_ s: UnsafeMutablePointer<CChar>?)
@_silgen_name("ac_cisco_sync")
func ac_cisco_sync(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
