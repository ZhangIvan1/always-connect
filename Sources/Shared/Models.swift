import Foundation

/// App Groups container + keys (ProfileStore). One place for the
/// suite name and keys.
enum AppGroups {
    static let suiteName = "group.com.alwaysconnect.app"
    static let profileKey = "profile"
    static let rulesKey = "rules"
    static let usernameKey = "username"
    static let appSettingsKey = "appSettings"
    static let dropHistoryKey = "dropHistory"
}

// MARK: - Profile

/// One VPN server the user can pick (DESIGN.md §21.13): added, edited
/// and removed in Settings → 账号, switched from the panel.
struct ServerEntry: Codable, Equatable, Identifiable {
    var id = UUID()
    var name: String
    var address: String
    /// Entries imported from the local Cisco profile keep Cisco's entry
    /// name and connect by it, so Cisco applies its own per-host
    /// settings; editing the address turns the entry into a plain one.
    var ciscoName: String?

    /// What the engine connects to.
    var target: String { ciscoName ?? address }
}

/// One VPN gateway configuration. Nothing company-specific is shipped
/// (§27.1): the server comes from the setup wizard or the Mac's Cisco
/// profile, the group is the gateway's default unless set.
struct Profile: Codable, Equatable {
    /// The selected server's connect target (ServerEntry.target).
    var server: String = ""
    var group: String = ""
    var autoConnectOnLaunch: Bool = true
    var defaultMode: DefaultMode = .secure
    /// Networks the pf sets let out directly (DESIGN.md §十九). Legacy:
    /// since §26.13 the split list and the detected local network feed
    /// the allowlist (AppSettings.effectiveAllowNetworks); no fixed LAN.
    var allowNetworks: [String] = []
    /// The user's server list (DESIGN.md §21.13). Empty until first
    /// filled from the Cisco profile.
    var servers: [ServerEntry] = []

    init() {}

    /// Every field optional on decode: synthesized Codable does NOT
    /// fall back to defaults for missing keys (it throws, and the
    /// whole stored profile would silently reset), so a profile saved
    /// by an older build keeps everything it has.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Profile()
        server = try c.decodeIfPresent(String.self, forKey: .server) ?? d.server
        group = try c.decodeIfPresent(String.self, forKey: .group) ?? d.group
        autoConnectOnLaunch = try c.decodeIfPresent(Bool.self, forKey: .autoConnectOnLaunch) ?? d.autoConnectOnLaunch
        defaultMode = try c.decodeIfPresent(DefaultMode.self, forKey: .defaultMode) ?? d.defaultMode
        allowNetworks = try c.decodeIfPresent([String].self, forKey: .allowNetworks) ?? d.allowNetworks
        servers = try c.decodeIfPresent([ServerEntry].self, forKey: .servers) ?? d.servers
    }
}

/// Default routing policy for traffic that matches no rule.
/// - secure: everything goes through the VPN (Cloudflare WARP "Exclude" mode).
/// - split: only listed traffic goes through the VPN (Cloudflare WARP "Include" mode).
enum DefaultMode: String, Codable {
    case secure
    case split
}

// MARK: - Rules

enum RuleType: String, Codable {
    case app
    case domain
    case network
}

enum RuleDirection: String, Codable {
    case viaVPN
    case direct
}

/// A single split rule. Priority: app > domain > network > default mode.
/// The 192.168.0.0/16 LAN hard rule always wins over everything.
struct Rule: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var type: RuleType
    /// App: signing identifier. Domain: wildcard allowed, e.g. *.example.com.
    /// Network: CIDR, e.g. 192.168.0.0/16.
    var target: String
    var direction: RuleDirection
    var isEnabled: Bool = true
}

// MARK: - CIDR validation

/// Strict CIDR check shared by the App (Settings validation) and
/// the Helper (defensive filter on updateAllowNetworks). A plain IP
/// without a prefix is rejected: pf rules need a range.
func isValidCIDR(_ value: String) -> Bool {
    let parts = value.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2,
          let prefix = Int(String(parts[1])), (0...32).contains(prefix) else { return false }
    let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
    guard octets.count == 4 else { return false }
    return octets.allSatisfy { octet in
        guard let n = Int(String(octet)) else { return false }
        return (0...255).contains(n)
    }
}

// MARK: - Session state (shared App <-> Provider via App Groups)

enum SessionStatus: String, Codable {
    case disconnected
    case connecting
    case authenticating
    case awaitingApproval   // Waiting for the user to confirm the login on their phone.
    case connected
    case reconnecting       // Kill switch active, traffic blackholed.
}

struct SessionState: Codable, Equatable {
    var status: SessionStatus = .disconnected
    var gateway: String = ""
    var tunnelAddress: String = ""
    var connectedSince: Date?
    var reconnectCount: Int = 0
    var lastDropAt: Date?
    var bytesIn: Int64 = 0
    var bytesOut: Int64 = 0
}

// MARK: - Leak check

/// One leak-check row for the Diagnostics page. `informational` rows
/// carry data for the user to judge and are never counted as pass or
/// fail; the DNS row is informational only when the gateway sent no
/// tunnel DNS set (DESIGN.md §十九).
/// One live connection for the Settings 连接 page (DESIGN.md §28.7).
struct ConnectionRow: Codable, Hashable {
    var process: String
    var pid: Int
    var proto: String
    var remote: String
    var port: Int
    /// The name it was looked up under, when the split forwarder saw it.
    var host: String?
    /// "vpn", "direct" or "local".
    var via: String
    var interface: String
    var reason: String
}

struct LeakCheckItem: Codable {
    var item: String
    var passed: Bool
    var informational: Bool = false
    var detail: String
}
