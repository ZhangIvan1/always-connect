import Foundation

/// The network gate (DESIGN.md §25.2, §25.8): the only code that writes
/// pf. The gate itself — holders and staleness, guard.json, the pf enable
/// token, adoption after a restart in the same boot (never a block at
/// boot), the grace period without an App, the direct-address table and
/// every pfctl call — is Rust (core/src/network_guard.rs, §32.12). This
/// is the service's shell, with the interface the engines and the
/// session always used.
final class NetworkGuard {
    static let shared = NetworkGuard()

    struct Inputs: Codable, Equatable {
        var tunnelIf: String
        var gatewayIps: [String]
        var physicalIf: String
        var allowNetworks: [String]
        var allowDNS: Bool
        /// Plan v2 (§25.8): port 53 passes to these only.
        var localDNSServers: [String] = []
        /// Plan v2 (§25.8): declare and pass `<ac_direct>`.
        var directTable: Bool = false
    }

    /// guard.json as written (the harness writes records of earlier runs).
    struct Record: Codable {
        var bootSession: String
        var token: String?
        var holder: String
        var connected: Bool
        var inputs: Inputs
        var direct: [String]?
    }

    static let directTableName = "ac_direct"

    struct Release: Codable {
        var reason: String
        var at: Date
    }

    enum Reason {
        static let user = "user"
        static let appGone = "app-gone"
        static let reboot = "reboot"
        static let upgrade = "upgrade"
    }

    /// How long a hold outlives its last App (DESIGN.md §25.2).
    static var graceSeconds: TimeInterval = {
        if TestSeam.isActive,
           let value = ProcessInfo.processInfo.environment["ALWAYSCONNECT_TEST_GRACE"],
           let seconds = TimeInterval(value) {
            return seconds
        }
        return 120
    }()

    /// Called off the gate's thread when a hold outlived its owner.
    var onGraceExpired: (() -> Void)?

    static let ciscoHolder = "cisco"

    private init() {
        let pfctl: String? = TestSeam.isActive ? TestSeam.tool("pfctl")
            : ["/sbin/pfctl", "/usr/sbin/pfctl"].first { FileManager.default.isExecutableFile(atPath: $0) }
        ac_guard_init(CLIOrchestrator.defaultSupportDir.path, BootSession.id ?? "",
                      UInt64(Self.graceSeconds * 1000), pfctl, {
            DispatchQueue.global().async { NetworkGuard.shared.onGraceExpired?() }
        })
    }

    // MARK: - Holders

    func newOwnHolder() -> String { Self.take(ac_guard_new_own_holder()) ?? "own:0" }

    /// Load `connected` (physical egress open) or the blocking set for
    /// `holder`. Nil on success (or when the holder is stale), else the
    /// panel's red pf line.
    @discardableResult
    func apply(holder: String, connected: Bool, inputs: Inputs) -> String? {
        guard let json = try? JSONEncoder().encode(inputs) else { return "pf 兜底未生效：规则生成被拒" }
        return Self.take(ac_guard_apply(holder, connected, String(decoding: json, as: UTF8.self)))
    }

    /// Let go of `holder`'s set; nil = whatever is held.
    func release(holder: String?, reason: String) { ac_guard_release(holder, reason) }

    var isHolding: Bool { ac_guard_is_holding() }

    var held: (holder: String, inputs: Inputs)? {
        struct Held: Decodable { var holder: String; var inputs: Inputs }
        guard let json = Self.take(ac_guard_held()),
              let held = try? JSONDecoder().decode(Held.self, from: Data(json.utf8)) else { return nil }
        return (held.holder, held.inputs)
    }

    func supersedeOwnHolders() { ac_guard_supersede_own_holders() }

    func updateHeldAllowNetworks(_ networks: [String]) {
        ac_guard_update_held_allow_networks(networks.joined(separator: ","))
    }

    // MARK: - Direct-address table (plan v2, DESIGN.md §25.8)

    /// In pf when this returns true; invalid entries fail the whole call.
    @discardableResult
    func addDirect(_ ips: [String]) -> Bool { ac_guard_add_direct(ips.joined(separator: ",")) }

    func removeDirect(_ ips: [String]) { ac_guard_remove_direct(ips.joined(separator: ",")) }

    func flushDirect() { ac_guard_flush_direct() }

    var directAddresses: [String] {
        (Self.take(ac_guard_direct_addresses()) ?? "").split(separator: ",").map(String.init)
    }

    static func isIPAddress(_ s: String) -> Bool { isValidIP(s) }

    var holder: String? { Self.take(ac_guard_holder()) }

    var lastRelease: Release? {
        guard let json = Self.take(ac_guard_last_release()) else { return nil }
        return try? JSONDecoder.iso.decode(Release.self, from: Data(json.utf8))
    }

    // MARK: - Owner and service start

    func ownerAttached() { ac_guard_owner_attached() }

    func ownerLost(sessionActive: Bool = false) { ac_guard_owner_lost(sessionActive) }

    func adoptAtStart() { ac_guard_adopt_at_start() }

    static func text(connected: Bool, inputs: Inputs) -> String? {
        guard let json = try? JSONEncoder().encode(inputs) else { return nil }
        return take(ac_guard_text(connected, String(decoding: json, as: UTF8.self)))
    }

    static func take(_ raw: UnsafeMutablePointer<CChar>?) -> String? {
        guard let raw else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }
}

extension JSONEncoder {
    static var iso: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}

extension JSONDecoder {
    static var iso: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}

extension NetworkGuard.Inputs {
    private enum CodingKeys: String, CodingKey {
        case tunnelIf, gatewayIps, physicalIf, allowNetworks, allowDNS, localDNSServers, directTable
    }

    /// Records written before plan v2 lack the last two keys (synthesized
    /// Codable would throw, AGENTS.md).
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        tunnelIf = try c.decode(String.self, forKey: .tunnelIf)
        gatewayIps = try c.decode([String].self, forKey: .gatewayIps)
        physicalIf = try c.decode(String.self, forKey: .physicalIf)
        allowNetworks = try c.decode([String].self, forKey: .allowNetworks)
        allowDNS = try c.decode(Bool.self, forKey: .allowDNS)
        localDNSServers = try c.decodeIfPresent([String].self, forKey: .localDNSServers) ?? []
        directTable = try c.decodeIfPresent(Bool.self, forKey: .directTable) ?? false
    }
}

@_silgen_name("ac_guard_init")
func ac_guard_init(_ supportDir: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>, _ graceMs: UInt64,
                   _ pfctl: UnsafePointer<CChar>?, _ graceExpired: (@convention(c) () -> Void)?)
@_silgen_name("ac_guard_new_own_holder") func ac_guard_new_own_holder() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_apply")
func ac_guard_apply(_ holder: UnsafePointer<CChar>, _ connected: Bool, _ inputs: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_release") func ac_guard_release(_ holder: UnsafePointer<CChar>?, _ reason: UnsafePointer<CChar>)
@_silgen_name("ac_guard_is_holding") func ac_guard_is_holding() -> Bool
@_silgen_name("ac_guard_held") func ac_guard_held() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_holder") func ac_guard_holder() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_supersede_own_holders") func ac_guard_supersede_own_holders()
@_silgen_name("ac_guard_update_held_allow_networks") func ac_guard_update_held_allow_networks(_ n: UnsafePointer<CChar>)
@_silgen_name("ac_guard_add_direct") func ac_guard_add_direct(_ ips: UnsafePointer<CChar>) -> Bool
@_silgen_name("ac_guard_remove_direct") func ac_guard_remove_direct(_ ips: UnsafePointer<CChar>)
@_silgen_name("ac_guard_flush_direct") func ac_guard_flush_direct()
@_silgen_name("ac_guard_direct_addresses") func ac_guard_direct_addresses() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_last_release") func ac_guard_last_release() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_guard_owner_attached") func ac_guard_owner_attached()
@_silgen_name("ac_guard_owner_lost") func ac_guard_owner_lost(_ sessionActive: Bool)
@_silgen_name("ac_guard_adopt_at_start") func ac_guard_adopt_at_start()
@_silgen_name("ac_guard_text")
func ac_guard_text(_ connected: Bool, _ inputs: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
