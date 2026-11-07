import Foundation

/// The openconnect engine, service side (DESIGN.md §15/§16, §23, §25–§30).
///
/// The engine itself — spawning openconnect, feeding the credential,
/// reading and redacting its output, cookie capture and reuse, the
/// approval wait, classifying the child's exit, retries through the
/// session driver, pf through the network gate, the split's forwarder
/// and routes, following the physical network, the manual stop — is
/// Rust (core/src/oc_engine.rs, §32.13: resident logic in Rust). This
/// class is its shell, with the interface the service always used, plus
/// what needs macOS frameworks: configd (the physical router, the local
/// DNS servers) and the system root certificates.
final class CLIOrchestrator {
    struct Config {
        var server: String
        var group: String
        var username: String
        var password: String
        var openconnectPath: String?
        var cafile: String? = nil
        var scriptPath: String
        var cookieStore: CookieStore
        /// The interface pf blocks; the connect hook's phys= replaces it.
        var physicalIf: String
        var allowNetworks: [String]
        var maxAttempts: Int?
        /// Load the connected set while the tunnel is up (§17.5); off.
        var allowDirectEgressWhenConnected = false
        var noRoutes: Bool
        /// Nil = the default Application Support dir.
        var supportDir: URL?
        /// Test tool only: each redacted child line to stderr.
        var debugChildOutput = false
        /// Own connection (§二十三): through the App's certificate relay.
        var relay: RelaySettings? = nil
        /// The domain split's list (§26.5). Nil = no forwarder.
        var directDomains: [String]? = nil
        /// 断线保护 (§26.19). Default on.
        var dropProtection = true
    }

    enum FedCredential { case password, cookie }
    enum TerminalReason { case stoppedManual, authFailure, attemptsExhausted, componentMissing }

    var onState: ((SessionDriverClient.State, String) -> Void)? {
        get { box.onState }
        set { box.onState = newValue }
    }
    var onTerminal: ((TerminalReason) -> Void)? {
        get { box.onTerminal }
        set { box.onTerminal = newValue }
    }

    static var approvalQuietSeconds: TimeInterval = TestKnobs.value("ALWAYSCONNECT_TEST_APPROVAL_QUIET") ?? 3
    /// A "Login failed" this soon after the password is a rejection,
    /// never an expired approval (§21.19).
    static var approvalExpiryMinimum: TimeInterval = TestKnobs.value("ALWAYSCONNECT_TEST_APPROVAL_MIN") ?? 20
    static let pushBackoff: [TimeInterval] = TestKnobs.value("ALWAYSCONNECT_TEST_PUSH_BACKOFF").map { [$0] }
        ?? [30, 60, 120, 300]

    /// What the Rust engine calls back into; it keeps this (retained)
    /// until its session is over, even after this shell is gone, so a
    /// stop's completion always runs.
    private final class Box {
        let lock = NSLock()
        var onState: ((SessionDriverClient.State, String) -> Void)?
        var onTerminal: ((TerminalReason) -> Void)?
        var completions: [() -> Void] = []
    }

    private let box = Box()
    private let handle: OpaquePointer

    init(config: Config) {
        _ = NetworkGuard.shared
        let support = config.supportDir ?? Self.defaultSupportDir
        var json: [String: Any] = [
            "server": config.server, "group": config.group, "username": config.username,
            "password": config.password, "scriptPath": config.scriptPath,
            "cookieStorePath": config.cookieStore.fileURL.path, "physicalIf": config.physicalIf,
            "allowNetworks": config.allowNetworks,
            "allowDirectEgressWhenConnected": config.allowDirectEgressWhenConnected,
            "noRoutes": config.noRoutes, "supportDir": support.path,
            "debugChildOutput": config.debugChildOutput, "dropProtection": config.dropProtection,
            "testActive": TestSeam.isActive, "bootSession": BootSession.id ?? "",
            "approvalQuietSecs": Self.approvalQuietSeconds,
            "approvalExpiryMinimum": Self.approvalExpiryMinimum, "pushBackoff": Self.pushBackoff,
        ]
        if let path = config.openconnectPath { json["openconnectPath"] = path }
        if let cafile = config.cafile { json["cafile"] = cafile }
        if let max = config.maxAttempts { json["maxAttempts"] = max }
        if let tool = TestSeam.tool("openconnect") { json["testOpenconnect"] = tool }
        if let relay = config.relay {
            json["relay"] = ["gatewayIp": relay.gatewayIp, "arguments": relay.arguments(server: config.server)]
        }
        if let domains = config.directDomains { json["directDomains"] = domains }
        var text = (try? JSONSerialization.data(withJSONObject: json)).map { String(decoding: $0, as: UTF8.self) } ?? "{}"
        let ctx = Unmanaged.passRetained(box).toOpaque()
        var hooks = AcEngineHooks(
            ctx: ctx,
            state: { ctx, state, detail in
                guard let ctx, let detail else { return }
                let box = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
                let value = SessionDriverClient.State(rawValue: Int(state)) ?? .disconnected
                box.lock.lock(); let handler = box.onState; box.lock.unlock()
                handler?(value, String(cString: detail))
            },
            terminal: { ctx, reason in
                guard let ctx else { return }
                let box = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
                let value: TerminalReason = reason == 0 ? .stoppedManual : reason == 1 ? .authFailure : reason == 3 ? .componentMissing : .attemptsExhausted
                box.lock.lock(); let handler = box.onTerminal; box.lock.unlock()
                handler?(value)
            },
            physicalNetwork: { _, prefer in
                guard let prefer, let now = PhysicalNetwork.current(preferring: String(cString: prefer)) else { return nil }
                return strdup("\(now.gateway)|\(now.interface)")
            },
            localDNS: { _, iface in
                guard let iface else { return nil }
                return strdup(LocalDNS.servers(for: String(cString: iface)).joined(separator: ","))
            },
            systemRoots: { _ in
                SystemRoots.ensure(supportDir: CLIOrchestrator.defaultSupportDir).flatMap { strdup($0) }
            },
            stopped: { ctx in
                guard let ctx else { return }
                let box = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
                box.lock.lock(); let done = box.completions; box.completions = []; box.lock.unlock()
                done.forEach { $0() }
            },
            release: { ctx in if let ctx { Unmanaged<Box>.fromOpaque(ctx).release() } })
        handle = ac_oc_new(text, &hooks)!
        text = String(repeating: " ", count: text.count)
    }

    deinit { ac_oc_free(handle) }

    // MARK: - Lifecycle

    func start() { ac_oc_start(handle) }

    /// The network gate's holder name for this engine (§25.2).
    var holder: String { NetworkGuard.take(ac_oc_holder(handle)) ?? "" }

    /// `completion` runs once openconnect has exited and routes and pf
    /// are restored (§25.7). `keepSession`: SIGHUP, no log-off (§30.1).
    func stop(keepSession: Bool = false, completion: (() -> Void)? = nil) {
        if let completion {
            box.lock.lock(); box.completions.append(completion); box.lock.unlock()
        }
        ac_oc_stop(handle, keepSession, completion != nil)
    }

    /// Daemon shutdown: SIGHUP (no log-off), SIGKILL after 2 s.
    func killChild() { ac_oc_kill_child(handle) }

    func updateDirectDomains(_ domains: [String]) {
        ac_oc_update_direct_domains(handle, domains.joined(separator: "\n"))
    }

    func updateDropProtection(_ on: Bool) { ac_oc_update_drop_protection(handle, on) }

    func updateAllowNetworks(_ networks: [String]) {
        ac_oc_update_allow_networks(handle, networks.joined(separator: ","))
    }

    // MARK: - Facts for the service (diagnostics, panel)

    private struct Info: Decodable {
        var tunnelIf: String?
        var gatewayIps: [String]
        var physicalIf: String
        var tunnelDns: [String]
        var episodeRetries: Int
        var lastError: String?
        var pfError: String?
        var lastTerminal: Int?
        var splitRunning: Bool
        var splitHits: [String]
        var splitAddresses: Int
        var tail: [String]
    }

    private var info: Info? {
        guard let json = NetworkGuard.take(ac_oc_info(handle)) else { return nil }
        return try? JSONDecoder().decode(Info.self, from: Data(json.utf8))
    }

    var episodeRetries: Int { info?.episodeRetries ?? 0 }
    var lastError: String? { info?.lastError }
    var pfError: String? { info?.pfError }
    var lastTerminalReason: TerminalReason? {
        info?.lastTerminal.map { $0 == 0 ? .stoppedManual : $0 == 1 ? .authFailure : $0 == 3 ? .componentMissing : .attemptsExhausted }
    }
    var tunnelInterface: String? { info?.tunnelIf }
    var gatewayAddresses: [String] { info?.gatewayIps ?? [] }
    var physicalInterface: String { info?.physicalIf ?? "en0" }
    var tunnelDnsServers: [String] { info?.tunnelDns ?? [] }
    var redactedLogTail: [String] { info?.tail ?? [] }

    /// (entries, address count); empty when no split is running.
    func splitActivity() -> ([String], Int) {
        guard let info, info.splitRunning else { return ([], 0) }
        return (info.splitHits, info.splitAddresses)
    }

    /// The connections page for this session (§28.7); `fallbackGateways`
    /// when the session has none (a Cisco session).
    func connectionsJSON(fallbackGateways: [String]) -> String {
        NetworkGuard.take(ac_oc_connections_json(handle, fallbackGateways.joined(separator: ","))) ?? "[]"
    }

    static func connectionsJSONWithoutEngine(gateways: [String]) -> String {
        NetworkGuard.take(ac_oc_connections_json(nil, gateways.joined(separator: ","))) ?? "[]"
    }

    // MARK: - Without an engine

    static var defaultSupportDir: URL {
        CookieStore.defaultFileURL.deletingLastPathComponent()
    }

    static func routeStateURL(_ supportDir: URL) -> URL {
        supportDir.appendingPathComponent("route-state")
    }

    static func localNetworkHeld() -> Bool {
        _ = NetworkGuard.shared
        return ac_oc_local_network_held(defaultSupportDir.path)
    }

    static func runScriptRestore(scriptPath: String, supportDir: URL, noRoutes: Bool) {
        runScript("restore", scriptPath: scriptPath, supportDir: supportDir, noRoutes: noRoutes)
    }

    static func runScript(_ reason: String, scriptPath: String, supportDir: URL, noRoutes: Bool) {
        ac_oc_run_script(reason, scriptPath, supportDir.path, noRoutes, TestSeam.isActive)
    }

    /// Daemon start (§26.3): "none", "dropped" or "restored".
    @discardableResult
    static func undoJournalAtStart(scriptPath: String, supportDir: URL = defaultSupportDir) -> String {
        NetworkGuard.take(ac_oc_undo_journal_at_start(scriptPath, supportDir.path, BootSession.id ?? "",
                                                      TestSeam.isActive)) ?? "none"
    }

    /// Release with no engine running (§20.4, §25.2).
    static func restoreLocalNetworkWithoutEngine(scriptPath: String, reason: String) {
        _ = NetworkGuard.shared
        ac_oc_restore_without_engine(scriptPath, reason, defaultSupportDir.path, BootSession.id ?? "",
                                     TestSeam.isActive)
    }

    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func redact(_ line: String) -> String { NetworkGuard.take(ac_oc_redact(line)) ?? "" }
}

struct AcEngineHooks {
    var ctx: UnsafeMutableRawPointer?
    var state: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?) -> Void
    var terminal: @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void
    var physicalNetwork: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    var localDNS: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    var systemRoots: @convention(c) (UnsafeMutableRawPointer?) -> UnsafeMutablePointer<CChar>?
    var stopped: @convention(c) (UnsafeMutableRawPointer?) -> Void
    var release: @convention(c) (UnsafeMutableRawPointer?) -> Void
}

@_silgen_name("ac_oc_new")
func ac_oc_new(_ config: UnsafePointer<CChar>, _ hooks: UnsafePointer<AcEngineHooks>) -> OpaquePointer?
@_silgen_name("ac_oc_free") func ac_oc_free(_ e: OpaquePointer)
@_silgen_name("ac_oc_start") func ac_oc_start(_ e: OpaquePointer)
@_silgen_name("ac_oc_stop") func ac_oc_stop(_ e: OpaquePointer, _ keepSession: Bool, _ notify: Bool)
@_silgen_name("ac_oc_kill_child") func ac_oc_kill_child(_ e: OpaquePointer)
@_silgen_name("ac_oc_update_direct_domains") func ac_oc_update_direct_domains(_ e: OpaquePointer, _ d: UnsafePointer<CChar>)
@_silgen_name("ac_oc_update_drop_protection") func ac_oc_update_drop_protection(_ e: OpaquePointer, _ on: Bool)
@_silgen_name("ac_oc_update_allow_networks") func ac_oc_update_allow_networks(_ e: OpaquePointer, _ n: UnsafePointer<CChar>)
@_silgen_name("ac_oc_holder") func ac_oc_holder(_ e: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_oc_info") func ac_oc_info(_ e: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_oc_connections_json")
func ac_oc_connections_json(_ e: OpaquePointer?, _ fallback: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_oc_redact") func ac_oc_redact(_ line: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_oc_run_script")
func ac_oc_run_script(_ reason: UnsafePointer<CChar>, _ script: UnsafePointer<CChar>, _ support: UnsafePointer<CChar>,
                      _ noRoutes: Bool, _ testActive: Bool)
@_silgen_name("ac_oc_local_network_held") func ac_oc_local_network_held(_ support: UnsafePointer<CChar>) -> Bool
@_silgen_name("ac_oc_undo_journal_at_start")
func ac_oc_undo_journal_at_start(_ script: UnsafePointer<CChar>, _ support: UnsafePointer<CChar>,
                                 _ boot: UnsafePointer<CChar>, _ testActive: Bool) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_oc_restore_without_engine")
func ac_oc_restore_without_engine(_ script: UnsafePointer<CChar>, _ reason: UnsafePointer<CChar>,
                                  _ support: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>, _ testActive: Bool)

/// macOS's root certificates as a PEM file for openconnect's --cafile
/// (§27.3), refreshed once a day from the system keychain.
enum SystemRoots {
    static func ensure(supportDir: URL) -> String? {
        let file = supportDir.appendingPathComponent("system-roots.pem")
        let fm = FileManager.default
        if let date = (try? fm.attributesOfItem(atPath: file.path))?[.modificationDate] as? Date,
           Date().timeIntervalSince(date) < 86_400 {
            return file.path
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return fm.fileExists(atPath: file.path) ? file.path : nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0, data.count > 1000 else { return fm.fileExists(atPath: file.path) ? file.path : nil }
        try? fm.createDirectory(at: supportDir, withIntermediateDirectories: true)
        guard (try? data.write(to: file, options: .atomic)) != nil else { return nil }
        return file.path
    }
}
