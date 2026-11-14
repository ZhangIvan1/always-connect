import AppKit
import Foundation
import os

/// Cisco engine (DESIGN.md §二十一): Cisco Secure Client runs the
/// tunnel, this drives it through Cisco's own CLI.
///
/// Why: the company gateway demands the client certificate in the
/// login keychain, whose private key is non-exportable (DESIGN.md
/// §20.13); only Cisco can present it, and Cisco's CLI does so when
/// run in the user's session — which is why this lives in the App, not
/// in the root Helper.
///
/// Division of labour:
/// - Cisco: certificate, protocol, its own in-session reconnects, its
///   split-exclude routes (home LAN 192.168.0.0/16 among them).
/// - This engine: log in with the Keychain password, watch Cisco's
///   state, re-establish a lost session forever (with backoff), map
///   everything onto the App's six states.
/// - Helper (root): the pf kill switch via setKillSwitch — connected
///   set while the tunnel is up, blocking set (plus DNS) the moment it
///   is lost, unloaded only on a manual disconnect. The Helper also
///   watches the tunnel interface itself, so a drop is blocked even
///   when the App is not running.
///
/// Facts this relies on are the 2026-11-03 observations (DESIGN.md
/// §21.1): prompt order (Username with a prefilled default, then
/// Password, which -s mode takes from stdin), "Login error." on a
/// rejected login, "Login failed." when the approval expires untapped
/// (§21.19), `>> state: X` lines, `vpn stats` "Server Address", and
/// that only one Cisco client may hold the connect capability (the GUI
/// app must not be running).
///
/// The engine itself — the CLI runs, output parsing, retries and backoff,
/// approval-expiry handling, the 4 s state watch, the kill-switch requests —
/// is Rust (core/src/cisco.rs, DESIGN.md §32.11). This class is its shell:
/// the keychain password, Cisco's profiles, quitting Cisco's window app
/// (AppKit), the persisted "owned" flag and the main-queue callbacks.
final class CiscoEngine {
    /// Settable only so the engine harness (scripts/cisco-engine-test.sh)
    /// can point it at a fake CLI; the App never changes it.
    static let realCliPath = "/opt/cisco/secureclient/bin/vpn"
    static var cliPath = realCliPath
    static let guiBundleID = "com.cisco.anyconnect.gui"

    static var isAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: cliPath)
    }

    struct Credentials {
        var entry: String
        var username: String
        var password: String
    }

    /// (state, detail) on the main queue.
    var onState: ((HelperClient.State, String) -> Void)?
    /// Terminal reason on the main queue: 1 = manual, 2 = rejected.
    var onTerminal: ((Int) -> Void)?
    /// Kill switch request (mode, tunnelIf, gatewayIps) on the main queue.
    var onKillSwitch: ((Int, String, [String]) -> Void)?
    /// Fresh credentials for every (re)connect: the Keychain is the
    /// only long-term store, nothing is cached here between attempts.
    var credentialsProvider: (() -> Credentials?)?

    /// `log show --predicate 'subsystem == "com.alwaysconnect.app"'`:
    /// state changes and Cisco's own state/notice/error lines (never the
    /// password, which Cisco does not echo).
    static let log = Logger(subsystem: "com.alwaysconnect.app", category: "cisco")
    /// A "Login failed" this soon after the password went in cannot be
    /// an approval that expired; treat it as a rejection (anti-lockout).
    /// Settable for the harness only.
    static var approvalTimeoutMinimum: TimeInterval = 20
    /// Fallback interval of the state check between routing changes;
    /// 0 = the engine's own (15 s). Settable for the harness only.
    static var monitorInterval: TimeInterval = 0
    static var physicalAvailability: () -> Bool = { PhysicalConnectivity.available() }

    /// The App started this Cisco session (DESIGN.md §25.4, F8):
    /// persisted, so a relaunch after a crash takes it back, while a
    /// session the user started in Cisco's own window is never adopted,
    /// armed, treated as a drop or disconnected at quit.
    static let ownedKey = "AlwaysConnectCiscoSessionOwned"

    private var completions: [() -> Void] = []
    private let completionLock = NSLock()
    /// The Rust engine and its thread exist only once Cisco is used
    /// (§32.15): in own-connection mode nothing of it runs.
    private var engine: OpaquePointer?
    private let engineLock = NSLock()
    private var handle: OpaquePointer {
        engineLock.lock(); defer { engineLock.unlock() }
        if let engine { return engine }
        let made = makeEngine()
        engine = made
        return made
    }
    private var existing: OpaquePointer? {
        engineLock.lock(); defer { engineLock.unlock() }
        return engine
    }

    var isManaging: Bool { existing.map(ac_cisco_is_managing) ?? false }
    var episodeRetries: Int { existing.map { Int(ac_cisco_episode_retries($0)) } ?? 0 }

    // MARK: - Public

    func connect() { ac_cisco_connect(handle) }

    func disconnect(completion: @escaping () -> Void) {
        completionLock.lock(); completions.append(completion); completionLock.unlock()
        ac_cisco_disconnect(handle)
    }

    /// The Helper restarted: send it the current kill switch again.
    func networkChanged() { existing.map(ac_cisco_network_changed) }

    func rearm() { existing.map(ac_cisco_rearm) }

    /// Launch / panel open: adopt a tunnel Cisco already has up (the
    /// App was restarted, the session never stopped).
    func refresh() {
        guard UserDefaults.standard.bool(forKey: Self.ownedKey) else { return }
        ac_cisco_refresh(handle)
    }

    // MARK: - The Rust engine's hooks

    private func makeEngine() -> OpaquePointer {
        let ctx = Unmanaged.passRetained(WeakBox(self)).toOpaque()
        var hooks = AcCiscoHooks(
            ctx: ctx,
            state: { ctx, state, detail in
                guard let engine = WeakBox.engine(ctx), let detail else { return }
                let text = String(cString: detail)
                let value = HelperClient.State(rawValue: Int(state)) ?? .disconnected
                DispatchQueue.main.async { engine.onState?(value, text) }
            },
            terminal: { ctx, code in
                guard let engine = WeakBox.engine(ctx) else { return }
                DispatchQueue.main.async { engine.onTerminal?(Int(code)) }
            },
            killSwitch: { ctx, mode, tun, gateways in
                guard let engine = WeakBox.engine(ctx) else { return }
                let t = tun.map { String(cString: $0) } ?? ""
                let g = gateways.map { String(cString: $0) }?.split(separator: ",").map(String.init) ?? []
                DispatchQueue.main.async { engine.onKillSwitch?(Int(mode), t, g) }
            },
            credentials: { ctx, entry, user, pass in
                guard let engine = WeakBox.engine(ctx), let c = engine.credentialsProvider?() else { return false }
                entry?.pointee = strdup(c.entry)
                user?.pointee = strdup(c.username)
                pass?.pointee = strdup(c.password)
                return true
            },
            profileHosts: { ctx in
                guard let engine = WeakBox.engine(ctx) else { return nil }
                var hosts = Array(CiscoProfiles.hostEntries().values)
                // The selected server may be a hand-added address (§21.13).
                if let entry = engine.credentialsProvider?()?.entry { hosts.append(CiscoProfiles.resolve(entry)) }
                return strdup(hosts.joined(separator: ","))
            },
            networkAvailable: { _ in CiscoEngine.physicalAvailability() },
            beforeLogin: { _ in CiscoEngine.quitCiscoGUI() },
            owned: { _, owned in UserDefaults.standard.set(owned, forKey: CiscoEngine.ownedKey) },
            log: { _, line in
                guard let line else { return }
                CiscoEngine.log.notice("\(String(cString: line), privacy: .public)")
            },
            disconnected: { ctx in
                guard let engine = WeakBox.engine(ctx) else { return }
                DispatchQueue.main.async {
                    engine.completionLock.lock()
                    let done = engine.completions.isEmpty ? nil : engine.completions.removeFirst()
                    engine.completionLock.unlock()
                    done?()
                }
            },
            release: { ctx in if let ctx { Unmanaged<WeakBox>.fromOpaque(ctx).release() } })
        return ac_cisco_new(Self.cliPath, UInt32(Self.approvalTimeoutMinimum * 1000),
                            UInt32(Self.monitorInterval * 1000), &hooks)!
    }

    private final class WeakBox {
        weak var engine: CiscoEngine?
        init(_ engine: CiscoEngine) { self.engine = engine }
        static func engine(_ ctx: UnsafeMutableRawPointer?) -> CiscoEngine? {
            ctx.flatMap { Unmanaged<WeakBox>.fromOpaque($0).takeUnretainedValue().engine }
        }
    }

    /// Only one Cisco client may hold the connect capability; the GUI
    /// app takes it at login. Ask it to quit (never force) before a
    /// CLI login.
    private static func quitCiscoGUI() {
        // The harness drives a fake CLI: never touch the real Cisco
        // window app of whoever runs the checks.
        guard cliPath == realCliPath else { return }
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: guiBundleID)
        guard !apps.isEmpty else { return }
        apps.forEach { $0.terminate() }
        for _ in 0..<20 where !apps.allSatisfy({ $0.isTerminated }) {
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    // MARK: - One-off CLI calls (Rust)

    struct RunResult {
        var status: Int32
        var output: String
    }

    /// Runs the Cisco CLI to completion.
    @discardableResult
    static func run(_ args: [String], input: String? = nil, timeout: TimeInterval = 30) -> RunResult {
        var status: Int32 = -1
        guard let raw = ac_cisco_run(cliPath, args.joined(separator: "\n"), input, UInt32(timeout * 1000), &status)
        else { return RunResult(status: -1, output: "") }
        defer { ac_string_free(raw) }
        return RunResult(status: status, output: String(cString: raw))
    }

    /// The last `>> state: X` the CLI printed.
    static func parseState(_ output: String) -> String? {
        guard let raw = ac_cisco_parse_state(output) else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }

    /// The tunnel interface holding the default route (routing socket,
    /// no `route` process), or nil.
    static func defaultRouteInterface() -> String? {
        guard let raw = ac_default_route_tunnel() else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }
}

struct AcCiscoHooks {
    var ctx: UnsafeMutableRawPointer?
    var state: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?) -> Void
    var terminal: @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void
    var killSwitch: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void
    var credentials: @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
                                     UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
                                     UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Bool
    var profileHosts: @convention(c) (UnsafeMutableRawPointer?) -> UnsafeMutablePointer<CChar>?
    var networkAvailable: @convention(c) (UnsafeMutableRawPointer?) -> Bool
    var beforeLogin: @convention(c) (UnsafeMutableRawPointer?) -> Void
    var owned: @convention(c) (UnsafeMutableRawPointer?, Bool) -> Void
    var log: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> Void
    var disconnected: @convention(c) (UnsafeMutableRawPointer?) -> Void
    var release: @convention(c) (UnsafeMutableRawPointer?) -> Void
}

@_silgen_name("ac_cisco_new")
func ac_cisco_new(_ cli: UnsafePointer<CChar>, _ approvalMinimumMs: UInt32, _ monitorMs: UInt32,
                  _ hooks: UnsafePointer<AcCiscoHooks>) -> OpaquePointer?
@_silgen_name("ac_cisco_connect")
func ac_cisco_connect(_ e: OpaquePointer)
@_silgen_name("ac_cisco_disconnect")
func ac_cisco_disconnect(_ e: OpaquePointer)
@_silgen_name("ac_cisco_rearm")
func ac_cisco_rearm(_ e: OpaquePointer)
@_silgen_name("ac_cisco_refresh")
func ac_cisco_refresh(_ e: OpaquePointer)
@_silgen_name("ac_cisco_is_managing")
func ac_cisco_is_managing(_ e: OpaquePointer) -> Bool
@_silgen_name("ac_cisco_episode_retries")
func ac_cisco_episode_retries(_ e: OpaquePointer) -> UInt32
@_silgen_name("ac_cisco_run")
func ac_cisco_run(_ cli: UnsafePointer<CChar>, _ args: UnsafePointer<CChar>, _ input: UnsafePointer<CChar>?,
                  _ timeoutMs: UInt32, _ status: UnsafeMutablePointer<Int32>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_cisco_parse_state")
func ac_cisco_parse_state(_ output: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_default_route_tunnel")
func ac_default_route_tunnel() -> UnsafeMutablePointer<CChar>?

@_silgen_name("ac_cisco_network_changed")
func ac_cisco_network_changed(_ e: OpaquePointer)
