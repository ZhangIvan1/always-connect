import Foundation
import Security

/// Helper-side XPC daemon (DESIGN.md §16.9).
///
/// Run as a LaunchDaemon (root) via `AlwaysConnectHelper daemon`. It
/// owns one CLIOrchestrator at a time and forwards its state to the
/// App over XPC. The daemon never stores credentials: they arrive per
/// connect call and live only in the engine's memory.
///
/// The session belongs to the daemon, not to an XPC connection: the
/// App quitting, crashing or relaunching only adds or removes a
/// status subscriber. Losing the UI is never a manual disconnect, so
/// it can never restore the local network (DESIGN.md §二十).
///
/// Client validation (DESIGN.md §36.3): only the App signed with the
/// same certificate as this daemon may connect (ClientRequirement). A
/// refused client is turned away at the listener, before any method
/// runs, and every message is checked again by audit token
/// (setCodeSigningRequirement): an arbitrary local process cannot
/// drive the root daemon's pf rules or tunnel. A daemon without a
/// signing certificate (ad-hoc build) accepts nobody; local builds are
/// signed with scripts/dev-signing-identity.sh's identity.
final class HelperDaemon: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let session = HelperSession()

    init(machServiceName: String = AlwaysConnectHelperMachService) {
        listener = NSXPCListener(machServiceName: machServiceName)
        super.init()
        listener.delegate = self
    }

    func shutdown() {
        session.shutdown()
        Self.endOwnProcesses()
    }

    func start() {
        // A crashed predecessor's openconnect (F6): the
        // engine that ran them is gone, nothing will ever stop them.
        Self.endOwnProcesses(includeChildren: false)
        // The network gate (DESIGN.md §25.2): adopt a hold from this
        // boot (blocking set, grace clock running until an App is
        // back), drop one from an earlier boot. A hold that outlives
        // its App is released as on a quit.
        NetworkGuard.shared.onGraceExpired = { [weak self] in
            guard let self else { return }
            self.session.releaseEverything(reason: NetworkGuard.Reason.appGone)
            self.startQuickIdleExit()
        }
        NetworkGuard.shared.adoptAtStart()
        // Routes and DNS entries a dead session left (§26.3, §26.5).
        let direct = DirectRoutes.undoAtStart(supportDir: CLIOrchestrator.defaultSupportDir,
                                              noRoutes: TestSeam.isActive)
        if direct != "none" { HelperSession.log("direct routes at start: \(direct)") }
        if let script = try? VpncScript.install() {
            let done = CLIOrchestrator.undoJournalAtStart(scriptPath: script)
            if done != "none" { HelperSession.log("route journal at start: \(done)") }
        }
        listener.resume()
        startIdleExit()
    }

    /// Quitting the App means nothing of ours keeps running (DESIGN.md
    /// §21.5, §23.11): with no App attached, no tunnel, no kill switch
    /// and no held network, the daemon exits cleanly. launchd starts
    /// it again on demand (MachServices) and restarts it only after a
    /// crash (KeepAlive Crashed = true, DESIGN.md §25.6).
    ///
    /// The last App leaving (a quit invalidates its connection) starts
    /// a 1 s check, so the daemon is gone a few seconds after the App
    /// instead of 30-45 s later; an openconnect still logging out keeps
    /// the session non-idle until it has exited. The 15 s check stays
    /// as the fallback (a daemon started at boot with no App at all).
    private var idleTimer: DispatchSourceTimer?
    private var quickTimer: DispatchSourceTimer?
    private let idleQueue = DispatchQueue(label: "com.alwaysconnect.helper.idle")
    private var idleChecks = 0
    private var quickChecks = 0

    private func startIdleExit() {
        session.onLastClientGone = { [weak self] in self?.startQuickIdleExit() }
        let timer = DispatchSource.makeTimerSource(queue: idleQueue)
        timer.schedule(deadline: .now() + 15, repeating: 15, leeway: .seconds(3))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.idleChecks = self.isFullyIdle ? self.idleChecks + 1 : 0
            if self.idleChecks >= 2 { self.exitIdle() }
        }
        timer.resume()
        idleTimer = timer
    }

    private var isFullyIdle: Bool {
        session.isIdle && KillSwitch.shared.isOff && !CLIOrchestrator.localNetworkHeld()
    }

    /// Exposed for the grace path; idempotent while a check runs.
    func checkIdleSoon() { startQuickIdleExit() }

    /// Two idle checks in a row, 1 s apart, then exit. Gives up after
    /// a minute (a held network or an App reattaching keeps it busy;
    /// the 15 s check takes over from there).
    private func startQuickIdleExit() {
        idleQueue.async {
            guard self.quickTimer == nil else { return }
            self.quickChecks = 0
            var ticks = 0
            let timer = DispatchSource.makeTimerSource(queue: self.idleQueue)
            timer.schedule(deadline: .now() + 1, repeating: 1)
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                ticks += 1
                self.quickChecks = self.isFullyIdle ? self.quickChecks + 1 : 0
                if self.quickChecks >= 2 { self.exitIdle() }
                if ticks >= 60 {
                    self.quickTimer?.cancel()
                    self.quickTimer = nil
                }
            }
            timer.resume()
            self.quickTimer = timer
        }
    }

    private func exitIdle() {
        HelperSession.log("idle, exiting")
        Self.endOwnProcesses()
        exit(0)
    }

    /// Before the daemon exits (idle, or SIGTERM from launchd) and when
    /// it starts: its own children (openconnect, a vpnc-script, a pfctl
    /// or route call), and any openconnect an earlier run left behind —
    /// found by our installed vpnc-script on its command line
    /// (`--script`) (§23.7, §23.11, F6).
    static func endOwnProcesses(includeChildren: Bool = true) {
        var targets = includeChildren ? ProcessSweep.descendants() : []
        for (program, marker) in leftoverMarkers {
            for pid in ProcessSweep.pids(commandContaining: marker) where !targets.contains(pid) {
                // Our exact arguments AND the program: a `tail -f` on the
                // log or a recover running the script is not a leftover.
                guard let line = ProcessSweep.commandLine(of: pid), line.contains(program) else { continue }
                targets.append(pid)
            }
        }
        // SIGHUP: an openconnect that outlived a crashed service leaves
        // without logging the session off, so the App's reconnect can
        // reuse the cookie (§30.3; SIGTERM cost a phone approval).
        let killed = ProcessSweep.terminate(targets, grace: 2, signal: includeChildren ? SIGTERM : SIGHUP)
        if !targets.isEmpty {
            HelperSession.log("ended \(targets.count) leftover process(es), \(killed.count) by SIGKILL")
        }
    }

    /// (program, exact argument) pairs of what an earlier run started:
    /// openconnect with our installed vpnc-script.
    static var leftoverMarkers: [(String, String)] {
        let dir = CLIOrchestrator.defaultSupportDir
        let script = dir.appendingPathComponent("alwaysconnect-vpnc.sh").path
        return [("openconnect", "--script=" + CLIOrchestrator.shellQuoted(script))]
    }

    // MARK: - NSXPCListenerDelegate

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        guard let requirement = ClientRequirement.forThisProcess else {
            fputs("HelperDaemon: refused client: this background service has no signing "
                  + "certificate (ad-hoc build); sign with scripts/dev-signing-identity.sh\n", stderr)
            return false
        }
        guard ClientRequirement.runningProcess(pid: connection.processIdentifier,
                                               satisfies: requirement) else {
            fputs("HelperDaemon: refused client pid \(connection.processIdentifier): "
                  + "not the App signed like this service\n", stderr)
            return false
        }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: AlwaysConnectHelperProtocol.self)
        connection.exportedObject = session
        connection.remoteObjectInterface = NSXPCInterface(
            with: AlwaysConnectHelperClientProtocol.self)
        // Unsubscribe only: the engine keeps running (and pf keeps
        // holding) whether or not any App is attached.
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.session.removeClient(connection)
        }
        connection.resume()
        session.addClient(connection)
        return true
    }
}

/// The daemon's one VPN session: translates XPC calls into engine
/// actions and engine state into XPC pushes to every attached App.
/// All mutable state lives on `queue`; XPC replies and engine
/// callbacks arrive on arbitrary threads and hop onto it.
final class HelperSession: NSObject, AlwaysConnectHelperProtocol {
    private let queue = DispatchQueue(label: "com.alwaysconnect.helper.session")
    private var clients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var engine: CLIOrchestrator?
    /// The parameters of the engine currently running (nil once it
    /// reaches a terminal state). A repeated connect with the same
    /// parameters — the App relaunching and auto-connecting — joins
    /// the running session instead of tearing it down.
    private var activeParameters: [String]?
    /// Set by prepareRelay, used by the next connect (DESIGN.md §二十三).
    private var relay: RelaySettings?
    /// Names that go out the local network (DESIGN.md §26.5), from the App.
    private var directDomains: [String] = []
    /// The App's direct networks (its list and the local network), kept
    /// for the next engine: one that starts takes over a held set at
    /// once and must pass the LAN from its first second (§30.1).
    private var allowNetworks: [String] = []
    /// 断线保护 for the own connection (DESIGN.md §26.19), from the App.
    private var dropProtection = true
    private var lastStateCode = 0
    private var lastDetail = ""
    /// Last terminal reason code + drop-episode retries, for
    /// getSessionInfo (DESIGN.md §十九): 0 = none/ongoing,
    /// 1 = manual stop, 2 = credentials rejected, 3 = attempts
    /// exhausted. Reset on every new connect.
    private var lastReasonCode = 0
    private var lastRetryCount = 0

    /// One timestamped line to the daemon's stderr (launchd's
    /// StandardErrorPath when configured). Engine details only:
    /// never credentials, never raw child output.
    static func log(_ line: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardError.write(Data("\(stamp) \(line)\n".utf8))
    }

    /// Keeps the daemon's log (launchd's StandardErrorPath) bounded
    /// (§32.3): it only ever grew, and the dev install logs every
    /// redacted openconnect line of every login. Over `limit` bytes it
    /// is cut to its last `keep` bytes, from the start of a line. Run at
    /// start and on every connect; stderr that is not a file is left.
    static func trimLog(limit: Int = 4_000_000, keep: Int = 1_000_000) {
        var info = stat()
        guard fstat(STDERR_FILENO, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              Int(info.st_size) > limit else { return }
        let size = Int(info.st_size)
        // launchd opens the file write-only: read it through its path.
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(STDERR_FILENO, F_GETPATH, &path) == 0 else { return }
        let reader = open(path, O_RDONLY)
        guard reader >= 0 else { return }
        var tail = [UInt8](repeating: 0, count: keep)
        let read = pread(reader, &tail, keep, off_t(size - keep))
        Darwin.close(reader)
        guard read > 0 else { return }
        var kept = tail.prefix(read)
        if let newline = kept.firstIndex(of: 0x0A) { kept = kept[(newline + 1)...] }
        guard ftruncate(STDERR_FILENO, 0) == 0 else { return }
        lseek(STDERR_FILENO, 0, SEEK_SET)
        _ = kept.withUnsafeBytes { write(STDERR_FILENO, $0.baseAddress, $0.count) }
        log("log trimmed: was \(size) bytes, kept the last \(kept.count)")
    }

    /// No App attached and no session running or retrying.
    var isIdle: Bool {
        queue.sync { clients.isEmpty && activeParameters == nil }
    }

    func addClient(_ connection: NSXPCConnection) {
        let app = AppRelauncher.App(pid: connection.processIdentifier,
                                    uid: connection.effectiveUserIdentifier)
        queue.async {
            self.clients[ObjectIdentifier(connection)] = connection
            self.ownerAttached(app: app)
            self.push(to: connection, state: self.lastStateCode, detail: self.lastDetail)
        }
    }

    /// Called (on `queue`) when the last App connection goes away.
    var onLastClientGone: (() -> Void)?

    func removeClient(_ connection: NSXPCConnection) {
        queue.async {
            guard self.clients.removeValue(forKey: ObjectIdentifier(connection)) != nil else { return }
            if self.clients.isEmpty { self.ownerGone() }
        }
    }

    private let relauncher = AppRelauncher()

    /// On `queue`. An App is attached: the gate's hold has an owner.
    func ownerAttached(app: AppRelauncher.App?) {
        if let app { relauncher.remember(app) }
        NetworkGuard.shared.ownerAttached()
    }

    /// Session harness only: an App attaching or vanishing, no XPC.
    func harnessOwner(attached: Bool, appPath: String? = nil) {
        queue.sync {
            if attached {
                ownerAttached(app: appPath.map { AppRelauncher.App(path: $0, uid: getuid()) })
            } else {
                ownerGone()
            }
        }
    }

    /// On `queue`. The last App went away. A quit releases first, so a
    /// hold still in place means the App did not quit on purpose
    /// (crash, force quit): start the gate's grace clock and try to
    /// bring the App back (DESIGN.md §25.2).
    func ownerGone() {
        // After the user's own release (a quit, a disconnect) the App
        // leaving is expected: no relaunch, even if a late engine event
        // briefly re-created a hold (it is released by the engine's own
        // wind-down).
        let sessionActive = activeParameters != nil && !userReleased
        NetworkGuard.shared.ownerLost(sessionActive: sessionActive)
        if !userReleased, NetworkGuard.shared.isHolding || sessionActive {
            relauncher.relaunch()
        }
        onLastClientGone?()
    }

    /// Set by the user's release, cleared by the next connect or arm.
    private var userReleased = false

    func connect(
        server: String,
        group: String,
        username: String,
        password: String,
        withReply reply: @escaping (Bool) -> Void
    ) {
        queue.async {
            // A new relay (the App restarted it: new pin, maybe a new
            // gateway address) must restart the engine too.
            let parameters = [server, group, username, password,
                              self.relay?.gatewayIp ?? "", self.relay?.serverPin ?? ""]
            if self.activeParameters == parameters {
                reply(true)
                return
            }
            self.startEngine(server: server, group: group, username: username,
                             password: password, parameters: parameters, reply: reply)
        }
    }

    /// On `queue`. Different parameters while an engine runs (the
    /// Credentials page's test connection) replace it, as before.
    /// An engine still winding down (a replacement waits for it), and
    /// the start that waits: a later connect or a disconnect bumps the
    /// generation, so a superseded start never runs.
    private var stoppingEngine: CLIOrchestrator?
    private var startGeneration = 0

    private func startEngine(
        server: String, group: String, username: String, password: String,
        parameters: [String], reply: @escaping (Bool) -> Void
    ) {
        startGeneration += 1
        userReleased = false
        let generation = startGeneration
        // Replacing a running engine (new server, new relay): stop it
        // the whole way first — routes back, its own pf hold released —
        // then start the new one (§25.7). Starting at once left the old
        // blocking set and missing default route in the new one's way.
        var sameLogin = false
        if let previous = engine, let running = activeParameters {
            stoppingEngine = previous
            // Same server, group and user: only the App's relay changed
            // (the App was reopened, or picked another gateway address).
            sameLogin = Array(running.prefix(3)) == Array(parameters.prefix(3))
        }
        engine = nil
        activeParameters = nil
        if stoppingEngine != nil, dropProtection, NetworkGuard.shared.isHolding {
            // Fail-closed handover (§30.1): the outgoing engine's release
            // is ignored from here, the new one takes the set over at its
            // start. Before, the network was open for the whole new login.
            NetworkGuard.shared.supersedeOwnHolders()
        }
        if let stopping = stoppingEngine {
            var started = false
            let begin: () -> Void = { [weak self] in
                guard let self else { return }
                self.queue.async {
                    guard !started else { return }
                    started = true
                    if self.stoppingEngine === stopping { self.stoppingEngine = nil }
                    guard generation == self.startGeneration else { reply(false); return }
                    self.startEngineNow(server: server, group: group, username: username,
                                        password: password, parameters: parameters, reply: reply)
                }
            }
            stopping.stop(keepSession: sameLogin, completion: begin)
            // Fallback only: the old engine's own restore must not land
            // on top of the new session's routes (§30.3).
            queue.asyncAfter(deadline: .now() + 20) { begin() }
            return
        }
        startEngineNow(server: server, group: group, username: username,
                       password: password, parameters: parameters, reply: reply)
    }

    private func startEngineNow(
        server: String, group: String, username: String, password: String,
        parameters: [String], reply: @escaping (Bool) -> Void
    ) {
        lastReasonCode = 0
        lastRetryCount = 0
        let script: String
        do {
            script = try VpncScript.install()
        } catch {
            reply(false)
            return
        }
        var config = CLIOrchestrator.Config(
            server: server,
            group: group,
            username: username,
            password: password,
            openconnectPath: nil,
            scriptPath: script,
            cookieStore: CookieStore(fileURL: CookieStore.defaultFileURL),
            physicalIf: "en0",
            allowNetworks: allowNetworks,  // the App's last push (§27.1, §30.1)
            maxAttempts: nil,
            noRoutes: TestSeam.isActive,
            supportDir: nil
        )
        config.relay = relay
        // Own connection: the domain split's forwarder runs (§26.5).
        if relay != nil { config.directDomains = directDomains }
        config.dropProtection = dropProtection
        // Redacted child output into the daemon's log (launchd
        // StandardErrorPath), only when the plist opts in: the dev
        // install does, to record the real gateway's output shapes
        // (approval wait, rejection text) that DESIGN §16.5 waits on.
        config.debugChildOutput =
            ProcessInfo.processInfo.environment["ALWAYSCONNECT_DEBUG_CHILD_OUTPUT"] == "1"
        Self.trimLog()
        let engine = CLIOrchestrator(config: config)
        engine.onState = { [weak self, weak engine] state, detail in
            guard let self, let engine else { return }
            let retries = engine.episodeRetries
            Self.log("state=\(state.rawValue) \(detail)")
            self.queue.async {
                guard self.engine === engine else { return }
                self.lastStateCode = state.rawValue
                self.lastDetail = detail
                self.lastRetryCount = retries
                self.push(state: state.rawValue, detail: detail)
            }
        }
        engine.onTerminal = { [weak self, weak engine] reason in
            guard let self, let engine else { return }
            let retries = engine.episodeRetries
            let error = engine.lastError
            Self.log("terminal=\(reason)")
            self.queue.async {
                guard self.engine === engine else { return }
                // A finished engine is gone: keeping the object made the
                // next disconnect (in Cisco mode) call its no-op stop()
                // instead of releasing the kill switch (§25.1, F1).
                self.engine = nil
                self.activeParameters = nil
                switch reason {
                case .stoppedManual: self.lastReasonCode = 1
                case .authFailure: self.lastReasonCode = 2
                case .attemptsExhausted: self.lastReasonCode = 3
                case .componentMissing: self.lastReasonCode = 4
                }
                self.lastRetryCount = retries
                // Terminal state is already reflected by the last pushed
                // state + detail; the App maps authFailure to its error row.
                if reason == .authFailure, let error {
                    self.push(state: self.lastStateCode, detail: error)
                }
            }
        }
        self.engine = engine
        activeParameters = parameters
        engine.start()
        reply(true)
    }

    /// The user asked for the direct network back: every holder lets
    /// go, whatever ran before in this service's lifetime (§25.1, F1).
    func disconnect(withReply reply: @escaping () -> Void) {
        queue.async {
            self.releaseEverythingLocked(reason: NetworkGuard.Reason.user)
            reply()
        }
    }

    /// The same, when the gate's grace ended with no App back.
    func releaseEverything(reason: String) {
        queue.sync {
            // The grace callback hops queues; an App that attached in
            // between keeps its session.
            if reason == NetworkGuard.Reason.appGone, !clients.isEmpty { return }
            releaseEverythingLocked(reason: reason)
        }
    }

    /// On `queue`. pf first — the network is direct the moment this
    /// returns — then the parts that take their time.
    private func releaseEverythingLocked(reason: String) {
        startGeneration += 1 // a replacement waiting to start never does
        if reason == NetworkGuard.Reason.user { userReleased = true }
        NetworkGuard.shared.release(holder: nil, reason: reason)
        // The Cisco kill switch, always: an own-connection engine
        // object must never stand in for it.
        KillSwitch.shared.disarm()
        if let engine, activeParameters != nil {
            // A running own connection restores routes itself once
            // openconnect has logged out.
            engine.stop()
        } else {
            engine = nil
            activeParameters = nil
            // No engine running: a Cisco session, or a service
            // restarted under a held set (DESIGN.md §20.4, §二十一).
            if let script = try? VpncScript.install() {
                CLIOrchestrator.restoreLocalNetworkWithoutEngine(scriptPath: script, reason: reason)
            }
        }
    }

    func setDirectDomains(_ domains: [String], withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            // Rules as the App expanded them (§26.13); SplitRules ignores
            // what it does not understand.
            self.directDomains = domains.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            self.engine?.updateDirectDomains(self.directDomains)
            reply(true)
        }
    }

    func setDropProtection(_ on: Bool, withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            self.dropProtection = on
            if let engine = self.engine {
                engine.updateDropProtection(on)
            } else if !on, let held = NetworkGuard.shared.held, held.holder != NetworkGuard.ciscoHolder {
                // Switched off with no engine to ask: a set a restarted
                // service adopted or a refused login left (§30.1) goes
                // now, as the switch promises.
                if let script = try? VpncScript.install() {
                    CLIOrchestrator.restoreLocalNetworkWithoutEngine(scriptPath: script,
                                                                     reason: NetworkGuard.Reason.user)
                }
            }
            reply(true)
        }
    }

    func getSplitActivity(withReply reply: @escaping ([String], Int, Bool) -> Void) {
        queue.async {
            guard let engine = self.engine else { reply([], 0, false); return }
            let (entries, addresses) = engine.splitActivity()
            reply(entries, addresses, true)
        }
    }

    func getConnections(withReply reply: @escaping (String) -> Void) {
        queue.async {
            let engine = self.engine
            let cisco = KillSwitch.shared.snapshot
            DispatchQueue.global(qos: .userInitiated).async {
                let fallback = cisco?.gatewayIps ?? []
                reply(engine?.connectionsJSON(fallbackGateways: fallback)
                      ?? CLIOrchestrator.connectionsJSONWithoutEngine(gateways: fallback))
            }
        }
    }

    func updateAllowNetworks(_ networks: [String], withReply reply: @escaping (Bool) -> Void) {
        KillSwitch.shared.updateAllowNetworks(networks)
        queue.async {
            let valid = networks.map { $0.trimmingCharacters(in: .whitespaces) }.filter { isValidCIDR($0) }
            self.allowNetworks = valid
            guard let engine = self.engine else {
                // Held with no engine (a refused login, §30.1): the new
                // LAN gets through the held set too.
                NetworkGuard.shared.updateHeldAllowNetworks(valid)
                reply(true)
                return
            }
            engine.updateAllowNetworks(networks)
            reply(true)
        }
    }

    func getSessionInfo(withReply reply: @escaping (Int, Int) -> Void) {
        queue.async { reply(self.lastReasonCode, self.lastRetryCount) }
    }

    func getStatus(withReply reply: @escaping (Int, String) -> Void) {
        queue.async { reply(self.lastStateCode, self.lastDetail) }
    }

    func getNetworkHeld(withReply reply: @escaping (Bool) -> Void) {
        queue.async { reply(CLIOrchestrator.localNetworkHeld()) }
    }

    func getLastRelease(withReply reply: @escaping (String, Double) -> Void) {
        let last = NetworkGuard.shared.lastRelease
        reply(last?.reason ?? "", last?.at.timeIntervalSince1970 ?? 0)
    }

    /// SIGTERM from launchd: take the openconnect child down too.
    func shutdown() {
        let current = queue.sync { engine }
        current?.killChild()
    }

    func prepareRelay(gatewayIp: String, serverPin: String,
                      withReply reply: @escaping (String) -> Void) {
        queue.async {
            guard !gatewayIp.isEmpty else {
                self.relay = nil
                reply("")
                return
            }
            var v4 = in_addr()
            guard inet_pton(AF_INET, gatewayIp, &v4) == 1, RelaySettings.isValidPin(serverPin),
                  let files = try? RelayClientIdentity.ensure(supportDir: CLIOrchestrator.defaultSupportDir)
            else {
                Self.log("prepareRelay rejected")
                reply("")
                return
            }
            self.relay = RelaySettings(
                gatewayIp: gatewayIp, serverPin: serverPin,
                certificatePath: files.certificatePath, keyPath: files.keyPath)
            Self.log("prepareRelay ok")
            reply(files.certificatePEM)
        }
    }

    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String],
                       withReply reply: @escaping (Bool, String) -> Void) {
        guard let parsed = KillSwitch.Mode(rawValue: mode) else {
            reply(false, "unknown kill switch mode")
            return
        }
        if parsed != .off { queue.async { self.userReleased = false } }
        KillSwitch.shared.set(mode: parsed, tunnelIf: tunnelIf,
                              gatewayIps: gatewayIps, reply: reply)
    }

    func evaluateRule(
        app: String,
        domain: String,
        ip: String,
        rulesJSON: String,
        defaultMode: Int,
        withReply reply: @escaping (Int, String) -> Void
    ) {
        let (direction, reason) = RuleEvaluator.evaluate(
            app: app, domain: domain, ip: ip,
            rulesJSON: rulesJSON, defaultMode: defaultMode)
        reply(direction, reason)
    }

    func getStats(withReply reply: @escaping (Int64, Int64, String) -> Void) {
        queue.async {
            guard let tunnelIf = self.engine?.tunnelInterface else {
                reply(0, 0, "")
                return
            }
            let (bytesIn, bytesOut) = SystemChecks.interfaceBytes(tunnelIf)
            reply(bytesIn, bytesOut, tunnelIf)
        }
    }

    func runLeakCheck(withReply reply: @escaping (String) -> Void) {
        queue.async {
            let engine = self.engine
            // Cisco engine (DESIGN.md §二十一): no engine of ours, the
            // kill switch knows the tunnel and the gateways.
            let cisco = engine?.tunnelInterface == nil ? KillSwitch.shared.snapshot : nil
            let items = SystemChecks.runLeakCheck(
                tunnelIf: engine?.tunnelInterface ?? cisco?.tunnelIf,
                // Only the live session's server (listed first) must
                // route via the physical interface; the other gateways
                // in the allowlist are spares that may route anywhere.
                gatewayIps: engine?.gatewayAddresses ?? Array((cisco?.gatewayIps ?? []).prefix(1)),
                physicalIf: engine?.physicalInterface ?? cisco?.physicalIf ?? "en0",
                tunnelDns: engine?.tunnelDnsServers ?? [])
            let data = (try? JSONEncoder().encode(items)) ?? Data("[]".utf8)
            reply(String(data: data, encoding: .utf8) ?? "[]")
        }
    }

    /// On `queue`.
    private func push(state: Int, detail: String) {
        for connection in clients.values {
            push(to: connection, state: state, detail: detail)
        }
    }

    private func push(to connection: NSXPCConnection, state: Int, detail: String) {
        guard let proxy = connection.remoteObjectProxy
                as? AlwaysConnectHelperClientProtocol
        else { return }
        proxy.statusChanged(state: state, detail: detail)
    }
}
