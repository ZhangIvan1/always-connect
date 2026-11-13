import AppKit
import Foundation
import Network

/// App-side client for the privileged Helper (DESIGN.md §16.9).
///
/// The panel's state source is Helper-reported state over XPC, never
/// NEVPNStatus. Credentials come from the Keychain and are sent over
/// XPC once per connect; the Helper holds them in memory only.
///
/// Connection lifecycle: the App attaches at launch and on every panel
/// open (getStatus), so a session the Helper kept running while the
/// App was away shows up immediately. helperAvailable is true only
/// once the Helper has actually answered or pushed, and drops to false
/// on interruption/invalidation (the panel's red "Helper 未运行" line).
/// When launchd restarts a crashed Helper (interruption) while the
/// session was active, the App re-sends the stored credentials ONCE
/// (DESIGN.md §20.9): the restarted daemon reloads the blocking pf set
/// but has no engine, so without this the user would sit blocked with
/// no reconnect. A Helper that is simply missing (invalidation) is
/// never retried, so it cannot spin a silent loop.
final class HelperClient: NSObject, ObservableObject, AlwaysConnectHelperClientProtocol {
    static let shared = HelperClient()

    enum State: Int {
        case disconnected = 0
        case connecting = 1
        case authenticating = 2
        case awaitingApproval = 3
        case connected = 4
        case reconnecting = 5
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var detail: String = ""
    @Published private(set) var lastError: String?
    /// The own connection stopped itself after its self-check found no
    /// usable network (§26.11); shown on the panel until the next connect.
    @Published private(set) var autoStopNotice: String?
    private let connectionCheck = ConnectionCheck()
    @Published private(set) var helperAvailable = false
    /// When the current connection was established (nil when not connected).
    @Published private(set) var connectedSince: Date?
    /// Most recent completed drop, if any.
    @Published private(set) var lastDrop: DropRecord?
    @Published private(set) var dropHistory: [DropRecord] = []
    /// Terminal reason code from getSessionInfo (DESIGN.md §十九):
    /// 0 = none/ongoing, 1 = manual stop, 2 = credentials rejected,
    /// 3 = attempts exhausted, 4 = component missing, 5 = phone
    /// confirmation failed (§43). 0 also means "old Helper / unknown".
    @Published private(set) var terminalReasonCode = 0
    /// Retries in the current drop episode (0 when connected or
    /// never dropped). Drives the panel's "第 N 次重连" line.
    @Published private(set) var dropRetryCount = 0 {
        didSet { dropTracker.noteRetries(dropRetryCount) }
    }
    /// Disconnected but the local network is still held closed
    /// (DESIGN.md §20.9): credentials rejected mid-drop, or a Helper
    /// restart reloaded the blocking set. The switch stays on so the
    /// user can confirm the manual disconnect that restores it.
    @Published private(set) var networkHeld = false {
        didSet { updateHoldReminder() }
    }
    /// The restore did not get an answer from the background service
    /// in 5 s (DESIGN.md §25.5, F9): the panel then offers the forced
    /// restore behind the administrator password.
    @Published private(set) var helperUnresponsive = false
    /// Kill switch not in force (Cisco engine): shown in red on the
    /// panel. Nil when pf is applied or nothing needs it.
    @Published private(set) var pfWarning: String?

    /// Drop episodes → DropRecords (DESIGN.md §21.22).
    private var dropTracker = DropEpisodeTracker()
    /// The record a just-ended episode produced, waiting for the
    /// engine's terminal reason (it arrives after "disconnected"), and
    /// that episode's own retries (a sleep record sums several).
    private var recordAwaitingTerminal: (id: DropRecord.ID, episodeRetries: Int)?
    private var sleepObservers: [NSObjectProtocol] = []

    /// Credentials are complete when a username is stored and the
    /// Keychain holds a password for it. The panel reads this on open
    /// (the popover view is rebuilt on every toggle).
    var hasCredentials: Bool {
        guard let username = ProfileStore.loadUsername(), !username.isEmpty else {
            return false
        }
        return KeychainStore.exists(server: KeychainStore.accountKey, username: username)
            || KeychainStore.exists(server: ProfileStore.loadProfile().server, username: username)
    }

    /// One-line status text (UI-DESIGN.md §三), shared by the panel,
    /// the Credentials page, and Diagnostics.
    var stateLine: String {
        switch state {
        case .disconnected:
            if onDemandPaused && !networkHeld { return "已断开 · 按需连接（规则：\(onDemandRuleName ?? "未命名")）" }
            return networkHeld ? "未连接，网络仍处暂停（断开即恢复直连）" : "未连接（直连网络）"
        case .connecting: return "连接中…"
        case .authenticating:
            // The own connection's login waits on the phone silently
            // (no approval line from openconnect yet, §二十三).
            return usesCisco ? "认证中…" : "登录中…（手机收到批准请求时请点批准）"
        case .awaitingApproval: return "等你在手机上确认登录"
        case .connected: return "已连接 · \(ProfileStore.loadProfile().server)"
        case .reconnecting:
            let retries = dropRetryCount > 0 ? "（第 \(dropRetryCount) 次）" : ""
            if !protectsDrops {
                return "已断开，正在重连（断线保护已关，流量走本地网络）" + retries
            }
            return "已断开，网络已拦截，正在重连" + retries
        }
    }

    @Published private(set) var onDemandPaused = false
    @Published private(set) var onDemandRuleName: String?
    private let networkFacts = NetworkFacts()
    private let onDemand = OnDemandController()
    private var onDemandProbe: OnDemandNetworkProbe?
    private let onDemandDisconnect = OnDemandDisconnect()
    private let protection = OnDemandProtection()
    private var onDemandDebounce: DispatchWorkItem?
    private var onDemandPathReady = false
    private var pendingOnDemandFacts: (Bool, (OnDemandFacts) -> Void)?

    private func setupOnDemand() {
        onDemand.active = { [weak self] in self?.switchIsOn == true }
        onDemand.autoConnect = { ProfileStore.loadProfile().autoConnectOnLaunch }
        onDemand.collect = { [weak self] ssid, done in
            guard let self else { return }
            if self.onDemandPathReady {
                done(self.networkFacts.collect(path: self.pathMonitor.currentPath, needsSSID: ssid))
            } else {
                self.pendingOnDemandFacts = (ssid, done)
            }
        }
        onDemand.probe = { [weak self] probe, facts, done in
            let task = OnDemandNetworkProbe()
            self?.onDemandProbe = task
            task.run(probe, interface: self?.networkFacts.interface, servers: facts.servers) { result in
                if self?.onDemandProbe === task { self?.onDemandProbe = nil }
                done(result)
                _ = task  // retain until the bounded operation completes
            }
        }
        onDemand.cancelProbe = { [weak self] in
            self?.onDemandDebounce?.cancel()
            self?.onDemandProbe?.cancel()
            self?.onDemandProbe = nil
        }
        setupOnDemandDisconnection()
        onDemand.disconnect = { [weak self] in
            self?.awaitingRestartRecovery = false
            self?.protection.invalidate(.onDemandStop)
            self?.onDemandDisconnect.begin()
        }
        onDemand.holdLaunch()
        onDemand.waiting = { [weak self] in self?.onDemandDisconnect.waiting == true }
        onDemand.connect = { [weak self] in _ = self?.startStoredConnection() }
        onDemand.stopUser = { [weak self] in self?.disconnect() }
        onDemand.recheck = { [weak self] in self?.onDemandDisconnect.recheck() }
        onDemand.debounce = { [weak self] delay, done in
            let work = DispatchWorkItem(block: done)
            self?.onDemandDebounce = work
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
        }
        onDemand.refreshService = { [weak self] in
            self?.awaitingRestartRecovery = false
            self?.markHelperReachable()
            self?.onDemandDisconnect.recover()
            self?.refreshStatus()
        }
        onDemand.changed = { [weak self] in
            guard let self else { return }
            self.onDemandPaused = self.onDemand.state.paused
            self.onDemandRuleName = self.onDemand.ruleName
        }
        networkFacts.networkChanged = { [weak self] in self?.scheduleOnDemandEvaluation() }
        onDemandSettingsChanged()
    }

    /// These callbacks are also exercised by the source-wiring fault harness.
    private func setupOnDemandDisconnection() {
        onDemandDisconnect.stop = { [weak self] token, localStopped, replied in
            guard let self else { return }
            self.disconnect(
                completion: replied,
                onLocalStopped: localStopped,
                isCurrent: { [weak self] in self?.onDemandDisconnect.isCurrent(token) == true })
        }
        onDemandDisconnect.usesCisco = { [weak self] in self?.usesCisco == true }
        onDemandDisconnect.verifyIdle = { [weak self] timeout, done in self?.verifyOnDemandIdle(timeout: timeout, done) }
        onDemandDisconnect.needsAttention = { [weak self] in self?.helperUnresponsive = true }
        onDemandDisconnect.restartRecovery = { [weak self] active in
            self?.scheduleRestartRecovery(wasActive: active)
        }
        onDemandDisconnect.settled = { [weak self] in
            self?.helperUnresponsive = false
            self?.onDemand.disconnectSettled()
        }
    }

    /// Report raw observations. Rust checks the generation, deadline and idle conditions.
    /// Both RPCs use one proxy, fencing the preceding disconnect on the service queue.
    private func verifyOnDemandIdle(timeout: TimeInterval, _ done: @escaping (Int, Bool, String?) -> Void) {
        ensureConnection { proxy in
            proxy.getStatus { code, _ in
                proxy.getNetworkHeld { held in
                    DispatchQueue.main.async {
                        // Keep all reducer calls and App state reads on the main queue.
                        // Only the bounded CLI I/O itself runs on the utility queue.
                        if self.usesCisco {
                            DispatchQueue.global(qos: .utility).async {
                                let result = CiscoEngine.run(["state"], timeout: timeout)
                                let state = result.status == 0 ? CiscoEngine.parseState(result.output) : "Unknown"
                                DispatchQueue.main.async { done(code, held, state) }
                            }
                        } else {
                            done(code, held, nil)
                        }
                    }
                }
            }
        }
    }

    func onDemandSettingsChanged() {
        if AppRole.isSettings {
            SettingsLink.shared.send("onDemandChanged")
            return
        }
        onDemandDebounce?.cancel()
        pendingOnDemandFacts = nil
        let settings = ProfileStore.loadAppSettings()
        networkFacts.watch(enabled: settings.onDemandEnabled == true)
        onDemand.configure(enabled: settings.onDemandEnabled == true, rules: settings.onDemandRules ?? [])
        onDemandDisconnect.recheck()
    }

    private func scheduleOnDemandEvaluation() {
        onDemand.networkWillChange()
    }

    /// The password, read from the Keychain at most once per account per
    /// App run (DESIGN.md §21.12): every read by a rebuilt, ad-hoc
    /// signed App can raise the keychain password prompt, and a drop's
    /// re-login retries would otherwise prompt again and again. Memory
    /// only; dropped when the account is edited.
    private let passwordLock = NSLock()
    private var cachedPassword: (key: String, value: String)?

    func storedPassword(server: String, username: String) -> String? {
        let key = "\(username)@\(server)"
        passwordLock.lock()
        defer { passwordLock.unlock() }
        if let cached = cachedPassword, cached.key == key { return cached.value }
        if let password = KeychainStore.read(server: KeychainStore.accountKey, username: username) {
            cachedPassword = (key, password)
            cleanUpKeychain(username: username, password: password, server: server)
            return password
        }
        // Saved per server by an older build: move it to the account.
        guard let password = KeychainStore.read(server: server, username: username) else { return nil }
        _ = KeychainStore.save(server: KeychainStore.accountKey, username: username, password: password)
        cachedPassword = (key, password)
        cleanUpKeychain(username: username, password: password, server: server)
        return password
    }

    /// Panel / Settings server switch (DESIGN.md §21.13): select it, and
    /// when a session is up or being set up, move it to the new server.
    func switchServer(to target: String) {
        var profile = ProfileStore.loadProfile()
        guard profile.server != target else { return }
        profile.server = target
        ProfileStore.saveProfile(profile)
        protection.invalidate(.serverChanged)
        guard state != .disconnected || networkHeld else { return }
        if let cisco {
            cisco.disconnect { [weak self] in
                _ = self?.connectWithStoredCredentials()
            }
        } else {
            disconnect()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                _ = self?.connectWithStoredCredentials()
            }
        }
    }

    /// One-time keychain clean-up under a stable signer (§21.16).
    private func cleanUpKeychain(username: String, password: String, server: String) {
        let legacy = ProfileStore.loadServers().map(\.target) + [server]
        KeychainStore.rebindIfSignerChanged(username: username, password: password,
                                            legacyServers: legacy)
    }

    func credentialsChanged() {
        if AppRole.isSettings { SettingsLink.shared.send("credentialsChanged"); return }
        passwordLock.lock()
        cachedPassword = nil
        passwordLock.unlock()
    }

    /// The tunnel engine (DESIGN.md §二十一, §二十三): Cisco Secure
    /// Client via its CLI when it is installed, unless the user chose
    /// the own connection; else the Helper's own openconnect engine,
    /// through the App's certificate relay when a client certificate is
    /// in use. With Cisco, the Helper only runs the pf kill switch and
    /// its own engine state is ignored.
    private let ciscoEngine: CiscoEngine? = CiscoEngine.isAvailable ? CiscoEngine() : nil
    @Published private(set) var ownConnection = ProfileStore.loadAppSettings().usesOwnConnection
    var cisco: CiscoEngine? { ownConnection ? nil : ciscoEngine }
    var usesCisco: Bool { cisco != nil }
    var ciscoInstalled: Bool { ciscoEngine != nil }

    /// Own connection's certificate relay (§二十三): from connect until
    /// the next connect, a disconnect or quit (idle after a rejected
    /// login, it only ever accepts the Helper's certificate). Not
    /// stopped on a pushed "disconnected": a late push from the previous
    /// session could kill the relay a reconnect just started.
    /// relayGeneration makes a relay still being prepared when the user
    /// disconnects give up.
    private var relay: CertificateRelay?
    private var relayGeneration = 0

    private override init() {
        super.init()
        dropHistory = ProfileStore.loadDropHistory()
        lastDrop = dropHistory.last
        // The settings process only mirrors the App (§32.15): no network
        // watch, no engine, nothing that acts.
        if AppRole.isSettings { return }
        ProfileStore.migrateSplitList()
        watchLocalNetwork()
        setupOnDemand()
        watchSleep()
        guard let cisco = ciscoEngine else { return }
        cisco.credentialsProvider = { [weak self] in
            let profile = ProfileStore.loadProfile()
            guard let username = ProfileStore.loadUsername(), !username.isEmpty,
                  let password = self?.storedPassword(server: profile.server, username: username)
            else { return nil }
            return CiscoEngine.Credentials(
                entry: profile.server, username: username, password: password)
        }
        // A Cisco engine still winding down after the switch to the own
        // connection must not speak for the session any more.
        cisco.onState = { [weak self] state, detail in
            guard let self, self.usesCisco else { return }
            if state == .reconnecting {
                self.dropRetryCount = cisco.episodeRetries
            }
            self.applyState(stateCode: state.rawValue, detail: detail)
        }
        cisco.onTerminal = { [weak self] reason in
            guard self?.usesCisco == true else { return }
            self?.terminalReasonCode = reason
            self?.applyTerminalToDrop(reason)
            Notifier.shared.notifyTerminal(reasonCode: reason)
        }
        cisco.onKillSwitch = { [weak self] mode, tun, gateways in
            guard self?.usesCisco == true else { return }
            self?.setKillSwitch(mode, tunnelIf: tun, gatewayIps: gateways)
        }
    }

    /// The Helper answered or pushed: it is up and talking.
    private func markHelperReachable() {
        helperAvailable = true
        lastError = nil
        helperUnresponsive = false
    }

    /// Cisco engine → Helper pf (DESIGN.md §二十一). A missing or old
    /// Helper means no kill switch: say so on the panel, never hide it.
    private func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String]) {
        guard let ticket = protection.request(mode) else { return }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished && self.protection.isCurrent(ticket) {
                    finished = true
                    self.pfWarning = "后台服务未响应：断线封网未生效"
                }
            }
            let apply = {
                guard self.protection.claim(ticket) else {
                    finished = true
                    return
                }
                let mode = ProfileStore.loadAppSettings().isDropProtectionOn
                    && self.onDemand.permitsConnection() && self.usesCisco ? mode : 0
                proxy.setKillSwitch(mode, tunnelIf: tunnelIf, gatewayIps: gatewayIps) { ok, message in
                    DispatchQueue.main.async {
                        // A reply may update only the latest session's intent.
                        guard self.protection.isCurrent(ticket) else { return }
                        finished = true
                        self.markHelperReachable()
                        self.pfWarning = ok || !self.usesCisco ? nil : message
                    }
                }
            }
            if HelperInstaller.installedHelperMatchesBundle {
                // This service serializes disconnect and protection on one queue.
                // No status reply is needed to submit protection after a lost reply.
                apply()
            } else {
                // Older/unknown service: its protection uses a different queue.
                proxy.getStatus { _, _ in DispatchQueue.main.async(execute: apply) }
            }
        }
    }

    private var connection: NSXPCConnection?

    /// The panel switch is "on" for every state except a confirmed
    /// manual disconnect. AwaitingApproval keeps the switch on: the
    /// user is mid-flow, not disconnected.
    var switchIsOn: Bool {
        state != .disconnected || networkHeld
    }

    func connect(server: String, group: String, username: String, password: String, onAccepted: (() -> Void)? = nil) {
        guard onDemand.permitsConnection() else { return }
        protection.startSession(usesCisco: usesCisco)
        autoStopNotice = nil
        ensureConnection { proxy in
            guard self.onDemand.permitsConnection() else { return }
            proxy.connect(
                server: server, group: group, username: username, password: password
            ) { [weak self] accepted in
                DispatchQueue.main.async {
                    if !accepted {
                        self?.lastError = "Helper 未接受连接请求"
                    } else {
                        onAccepted?()
                    }
                }
            }
        }
    }

    /// A drop pauses the network when 断线保护 is on (DESIGN.md §26.19).
    /// An own connection run by a background service that cannot take
    /// the setting (older version) still pauses: say so, never claim
    /// the local network.
    var protectsDrops: Bool {
        ProfileStore.loadAppSettings().isDropProtectionOn
            || (!usesCisco && helperIgnoresDropSetting)
    }

    /// The background service did not take setDropProtection (older
    /// version, or no answer in 3 s): its own connection keeps the
    /// always-on protection.
    private var helperIgnoresDropSetting = false

    /// 断线保护 for the own connection (DESIGN.md §26.19): sent before
    /// every own connection and on every change. Only to a service
    /// with this App's code: an unknown method drops the whole XPC
    /// connection (§26.14).
    func pushDropProtection(completion: (() -> Void)? = nil) {
        let on = ProfileStore.loadAppSettings().isDropProtectionOn
        guard !HelperInstaller.installedHelperOutdated else {
            helperIgnoresDropSetting = !on
            completion?()
            return
        }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished {
                    finished = true
                    self.helperIgnoresDropSetting = !on
                    completion?()
                }
            }
            proxy.setDropProtection(on) { _ in
                DispatchQueue.main.async {
                    guard !finished else { return }
                    finished = true
                    self.helperIgnoresDropSetting = false
                    completion?()
                }
            }
        }
    }

    /// Network paused by us right now (a drop being retried, or held
    /// after the session ended): remind every 10 minutes, with the
    /// restore action, until it is not (§25.5).
    private var holdReminder: Timer?

    /// The switch changed: the reminder and the status line follow it.
    private func refreshAfterDropSetting() {
        updateHoldReminder()
        objectWillChange.send()
    }

    private func updateHoldReminder() {
        let paused = (state == .reconnecting && protectsDrops) || (state == .disconnected && networkHeld)
        if !paused {
            holdReminder?.invalidate()
            holdReminder = nil
        } else if holdReminder == nil {
            holdReminder = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { _ in
                Notifier.shared.remindHeld()
            }
        }
    }

    /// The restore must visibly do something: no answer from the
    /// background service in 5 s offers the forced restore (F9).
    private func watchRestore(
        managed: Bool = false,
        isCurrent: @escaping () -> Bool = { true },
        _ send: (@escaping () -> Void) -> Void
    ) {
        var answered = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            if !managed && !answered && isCurrent() { self?.helperUnresponsive = true }
        }
        send {
            DispatchQueue.main.async {
                answered = true
                if !managed && isCurrent() { self.helperUnresponsive = false }
            }
        }
    }

    /// Panel: the forced restore is about to restart the service. Its
    /// restart must not read as "the service died under a session, so
    /// connect again" — that turned the VPN back on right after the
    /// user asked for the network back (§30.4).
    func prepareForForcedRestore() {
        protection.invalidate(.forcedRestore)
        dropTracker.noteUserStop()
        resettingNetwork = true
        onDemand.cancelResume()
        onDemandDisconnect.suspend()
    }

    /// Panel: the forced restore was cancelled or failed.
    func forcedRestoreAbandoned() {
        resettingNetwork = false
        protection.restoreAbandoned(managing: cisco?.isManaging == true, usesCisco: usesCisco) { [weak self] in
            self?.cisco?.rearm()
        }
        onDemandDisconnect.recover()
    }

    /// Panel: the forced restore went through (or the service is back).
    func forcedRestoreDone() {
        helperUnresponsive = false
        resettingNetwork = false
        awaitingRestartRecovery = false
        onDemandDisconnect.recover()
        refreshStatus()
    }

    func disconnectByUser() {
        protection.invalidate(.manualStop)
        onDemand.userStop()
    }

    func disconnect(
        completion: (() -> Void)? = nil,
        onLocalStopped: (() -> Void)? = nil,
        isCurrent: @escaping () -> Bool = { true }
    ) {
        let protectionSession = protection.invalidate(.disconnect)
        dropTracker.noteUserStop()
        if let cisco {
            // Network first: "断开 VPN，恢复直连网络" must restore the
            // direct network at once, not after Cisco has wound down a
            // login that may still be trying (DESIGN.md §21.10).
            pfWarning = nil
            watchRestore(managed: onLocalStopped != nil, isCurrent: isCurrent) { answered in
                ensureConnection { proxy in
                    proxy.disconnect {
                        answered()
                        DispatchQueue.main.async { self.refreshHeld() }
                    }
                }
            }
            cisco.disconnect { [weak self] in
                guard let self, isCurrent() else { return }
                // A superseding start/mode change owns protection now. Still report
                // local stop completion so the separate disconnect reducer can settle.
                guard self.protection.isSessionCurrent(protectionSession) else {
                    onLocalStopped?()
                    completion?()
                    return
                }
                // Unload again in case the engine re-armed in between. But
                // if the user has meanwhile switched to the own connection
                // (按网站分流 on), a full disconnect would stop the session
                // that just started (2026-11-06, user report): only the
                // Cisco kill switch goes then.
                self.ensureConnection { proxy in
                    if self.usesCisco {
                        proxy.disconnect {
                            DispatchQueue.main.async {
                                guard isCurrent() else { return }
                                self.refreshHeld()
                                completion?()
                            }
                        }
                    } else {
                        proxy.setKillSwitch(0, tunnelIf: "", gatewayIps: []) { _, _ in
                            DispatchQueue.main.async { completion?() }
                        }
                    }
                    onLocalStopped?()
                }
            }
            return
        }
        let relay = takeRelay()
        if onLocalStopped != nil { retire(relay) }
        watchRestore(managed: onLocalStopped != nil, isCurrent: isCurrent) { answered in
            ensureConnection { proxy in
                proxy.disconnect { [weak self] in
                    answered()
                    // An engine-less restore (held network, no session)
                    // pushes nothing; re-read state and the held flag.
                    DispatchQueue.main.async {
                        guard isCurrent() else { return }
                        if onLocalStopped == nil { self?.retire(relay) }
                        self?.refreshStatus()
                        completion?()
                    }
                }
            }
        }
        onLocalStopped?()
    }

    /// Own connection only (§26.11): connected but nothing gets through
    /// for 30 s within the first two minutes -> VPN off, direct network
    /// back, and the panel and a notification say so. The user is never
    /// left to rescue the network by hand.
    private func startConnectionCheck() {
        connectionCheck.start { [weak self] in
            guard let self, self.state == .connected, !self.usesCisco else { return }
            self.autoStopNotice = "自建连接连上后 30 秒都上不了网，已自动断开并恢复直连。"
                + "可以先在设置里改用「经 Cisco」连接。"
            self.disconnect()
            Notifier.shared.notifyOwnConnectionUnusable()
        }
    }

    /// openconnect logs the session out on its way down, through the
    /// relay: keep a detached relay a few seconds longer (§23.7). A new
    /// connect stops it at once (same 127.0.0.1 port).
    private var retiringRelay: CertificateRelay?

    private func retire(_ relay: CertificateRelay?) {
        guard let relay else { return }
        retiringRelay?.stop()
        retiringRelay = relay
        DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
            guard let self, self.retiringRelay === relay else { return }
            relay.stop()
            self.retiringRelay = nil
        }
    }

    /// Detaches the current relay (and cancels one being prepared); the
    /// caller stops it once the Helper has let go of the tunnel.
    private func takeRelay() -> CertificateRelay? {
        relayGeneration += 1
        let current = relay
        relay = nil
        return current
    }

    /// Switch between Cisco and the own connection. The session, if
    /// any, is disconnected with the engine that runs it.
    func setConnectionMode(own: Bool) {
        guard own != ownConnection else { return }
        if switchIsOn { disconnect() }
        protection.invalidate(.modeChanged)
        var settings = ProfileStore.loadAppSettings()
        settings.connectionMode = own ? "own" : "cisco"
        ProfileStore.saveAppSettings(settings)
        ownConnection = own
        pfWarning = nil
        splitActivity = nil
    }

    /// 按网站分流 (DESIGN.md §26.12): one switch for the user; on = the
    /// own connection with the site list, off = Cisco. With a session
    /// up (or coming up) it disconnects, switches once the old engine
    /// has let go, and connects again with the new one.
    func setSplit(on: Bool) {
        if AppRole.isSettings { SettingsLink.shared.send("setSplit", on ? "1" : "0"); return }
        guard on != ownConnection else { return }
        guard switchIsOn else { setConnectionMode(own: on); return }
        splitSwitchPending = true
        disconnect()
        waitForIdleThenSwitch(on: on, tries: 60)
    }

    /// Set while setSplit is reconnecting, for the panel.
    @Published private(set) var splitSwitchPending = false

    private func waitForIdleThenSwitch(on: Bool, tries: Int) {
        whenIdle(tries: tries) {
            self.setConnectionMode(own: on)
            self.splitSwitchPending = false
            if self.state == .disconnected { _ = self.connectWithStoredCredentials() }
        }
    }

    /// Runs `body` on main once the session has wound down (disconnected,
    /// network not held), or after `tries` half-second checks anyway.
    private func whenIdle(tries: Int, _ body: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            if (self.state != .disconnected || self.networkHeld), tries > 0 {
                self.whenIdle(tries: tries - 1, body)
                return
            }
            body()
        }
    }

    /// Set while installHelper winds a session down, replaces the
    /// service and connects again, for the panel.
    @Published private(set) var helperUpdatePending = false

    /// Install or update the background service from any state
    /// (§26.14, user: "程序应该能兼容各种情况"). Replacing the service
    /// restarts it, which would take a running tunnel down uncleanly; so
    /// a session that is up is ended first, the service replaced, and
    /// the session connected again, whether or not the install went
    /// through (a cancelled password prompt must not leave the VPN off).
    func installHelper(waited: Bool = false, completion: @escaping (Result<Void, Error>) -> Void) {
        // A login waiting for the phone is let finish first: replacing
        // the service would throw that approval away (§26.17, the user
        // got two approval pushes). At most 2 minutes, once (§30.4).
        let loggingIn: Set<State> = [.connecting, .authenticating, .awaitingApproval]
        if !waited, !usesCisco, loggingIn.contains(state) {
            helperUpdateWaiting = true
            helperUpdatePending = true
            whenSettled(tries: 240) { self.installHelper(waited: true, completion: completion) }
            return
        }
        helperUpdateWaiting = false
        helperUpdatePending = true
        let wasActive = !usesCisco && state != .disconnected
        // No disconnect: that would log the session off. The old service
        // ends openconnect without logging off (SIGHUP), and the usual
        // recovery after a service restart (recoverAfterInterruption)
        // connects again with the saved cookie, no phone approval. A
        // Cisco session is not inside the service at all; it only gets
        // its drop protection re-sent.
        let prompt = HelperInstaller.installedHelperOutdated
            ? "AlwaysConnect 要更新后台服务（断线时封网用）。" : HelperInstaller.installPrompt
        HelperInstaller.install(prompt: prompt) { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                self.helperUpdatePending = false
                if case .success = result, wasActive, !self.awaitingRestartRecovery {
                    // The interruption may not have reached this App (the
                    // replacement fell between two messages): the install
                    // itself starts the recovery (§30.4).
                    self.scheduleRestartRecovery(wasActive: true)
                } else if !self.awaitingRestartRecovery {
                    self.refreshStatus()
                }
                self.cisco?.rearm()
                completion(result)
            }
        }
    }

    /// Launch (§30.5): this App is newer than the background service it
    /// finds. The update goes first — one administrator password, then
    /// the connection — instead of a separate 更新 click later, and never
    /// under a live session. Cancelled: connect with the service as it
    /// is; the panel keeps offering 更新.
    func updateHelperAtLaunch(thenConnect connect: Bool) {
        guard HelperInstaller.installedHelperOutdated else {
            finishLaunchConnection(connect)
            return
        }
        // Only an idle service is replaced here: one that still runs a
        // session (this App was reopened under it) is left to the panel.
        ensureConnection { proxy in
            var finished = false
            let decide: (Int) -> Void = { [weak self] code in
                guard let self, !finished else { return }
                finished = true
                guard code <= State.disconnected.rawValue else {
                    self.finishLaunchConnection(connect)
                    return
                }
                self.helperUpdatePending = true
                HelperInstaller.install(prompt: HelperInstaller.updatePrompt) { [weak self] _ in
                    DispatchQueue.main.async {
                        guard let self else { return }
                        self.helperUpdatePending = false
                        self.refreshStatus()
                        self.finishLaunchConnection(connect)
                    }
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { decide(-1) }
            proxy.getStatus { code, _ in DispatchQueue.main.async { decide(code) } }
        }
    }

    private func finishLaunchConnection(_ automatic: Bool) {
        onDemand.launchFinished(automatic)
    }

    /// True while installHelper waits for a login to finish.
    @Published private(set) var helperUpdateWaiting = false

    private func whenSettled(tries: Int, _ body: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            let loggingIn: Set<State> = [.connecting, .authenticating, .awaitingApproval]
            if loggingIn.contains(self.state), tries > 0 {
                self.whenSettled(tries: tries - 1, body)
                return
            }
            body()
        }
    }

    /// What the split did in this session (§26.12), refreshed by the
    /// open panel: list entries looked up and addresses sent direct.
    @Published private(set) var splitActivity: (entries: [String], addresses: Int)?

    func refreshSplitActivity() {
        guard !usesCisco, state == .connected else { splitActivity = nil; return }
        // An older background service does not know this method, and a
        // call to an unknown method drops the whole XPC connection: polled
        // every 3 s, the panel flickered between 后台服务未运行 and 有新版本
        // (2026-11-05). Ask only a service built from this App.
        guard !HelperInstaller.installedHelperOutdated else { splitActivity = nil; return }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finished = true }
            proxy.getSplitActivity { entries, addresses, running in
                DispatchQueue.main.async {
                    guard !finished else { return }
                    finished = true
                    self.splitActivity = running ? (entries, addresses) : nil
                }
            }
        }
    }

    /// The panel or the General page flipped drop protection: apply it
    /// to the live session at once. Cisco: re-send the current kill
    /// switch, which the setting now maps to the real mode or to off.
    /// Own connection: tell the background service (§26.19).
    func dropProtectionChanged() {
        if AppRole.isSettings { SettingsLink.shared.send("dropProtectionChanged"); return }
        if usesCisco {
            cisco?.rearm()
            if !ProfileStore.loadAppSettings().isDropProtectionOn {
                setKillSwitch(0, tunnelIf: "", gatewayIps: [])
            }
        } else {
            pushDropProtection { [weak self] in self?.refreshAfterDropSetting() }
        }
    }

    /// The panel's "恢复网络" (DESIGN.md §24.6): our own session ends
    /// first, and while the reset runs (it stops the background service)
    /// an interrupted connection is not taken as a reason to reconnect.
    private(set) var resettingNetwork = false

    func prepareForNetworkReset() {
        resettingNetwork = true
        if switchIsOn || networkHeld { disconnect() }
    }

    func networkResetFinished() {
        resettingNetwork = false
        refreshStatus()
    }

    /// Quit = VPN off and the plain direct network (DESIGN.md §21.5):
    /// release the network through the Helper FIRST and always — not
    /// only when the cached state says something is up: that cache can
    /// lag (disconnect then quit at once), and a hold left behind would
    /// end up with the gate's grace period instead (§25.4, F10). Then
    /// wind down what the App runs, and drop our XPC connection so the
    /// Helper, with nothing left to do, exits on its own.
    func shutdownForQuit(completion: @escaping () -> Void) {
        if let record = dropTracker.finishForQuit() {
            appendDrop(record)
        }
        let finish = { [weak self] in
            self?.connection?.invalidate()
            self?.connection = nil
            completion()
        }
        pfWarning = nil
        if let cisco, cisco.isManaging {
            // A Cisco login still waiting for the phone can take its
            // time to wind down; the network is already direct.
            ensureConnection { proxy in proxy.disconnect {} }
            cisco.disconnect { [weak self] in
                guard let self else { finish(); return }
                self.ensureConnection { proxy in
                    proxy.disconnect { DispatchQueue.main.async { finish() } }
                }
            }
            return
        }
        let relay = takeRelay()
        ensureConnection { proxy in
            proxy.disconnect {
                DispatchQueue.main.async {
                    // openconnect logs out through the relay on its way
                    // down: keep it until the engine has stopped, at
                    // most 6 s (as on disconnect, §23.7; F16).
                    self.whenOwnEngineStopped(timeout: relay == nil ? 0 : 6) {
                        relay?.stop()
                        self.retiringRelay?.stop()
                        self.retiringRelay = nil
                        finish()
                    }
                }
            }
        }
    }

    /// Main thread. Calls `done` once the Helper reports the own
    /// engine's manual stop as finished (terminal reason 1: openconnect
    /// has exited, after logging out through the relay), or after
    /// `timeout`. The pushed "disconnected" state comes at the START of
    /// the stop, so it cannot be the signal.
    private func whenOwnEngineStopped(timeout: TimeInterval, _ done: @escaping () -> Void) {
        let deadline = Date().addingTimeInterval(timeout)
        func poll() {
            guard Date() < deadline else { done(); return }
            fetchSessionInfo { info in
                if let (reason, _) = info, reason == 1 {
                    done()
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { poll() }
                }
            }
        }
        poll()
    }

    /// Connect with the stored profile + username + Keychain password.
    /// Returns false when credentials are incomplete; the caller shows
    /// the panel's no-credential state in that case.
    @discardableResult
    func connectWithStoredCredentials(manual: Bool = false) -> Bool {
        if AppRole.isSettings {
            guard hasCredentials else { return false }
            SettingsLink.shared.send("connect")
            return true
        }
        onDemand.requestConnection(manual: manual) { [weak self] in _ = self?.startStoredConnection() }
        return hasCredentials
    }

    @discardableResult
    private func startStoredConnection() -> Bool {
        if AppRole.isSettings {
            guard hasCredentials else { return false }
            SettingsLink.shared.send("connect")
            return true
        }
        let profile = ProfileStore.loadProfile()
        guard hasCredentials, let username = ProfileStore.loadUsername() else { return false }
        protection.startSession(usesCisco: usesCisco)
        if let cisco {
            // The engine reads the password itself, once, when it logs in.
            // Allowlist first, so the kill switch's first load has it.
            updateAllowNetworks(ProfileStore.loadAppSettings().effectiveAllowNetworks) { _ in }
            cisco.connect()
            return true
        }
        guard let password = storedPassword(server: profile.server, username: username) else {
            return false
        }
        // Keychain stays keyed by the entry name the user typed; only
        // the Helper gets the resolved address (DESIGN.md §20.6).
        let server = CiscoProfiles.resolve(profile.server)
        prepareRelay(server: server) { [weak self] error in
            guard let self else { return }
            if let error {
                self.lastError = error
                self.detail = error
                return
            }
            // The split's list and 断线保护 go first; XPC keeps the
            // order (§26.5, §26.19).
            if !self.usesCisco {
                self.pushDirectDomains()
                self.pushDropProtection()
                // The LAN too: an engine that starts under a held set
                // takes it over at once and must pass the LAN (§30.1).
                self.updateAllowNetworks(ProfileStore.loadAppSettings().effectiveAllowNetworks) { _ in }
            }
            self.connect(server: server, group: profile.group,
                         username: username, password: password) {
                // The Helper starts with the built-in LAN allowlist; push
                // the user's list as soon as the engine exists (the
                // connect reply means it does). Best effort: a stale
                // list is corrected on the next connect or Settings save.
                HelperClient.shared.updateAllowNetworks(ProfileStore.loadAppSettings().effectiveAllowNetworks) { _ in }
            }
        }
        return true
    }

    /// Own connection (DESIGN.md §二十三): start a certificate relay
    /// for `server` with the chosen keychain certificate and tell the
    /// Helper to go through it; with no certificate in use, tell it to
    /// go straight to the gateway. Completion on main: nil = ready to
    /// connect, else what to show the user.
    private func prepareRelay(server: String, completion: @escaping (String?) -> Void) {
        takeRelay()?.stop()
        retiringRelay?.stop()
        retiringRelay = nil
        let generation = relayGeneration
        let choice = ProfileStore.loadAppSettings().clientCertificate
        // A disconnect during the preparation wins: nothing to report.
        let finish: (String?) -> Void = { error in
            DispatchQueue.main.async {
                guard generation == self.relayGeneration else { return }
                completion(error)
            }
        }
        DispatchQueue.global(qos: .userInitiated).async {
            // One VPN at a time: Cisco's filter would block this tunnel.
            if CiscoEngine.isAvailable,
               CiscoEngine.parseState(CiscoEngine.run(["state"], timeout: 8).output) == "Connected" {
                _ = CiscoEngine.run(["disconnect"], timeout: 20)
            }
            let identity = choice == "none" ? nil : CertificateRelay.selectedIdentity(digest: choice)
            guard let identity else {
                if choice != nil, choice != "none" {
                    finish("找不到设置里选的证书，请重新选择")
                    return
                }
                DispatchQueue.main.async {
                    self.sendPrepareRelay(gatewayIp: "", serverPin: "") { _ in finish(nil) }
                }
                return
            }
            guard let address = GatewayAddress(server) else { finish("服务器地址无效"); return }
            // The automatic choice follows renewals while connected (§45);
            // a manual one stays the user's choice.
            let relay = CertificateRelay(host: address.host, port: address.port,
                                         identity: identity.identity, expires: identity.expires,
                                         renewal: choice == nil ? { CertificateRelay.loginCandidates().first } : nil)
            let memory = GatewayMemory.load(address.host)
            let avoid = DispatchQueue.main.sync { () -> String? in
                defer { self.gatewayToAvoid = nil }
                return self.gatewayToAvoid
            }
            let prepared: CertificateRelay.Prepared
            do {
                prepared = try relay.prepare(prefer: memory.last, avoid: avoid, known: memory.addresses)
            } catch {
                finish(error.localizedDescription)
                return
            }
            GatewayMemory.save(address.host, last: prepared.gatewayIp,
                               addresses: prepared.addresses.isEmpty ? memory.addresses : prepared.addresses)
            relay.onGatewayUnreachable = { [weak self] silent in
                DispatchQueue.main.async { self?.gatewayUnreachable(silent, host: address.host, generation: generation) }
            }
            DispatchQueue.main.async {
                guard generation == self.relayGeneration else { return }
                self.sendPrepareRelay(gatewayIp: prepared.gatewayIp,
                                      serverPin: prepared.serverPin) { pem in
                    guard let pem, let der = Self.certificateDER(pem: pem) else {
                        finish("后台服务需要更新：在菜单栏面板里点「更新」")
                        return
                    }
                    relay.start(clientCertificate: der) { error in
                        DispatchQueue.main.async {
                            guard generation == self.relayGeneration else {
                                relay.stop()
                                return
                            }
                            if let error {
                                relay.stop()
                                completion(error.localizedDescription)
                                return
                            }
                            self.relay = relay
                            completion(nil)
                        }
                    }
                }
            }
        }
    }

    /// The relay's gateway address went silent (§30.6): reconnect through
    /// another address of the same gateway, if it has one. The handover
    /// keeps the network closed and the session's cookie (§30.1).
    private var gatewayToAvoid: String?

    private func gatewayUnreachable(_ silent: String, host: String, generation: Int) {
        guard generation == relayGeneration, !usesCisco, switchIsOn else { return }
        let others = GatewayMemory.load(host).addresses.filter { $0 != silent }
        guard !others.isEmpty else { return }
        RelayLog.write("gateway address silent three times in a row: switching to another address of the gateway")
        gatewayToAvoid = silent
        GatewayMemory.save(host, last: others[0], addresses: GatewayMemory.load(host).addresses)
        _ = connectWithStoredCredentials()
    }

    /// prepareRelay over XPC; nil = no reply in 3 s (an older Helper)
    /// or an invalid request.
    private func sendPrepareRelay(gatewayIp: String, serverPin: String,
                                  completion: @escaping (String?) -> Void) {
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion(nil) }
            }
            proxy.prepareRelay(gatewayIp: gatewayIp, serverPin: serverPin) { pem in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion(pem.isEmpty ? nil : pem) }
                }
            }
        }
    }

    static func certificateDER(pem: String) -> Data? {
        let body = pem.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
        return Data(base64Encoded: body)
    }

    func refreshStatus() {
        if AppRole.isSettings {
            SettingsLink.shared.send("refreshStatus")
            return
        }
        ensureConnection { proxy in
            proxy.getStatus { [weak self] stateCode, detail in
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.markHelperReachable()
                    self.onDemandDisconnect.recheck()
                    if self.usesCisco {
                        self.refreshHeld()
                    } else {
                        self.applyState(stateCode: stateCode, detail: detail)
                        self.resumeOwnSessionIfOrphaned(stateCode: stateCode)
                    }
                }
            }
        }
        cisco?.refresh()
    }

    /// Own connection (§25.5, F12): the background service is still
    /// trying (the App crashed and was reopened, auto-connect off or
    /// not), but its relay died with the old App. Start a new relay and
    /// reconnect once per App run, else it retries forever through a
    /// relay nothing will bring back.
    private var resumedOwnSession = false

    private func resumeOwnSessionIfOrphaned(stateCode: Int) {
        guard !resumedOwnSession, stateCode != State.disconnected.rawValue,
              relay == nil, retiringRelay == nil,
              ProfileStore.loadAppSettings().clientCertificate != "none"
        else { return }
        resumedOwnSession = true
        _ = connectWithStoredCredentials()
    }

    /// Launch: the network gate let go on its own while the App was
    /// gone (§25.2) — tell the user once.
    func checkLastRelease() {
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finished = true }
            proxy.getLastRelease { reason, at in
                DispatchQueue.main.async {
                    guard !finished else { return }
                    finished = true
                    let key = "AlwaysConnectLastReleaseShown"
                    guard reason == "app-gone", at > UserDefaults.standard.double(forKey: key) else { return }
                    UserDefaults.standard.set(at, forKey: key)
                    Notifier.shared.notifyReleasedWhileAway()
                }
            }
        }
    }

    private func refreshHeld() {
        guard state == .disconnected else { return }
        fetchNetworkHeld { [weak self] held in
            guard let self, self.state == .disconnected else { return }
            self.networkHeld = held ?? false
        }
    }

    // MARK: - Drop history (Diagnostics page, DESIGN.md §21.21)

    /// Deletes one drop record. The panel's "上次掉线" follows the list,
    /// so deleting the newest one shows the one before it (or nothing).
    func deleteDrop(_ id: DropRecord.ID) {
        if AppRole.isSettings { SettingsLink.shared.send("deleteDrop", id.uuidString); return }
        dropHistory.removeAll { $0.id == id }
        ProfileStore.saveDropHistory(dropHistory)
        lastDrop = dropHistory.last
    }

    func clearDropHistory() {
        if AppRole.isSettings { SettingsLink.shared.send("clearDropHistory"); return }
        dropHistory = []
        ProfileStore.saveDropHistory(dropHistory)
        lastDrop = nil
    }

    /// Adds a finished episode; a drop of the same sleep folds into
    /// the sleep's record (DESIGN.md §41). Returns the record it is in.
    @discardableResult
    private func appendDrop(_ record: DropRecord) -> DropRecord.ID? {
        dropHistory = ProfileStore.trimmedDropHistory(DropRecord.appending(record, to: dropHistory))
        ProfileStore.saveDropHistory(dropHistory)
        lastDrop = dropHistory.last
        return dropHistory.last?.id
    }

    /// Sleep windows for the drop history (DESIGN.md §41): "will sleep"
    /// opens one, the screens waking closes it (dark wakes wake none).
    private func watchSleep() {
        let center = NSWorkspace.shared.notificationCenter
        sleepObservers = [
            center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
                self?.dropTracker.noteSleep()
            },
            center.addObserver(forName: NSWorkspace.screensDidWakeNotification, object: nil, queue: .main) { [weak self] _ in
                self?.dropTracker.noteWake()
            },
        ]
    }

    /// Refines the record of an episode that just ended in
    /// "disconnected" with the engine's terminal reason.
    /// The own connection's final retry count comes with it.
    private func applyTerminalToDrop(_ reason: Int, retries: Int? = nil) {
        guard let pending = recordAwaitingTerminal else { return }
        recordAwaitingTerminal = nil
        guard let index = dropHistory.firstIndex(where: { $0.id == pending.id }) else { return }
        var record = dropHistory[index].applyingTerminal(reason)
        if let retries, retries > pending.episodeRetries {
            record.retries = (record.retries ?? 0) + retries - pending.episodeRetries
        }
        dropHistory[index] = record
        ProfileStore.saveDropHistory(dropHistory)
        lastDrop = dropHistory.last
    }

    private static func dropEvent(_ state: State) -> DropEpisodeTracker.Event {
        switch state {
        case .connected: return .connected
        case .reconnecting: return .reconnecting
        case .awaitingApproval: return .awaitingApproval
        case .connecting, .authenticating: return .connecting
        case .disconnected: return .disconnected
        }
    }

    // MARK: - AlwaysConnectHelperClientProtocol (Helper -> App pushes)

    func statusChanged(state: Int, detail: String) {
        // The settings process takes its state from the App only.
        if AppRole.isSettings { return }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.markHelperReachable()
            self.onDemandDisconnect.recheck()
            // With the Cisco engine the Helper's own (idle) engine is
            // not the tunnel; its pushes only prove the Helper is up.
            if !self.usesCisco {
                self.applyState(stateCode: state, detail: detail)
            }
        }
    }

    /// Single funnel for every state update (push or poll): records
    /// drop history and drives notifications from transitions, so a
    /// repeated push of the same state never double-counts.
    /// The own connection's self-check already ran for this session.
    private var sessionProven = false

    private func applyState(stateCode: Int, detail: String) {
        let old = state
        guard let parsed = State(rawValue: stateCode) else {
            self.detail = detail
            return
        }
        if awaitingRestartRecovery, parsed == .disconnected {
            // A restarted service says "disconnected" when the App
            // attaches, before the recovery has asked: not the end of
            // the drop (it read as 断了 2 秒，没恢复, §30.4).
            return
        }
        state = parsed
        self.detail = detail
        if parsed != old, !usesCisco {
            // Next to the relay's login trace (§30.9): what the App showed
            // and when, readable without administrator rights.
            RelayLog.write("app state: \(old) -> \(parsed)")
        }
        if parsed == .reconnecting, old == .connected, !usesCisco {
            // The own connection's count arrives later from the Helper;
            // don't carry the previous episode's into this one.
            dropRetryCount = 0
        }
        if parsed != .disconnected {
            // A terminal reason only belongs to the episode that just
            // ended; once anything else happens, a later one is unrelated.
            recordAwaitingTerminal = nil
        }
        if let record = dropTracker.handle(
            Self.dropEvent(parsed), previous: Self.dropEvent(old),
            engine: usesCisco ? "cisco" : "own", retries: dropRetryCount) {
            let id = appendDrop(record)
            recordAwaitingTerminal = parsed == .disconnected ? id.map { ($0, record.retries ?? 0) } : nil
        }
        if parsed == .connected {
            if old != .connected {
                connectedSince = Date()
                // Only a session that has not worked yet (§26.11): one
                // that comes back after a drop, a wake or a service
                // restart was proven before, and 30 quiet seconds there
                // must not turn the VPN off (§30.4).
                if !usesCisco, !sessionProven {
                    sessionProven = true
                    startConnectionCheck()
                }
            }
        } else {
            connectionCheck.stop()
        }
        if parsed == .disconnected { sessionProven = false }
        if parsed == .disconnected {
            connectedSince = nil
            fetchNetworkHeld { [weak self] held in
                guard let self, self.state == .disconnected else { return }
                self.networkHeld = held ?? false
            }
        } else {
            networkHeld = false
        }
        Notifier.shared.handleTransition(from: old, to: parsed, blocking: protectsDrops)
        updateHoldReminder()
        // Session info (DESIGN.md §十九): the retry count is live
        // during a drop episode; the terminal reason is fetched once
        // per real terminal transition (not on poll repeats, where
        // old is already .disconnected). A timeout means an old
        // Helper: counts stay 0 and no terminal notification fires,
        // exactly the pre-§十九 behavior.
        if usesCisco {
            // Retries and terminal reasons come from the Cisco engine
            // (onState / onTerminal), not from the Helper's idle engine.
            return
        }
        if parsed == .reconnecting {
            fetchSessionInfo { [weak self] info in
                guard let self, let (reason, retries) = info else { return }
                self.terminalReasonCode = reason
                if reason == 4 { self.lastError = "内置连接组件缺失或不可信，请重新安装后台服务" }
                self.dropRetryCount = retries
            }
        }
        if parsed == .disconnected, old != .disconnected {
            fetchSessionInfo { [weak self] info in
                guard let self, let (reason, retries) = info else { return }
                self.terminalReasonCode = reason
                if reason == 4 { self.lastError = "内置连接组件缺失或不可信，请重新安装后台服务" }
                self.dropRetryCount = retries
                self.applyTerminalToDrop(reason, retries: retries)
                Notifier.shared.notifyTerminal(reasonCode: reason)
            }
        }
    }

    // MARK: - Diagnostics XPC (additive methods, timeout-guarded)

    /// Every call below may target an old Helper that never replies;
    /// the 3-second timeout turns that into a nil fallback instead
    /// of a hang (see HelperXPC.swift upgrade-safety note).
    func evaluateRule(
        app: String,
        domain: String,
        ip: String,
        rules: [Rule],
        defaultMode: DefaultMode,
        completion: @escaping ((Int, String)?) -> Void
    ) {
        let rulesJSON = String(
            data: (try? JSONEncoder().encode(rules)) ?? Data("[]".utf8),
            encoding: .utf8) ?? "[]"
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion(nil) }
            }
            proxy.evaluateRule(
                app: app, domain: domain, ip: ip,
                rulesJSON: rulesJSON, defaultMode: defaultMode == .secure ? 0 : 1
            ) { direction, reason in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion((direction, reason)) }
                }
            }
        }
    }

    func fetchStats(completion: @escaping ((Int64, Int64, String)?) -> Void) {
        let done: ((Int64, Int64, String)?) -> Void = { [weak self] result in
            self?.endReadOnlyConnection()
            completion(result)
        }
        if usesCisco {
            guard state == .connected else { done((0, 0, "")); return }
            // Read-only and independent of the pf switch / Helper version.
            // Keep the CLI off the main thread and away from login's queue.
            DispatchQueue.global(qos: .utility).async {
                // The real CLI takes about 3 seconds even on a live session.
                let result = CiscoEngine.run(["stats"], timeout: 8)
                let counters = result.status == 0 ? CiscoTrafficStats.parse(result.output) : nil
                let tunnel = counters != nil ? CiscoEngine.defaultRouteInterface() : nil
                DispatchQueue.main.async {
                    guard self.state == .connected else { done((0, 0, "")); return }
                    if let counters, let tunnel {
                        done((counters.bytesIn, counters.bytesOut, tunnel))
                    } else {
                        done(nil)
                    }
                }
            }
            return
        }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; done(nil) }
            }
            proxy.getStats { bytesIn, bytesOut, tunnelIf in
                DispatchQueue.main.async {
                    if !finished { finished = true; done((bytesIn, bytesOut, tunnelIf)) }
                }
            }
        }
    }

    /// Live connections for the 连接 page (§28.7). nil = no answer in
    /// 3 s, or a background service that does not have the method yet
    /// (never asked: an unknown method drops the XPC connection).
    func fetchConnections(completion: @escaping ([ConnectionRow]?) -> Void) {
        let done: ([ConnectionRow]?) -> Void = { [weak self] result in
            self?.endReadOnlyConnection()
            completion(result)
        }
        guard !HelperInstaller.installedHelperOutdated else { done(nil); return }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; done(nil) }
            }
            proxy.getConnections { json in
                let rows = try? JSONDecoder().decode([ConnectionRow].self, from: Data(json.utf8))
                DispatchQueue.main.async {
                    if !finished { finished = true; done(rows) }
                }
            }
        }
    }

    func runLeakCheck(completion: @escaping ([LeakCheckItem]?) -> Void) {
        let done: ([LeakCheckItem]?) -> Void = { [weak self] result in
            self?.endReadOnlyConnection()
            completion(result)
        }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; done(nil) }
            }
            proxy.runLeakCheck { json in
                DispatchQueue.main.async {
                    if !finished {
                        finished = true
                        let items = json.data(using: .utf8)
                            .flatMap { try? JSONDecoder().decode([LeakCheckItem].self, from: $0) }
                        done(items)
                    }
                }
            }
        }
    }

    /// The domain split's list (DESIGN.md §26.5), sent before every own
    /// connection and on every change. Completion: true = taken, nil =
    /// no reply in 3 s (an older background service).
    func pushDirectDomains(completion: ((Bool?) -> Void)? = nil) {
        if AppRole.isSettings {
            SettingsLink.shared.send("pushDirectDomains") { result in completion?(result.map { $0 == "1" }) }
            return
        }
        let settings = ProfileStore.loadAppSettings()
        // Without Cisco on this Mac the own connection runs either way;
        // only the switch decides whether the list applies.
        let domains = settings.splitOn ? settings.directDomains : []
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion?(nil) }
            }
            proxy.setDirectDomains(domains) { ok in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion?(ok) }
                }
            }
        }
    }

    /// 本地局域网直连 follows the Mac (§26.13): when the network
    /// changes (home, office, hotspot) during a session or a held
    /// network, the allowlist with the new local network is pushed.
    private let pathMonitor = NWPathMonitor()
    private var lastLocalNetworks: [String] = []

    private func watchLocalNetwork() {
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            DispatchQueue.main.async {
                guard let self else { return }
                self.onDemandPathReady = true
                self.scheduleOnDemandEvaluation()
                if let (ssid, done) = self.pendingOnDemandFacts {
                    self.pendingOnDemandFacts = nil
                    done(self.networkFacts.collect(path: self.pathMonitor.currentPath, needsSSID: ssid))
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                guard let self else { return }
                let now = LocalNetwork.current()
                guard now != self.lastLocalNetworks else { return }
                self.lastLocalNetworks = now
                guard self.switchIsOn || self.networkHeld else { return }
                self.updateAllowNetworks(ProfileStore.loadAppSettings().effectiveAllowNetworks) { _ in }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "com.alwaysconnect.app.path"))
    }

    /// Push the pf allowlist to the Helper (DESIGN.md §十九).
    /// Completion: true = applied, false = no engine running,
    /// nil = Helper did not reply in 3s (version too old).
    func updateAllowNetworks(_ networks: [String], completion: @escaping (Bool?) -> Void) {
        if AppRole.isSettings {
            SettingsLink.shared.send("updateAllowNetworks", networks.joined(separator: "\n")) { result in
                completion(result.map { $0 == "1" })
            }
            return
        }
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion(nil) }
            }
            proxy.updateAllowNetworks(networks) { applied in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion(applied) }
                }
            }
        }
    }

    /// Held-network flag (DESIGN.md §20.9). Completion nil on 3s
    /// timeout (old Helper): treated as not held, the pre-§20.9 view.
    func fetchNetworkHeld(completion: @escaping (Bool?) -> Void) {
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion(nil) }
            }
            proxy.getNetworkHeld { held in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion(held) }
                }
            }
        }
    }

    /// Terminal reason + drop-episode retries (DESIGN.md §十九).
    /// Completion nil on 3s timeout (old Helper).
    func fetchSessionInfo(completion: @escaping ((Int, Int)?) -> Void) {
        ensureConnection { proxy in
            var finished = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                if !finished { finished = true; completion(nil) }
            }
            proxy.getSessionInfo { reason, retries in
                DispatchQueue.main.async {
                    if !finished { finished = true; completion((reason, retries)) }
                }
            }
        }
    }

    // MARK: - Connection management

    /// One reconnect per Helper restart, only if the session was active
    /// and the restarted Helper indeed has none (state 0, no terminal
    /// reason): a manual disconnect before the crash stays disconnected.
    /// The service went away under the App (an update, a crash). The
    /// recovery runs once the new one answers; until then its
    /// "disconnected" is not taken as the session's end. If the first
    /// try gets no answer (the old service was still being replaced),
    /// it is tried again, up to half a minute (§30.4).
    private var awaitingRestartRecovery = false
    private var restartRecoveryGeneration = 0

    private func scheduleRestartRecovery(wasActive: Bool, attempt: Int = 0) {
        if attempt == 0 {
            restartRecoveryGeneration += 1
            awaitingRestartRecovery = wasActive
        }
        let generation = restartRecoveryGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, generation == self.restartRecoveryGeneration, !self.resettingNetwork else { return }
            if attempt > 0, !self.awaitingRestartRecovery { return }
            self.recoverAfterInterruption(wasActive: wasActive)
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                guard let self, generation == self.restartRecoveryGeneration,
                      self.awaitingRestartRecovery else { return }
                if attempt < 5 {
                    self.scheduleRestartRecovery(wasActive: wasActive, attempt: attempt + 1)
                } else {
                    // Never answered: stop waiting; the panel shows the
                    // service as not running and the restore button.
                    self.awaitingRestartRecovery = false
                }
            }
        }
    }

    private func recoverAfterInterruption(wasActive: Bool) {
        ensureConnection { proxy in
            proxy.getStatus { [weak self] stateCode, detail in
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard !self.resettingNetwork else { return }
                    self.onDemand.serviceRecovered { [weak self] in
                        guard let self else { return }
                        let awaited = self.awaitingRestartRecovery
                        self.awaitingRestartRecovery = false
                        self.markHelperReachable()
                        if let cisco = self.cisco {
                            // The tunnel is Cisco's and survived; only the
                            // restarted Helper's kill switch needs re-arming.
                            cisco.rearm()
                            return
                        }
                        if wasActive, awaited, stateCode == State.disconnected.rawValue {
                            // The service restarted under a live session (an
                            // update, a crash): a drop being recovered, not
                            // the end of one. Applied as "disconnected" it
                            // closed the episode at once as 断了 2 秒，停止重试
                            // while the App was already connecting again
                            // (user report, DESIGN.md §27.5).
                            self.applyState(
                                stateCode: State.reconnecting.rawValue,
                                detail: "后台服务重启了，正在重新连接…")
                            _ = self.connectWithStoredCredentials()
                        } else {
                            self.applyState(stateCode: stateCode, detail: detail)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Settings process mirror (§32.15)

    private static func dropSignature(_ record: DropRecord?) -> String {
        guard let record else { return "" }
        return "\(record.recoveredAt.timeIntervalSince1970) \(record.sleepDropCount) \(record.outcomeLabel) \(record.retries ?? 0)"
    }

    /// What the settings process shows, as JSON.
    func remoteSnapshot() -> String {
        var json: [String: Any] = [
            "state": state.rawValue, "detail": detail, "helperAvailable": helperAvailable,
            "terminalReasonCode": terminalReasonCode, "dropRetryCount": dropRetryCount,
            "networkHeld": networkHeld, "helperUnresponsive": helperUnresponsive,
            "ownConnection": ownConnection, "splitSwitchPending": splitSwitchPending,
            "onDemandPaused": onDemandPaused, "onDemandRuleName": onDemandRuleName ?? "",
            "helperUpdatePending": helperUpdatePending, "drops": dropHistory.count,
            "lastDropId": lastDrop?.id.uuidString ?? "", "lastDropSignature": Self.dropSignature(lastDrop),
        ]
        if let lastError { json["lastError"] = lastError }
        if let autoStopNotice { json["autoStopNotice"] = autoStopNotice }
        if let pfWarning { json["pfWarning"] = pfWarning }
        if let connectedSince { json["connectedSince"] = connectedSince.timeIntervalSince1970 }
        let data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    func applyRemoteSnapshot(_ text: String) {
        guard let json = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return }
        state = State(rawValue: json["state"] as? Int ?? 0) ?? .disconnected
        detail = json["detail"] as? String ?? ""
        helperAvailable = json["helperAvailable"] as? Bool ?? false
        terminalReasonCode = json["terminalReasonCode"] as? Int ?? 0
        dropRetryCount = json["dropRetryCount"] as? Int ?? 0
        networkHeld = json["networkHeld"] as? Bool ?? false
        helperUnresponsive = json["helperUnresponsive"] as? Bool ?? false
        onDemandPaused = json["onDemandPaused"] as? Bool ?? false
        onDemandRuleName = json["onDemandRuleName"] as? String
        ownConnection = json["ownConnection"] as? Bool ?? ownConnection
        splitSwitchPending = json["splitSwitchPending"] as? Bool ?? false
        helperUpdatePending = json["helperUpdatePending"] as? Bool ?? false
        lastError = json["lastError"] as? String
        autoStopNotice = json["autoStopNotice"] as? String
        pfWarning = json["pfWarning"] as? String
        connectedSince = (json["connectedSince"] as? Double).map(Date.init(timeIntervalSince1970:))
        // The drop list is stored; reload it when the App's changed.
        let drops = json["drops"] as? Int ?? 0
        let last = json["lastDropId"] as? String ?? ""
        // A sleep record changes in place (one more drop folded in, or the
        // terminal reason) without a new id: compare what it shows too.
        let signature = json["lastDropSignature"] as? String ?? ""
        if drops != dropHistory.count || last != (dropHistory.last?.id.uuidString ?? "")
            || signature != Self.dropSignature(dropHistory.last) {
            dropHistory = ProfileStore.loadDropHistory()
            lastDrop = dropHistory.last
        }
    }

    /// The settings process asks the background service read-only
    /// questions directly; it must not stay one of its clients (a crashed
    /// App's hold would then never lose its owner).
    private func endReadOnlyConnection() {
        guard AppRole.isSettings else { return }
        connection?.invalidate()
        connection = nil
    }

    private func ensureConnection(_ body: @escaping (AlwaysConnectHelperProtocol) -> Void) {
        if let connection,
            let proxy = connection.remoteObjectProxy as? AlwaysConnectHelperProtocol
        {
            body(proxy)
            return
        }
        let connection = NSXPCConnection(
            machServiceName: AlwaysConnectHelperMachService, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(
            with: AlwaysConnectHelperProtocol.self)
        connection.exportedInterface = NSXPCInterface(
            with: AlwaysConnectHelperClientProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self, weak connection] in
            DispatchQueue.main.async {
                guard let self, self.connection === connection, !AppRole.isSettings else { return }
                // The panel's "后台服务未运行" row already says it;
                // no second red line.
                self.helperAvailable = false
                self.onDemandDisconnect.transportLost(
                    active: self.state != .disconnected, resetting: self.resettingNetwork, invalidated: false)
            }
        }
        connection.invalidationHandler = { [weak self, weak connection] in
            DispatchQueue.main.async {
                guard let self, self.connection === connection else { return }
                self.connection = nil
                if !AppRole.isSettings {
                    self.helperAvailable = false
                    self.onDemandDisconnect.transportLost(
                        active: self.state != .disconnected, resetting: self.resettingNetwork, invalidated: true)
                }
            }
        }
        connection.resume()
        self.connection = connection
        if let proxy = connection.remoteObjectProxy as? AlwaysConnectHelperProtocol {
            body(proxy)
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.lastError = "Helper 协议不匹配"
            }
        }
    }
}


/// The gateway addresses seen for a server name, and the one the last
/// session used (§30.6): kept on this Mac only (UserDefaults), so a
/// reconnect keeps its address while it works and still has the others
/// when DNS is unreachable during a drop.
enum GatewayMemory {
    private static let key = "AlwaysConnectGatewayAddresses"

    static func load(_ host: String) -> (last: String?, addresses: [String]) {
        let all = UserDefaults.standard.dictionary(forKey: key) as? [String: [String]] ?? [:]
        let list = all[host] ?? []
        // First entry: the last used one; then every known address.
        return (list.first, Array(list.dropFirst()))
    }

    static func save(_ host: String, last: String, addresses: [String]) {
        var all = UserDefaults.standard.dictionary(forKey: key) as? [String: [String]] ?? [:]
        all[host] = [last] + addresses.filter(isValidIPv4Address)
        UserDefaults.standard.set(all, forKey: key)
    }
}
