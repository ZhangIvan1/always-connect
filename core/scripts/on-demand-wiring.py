#!/usr/bin/env python3
"""Compile production HelperClient callback wiring against deterministic system stubs."""
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:])
source = (root / 'Sources/App/HelperClient.swift').read_text()

def block(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    if 'func ' in marker:
        paren = text.index('(', start)
        level = 0
        for at in range(paren, len(text)):
            level += (text[at] == '(') - (text[at] == ')')
            if level == 0:
                opening = text.index('{', at + 1)
                break
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0:
                return text[start:end + 1]
    raise ValueError(marker)

methods = [
    'private func setupOnDemandDisconnection()', 'private func verifyOnDemandIdle(',
    'func connectWithStoredCredentials(', 'func disconnect(\n',
    'private func watchRestore(', 'func onDemandSettingsChanged()',
    'func prepareForForcedRestore()', 'func forcedRestoreAbandoned()', 'func forcedRestoreDone()',
    'func disconnectByUser()', 'func refreshStatus()', 'private func recoverAfterInterruption('
]
body = '\n'.join(block(source, marker).replace('private func ', 'func ', 1) for marker in methods)
callbacks = '\n'.join(block(source, marker) for marker in [
    'onDemand.disconnect =', 'onDemand.connect =', 'onDemand.changed ='])
handlers = '\n'.join(block(source, marker) for marker in [
    'connection.interruptionHandler =', 'connection.invalidationHandler ='])
# The view's real disappearance closure is executed below, not copied by hand.
view = (root / 'Sources/App/OnDemandSettings.swift').read_text()
disappear = block(view, '.onDisappear')[len('.onDisappear'):]
fixture = r'''
import Foundation
struct DispatchQueue {
    static let main = ImmediateQueue()
    static func global(qos: DispatchQoS.QoSClass) -> ImmediateQueue { main }
}
final class ImmediateQueue {
    var timers: [() -> Void] = []
    func async(execute: () -> Void) { execute() }
    func asyncAfter(deadline: DispatchTime, execute: @escaping () -> Void) { timers.append(execute) }
    func fire() {
        let due = timers
        timers = []
        for task in due { task() }
    }
}
struct AppRole { static let isSettings = false }
final class SettingsLink {
    static let shared = SettingsLink()
    func send(_ action: String) {}
}
struct Settings { var onDemandEnabled: Bool?; var onDemandRules: [OnDemandRule]? }
enum ProfileStore {
    static var settings = Settings(onDemandEnabled: true, onDemandRules: [])
    static func loadAppSettings() -> Settings { settings }
}
struct Tracker { func noteUserStop() {} }
final class FakeObject {
    var pathUpdateHandler: (() -> Void)?
    var cancelled = false
    func cancel() { cancelled = true }
}
final class FakeFacts { func watch(enabled: Bool) {} }
final class FakeRelay {}
final class FakeCisco {
    var completions: [() -> Void] = []
    func disconnect(completion: @escaping () -> Void) { completions.append(completion) }
    func finish() { let all = completions; completions = []; all.forEach { $0() } }
    func rearm() {}
    func refresh() {}
}
enum CiscoEngine {
    static var observedState = "Disconnected"
    struct Result { var status: Int32; var output: String }
    static func run(_ args: [String], timeout: TimeInterval) -> Result {
        precondition(args == ["state"] && timeout == 2)
        return Result(status: 0, output: observedState)
    }
    static func parseState(_ text: String) -> String? { text }
}
final class FakeConnection {
    var interruptionHandler: (() -> Void)?
    var invalidationHandler: (() -> Void)?
}
final class FakeProxy {
    var code = 0
    var held = false
    var missingReply = true
    var unavailable = false
    var blocked = false
    var queue: [() -> Void] = []
    var replies: [() -> Void] = []
    var stops = 0
    func enqueue(_ work: @escaping () -> Void) {
        queue.append(work)
        drain()
    }
    func drain() {
        while !blocked && !queue.isEmpty { queue.removeFirst()() }
    }
    func disconnect(_ reply: @escaping () -> Void) {
        enqueue {
            self.stops += 1
            self.code = 0
            self.held = false
            if self.missingReply { self.replies.append(reply) } else { reply() }
        }
    }
    func getStatus(_ reply: @escaping (Int, String) -> Void) {
        enqueue { if !self.unavailable { reply(self.code, "") } }
    }
    func getNetworkHeld(_ reply: @escaping (Bool) -> Void) {
        enqueue { if !self.unavailable { reply(self.held) } }
    }
    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String], reply: @escaping (Bool, String) -> Void) {
        enqueue { self.held = false; reply(true, "") }
    }
}
final class Client {
    enum State: Int { case disconnected = 0, connecting = 1, reconnecting = 5 }
    var state = State.disconnected
    let onDemand = OnDemandController()
    let onDemandDisconnect = OnDemandDisconnect()
    var onDemandResumePending = false
    var onDemandLaunchReady = true
    var awaitingRestartRecovery = false
    var onDemandPaused = false
    var onDemandRuleName: String?
    var onDemandDebounce: DispatchWorkItem?
    var pendingOnDemandFacts: Int?
    let networkFacts = FakeFacts()
    let dropTracker = Tracker()
    var resettingNetwork = false
    var helperUnresponsive = false
    var helperAvailable = false
    var hasCredentials = true
    var starts = 0
    var retires = 0
    var restartRequests = 0
    var pfWarning: String?
    var cisco: FakeCisco?
    var usesCisco: Bool { cisco != nil }
    let proxy = FakeProxy()
    var connection: FakeConnection?
    init() {
        setupOnDemandDisconnection()
        CALLBACKS
        onDemand.active = { true }
        onDemand.collect = { _, done in done(OnDemandFacts(network: "wifi", ssid: "Office-WiFi")) }
        var rule = OnDemandRule()
        rule.ssids = ["Office-WiFi"]
        ProfileStore.settings = Settings(onDemandEnabled: true, onDemandRules: [rule])
        attach()
    }
    func attach() {
        let connection = FakeConnection()
        self.connection = connection
        HANDLERS
    }
    func ensureConnection(_ body: (FakeProxy) -> Void) { body(proxy) }
    func takeRelay() -> FakeRelay? { FakeRelay() }
    func retire(_ relay: FakeRelay?) { retires += 1 }
    func refreshHeld() {}
    func markHelperReachable() { helperAvailable = true }
    func resumeOwnSessionIfOrphaned(stateCode: Int) {}
    func applyState(stateCode: Int, detail: String) { state = State(rawValue: stateCode)! }
    func scheduleRestartRecovery(wasActive: Bool, attempt: Int = 0) { restartRequests += 1 }
    func startStoredConnection() -> Bool {
        precondition(!onDemandDisconnect.waiting)
        starts += 1
        proxy.code = 1
        return true
    }
    METHODS
}
final class ViewLifecycle {
    var testing = true
    var testGeneration = 10
    var testProbe: FakeObject? = FakeObject()
    var testMonitor: FakeObject? = FakeObject()
    var testFacts: FakeObject? = FakeObject()
    func disappear() DISAPPEAR
}
@main struct WiringTest {
    static var count = 0
    static func check(_ condition: @autoclosure () -> Bool, _ name: String) {
        if !condition() { fputs("FAIL \(name)\n", stderr); exit(1) }
        count += 1
        print("PASS \(name)")
    }
    static func main() {
        setbuf(stdout, nil)
        let noReply = Client()
        noReply.onDemandSettingsChanged()
        _ = noReply.connectWithStoredCredentials(manual: true)
        check(noReply.starts == 1, "missing disconnect reply recovers through real idle reads")
        check(!noReply.onDemandDisconnect.waiting, "reply loss does not latch the production connect entry")

        let recovery = Client()
        recovery.proxy.unavailable = true
        recovery.onDemandSettingsChanged()
        _ = recovery.connectWithStoredCredentials(manual: true)
        DispatchQueue.main.fire()
        check(recovery.starts == 0 && recovery.onDemandDisconnect.waiting, "deadline never releases without real state")
        recovery.connection?.interruptionHandler?()
        check(recovery.restartRequests == 1, "actual interruption handler requests service recovery")
        recovery.proxy.unavailable = false
        recovery.recoverAfterInterruption(wasActive: true)
        check(recovery.starts == 1 && !recovery.onDemandDisconnect.waiting, "service recovery releases queued manual connection once")
        let stops = recovery.proxy.stops
        let retires = recovery.retires
        recovery.proxy.replies.forEach { $0(); $0() }
        check(recovery.starts == 1 && recovery.proxy.stops == stops && recovery.retires == retires,
              "late duplicate replies have no destructive or reconnect effects")
        let old = recovery.connection
        recovery.attach()
        old?.invalidationHandler?()
        check(recovery.connection != nil, "old transport invalidation cannot clear a replacement")

        let invalidation = Client()
        invalidation.proxy.unavailable = true
        invalidation.onDemandSettingsChanged()
        _ = invalidation.connectWithStoredCredentials(manual: true)
        invalidation.connection?.invalidationHandler?()
        check(invalidation.connection == nil && invalidation.restartRequests == 1,
              "actual invalidation handler invalidates observations and requests recovery")
        invalidation.proxy.unavailable = false
        invalidation.attach()
        invalidation.recoverAfterInterruption(wasActive: true)
        check(invalidation.starts == 1, "invalidated transport can recover without restarting the App")

        let forced = Client()
        forced.proxy.unavailable = true
        forced.onDemandSettingsChanged()
        _ = forced.connectWithStoredCredentials(manual: true)
        forced.prepareForForcedRestore()
        forced.proxy.unavailable = false
        DispatchQueue.main.fire()
        check(forced.starts == 0, "forced restore suspends pending observations and cancels resume intent")
        forced.forcedRestoreAbandoned()
        check(!forced.onDemandDisconnect.waiting && forced.starts == 0,
              "cancelled forced restore reconciles actual idle state without auto-connecting")
        _ = forced.connectWithStoredCredentials(manual: true)
        check(forced.starts == 1, "manual connect works after cancellation")

        let done = Client()
        done.proxy.unavailable = true
        done.onDemandSettingsChanged()
        done.prepareForForcedRestore()
        done.proxy.unavailable = false
        done.forcedRestoreDone()
        _ = done.connectWithStoredCredentials(manual: true)
        check(done.starts == 1 && !done.onDemandDisconnect.waiting, "forced restore done recovers the gate")

        let disable = Client()
        disable.proxy.unavailable = true
        disable.onDemandSettingsChanged()
        DispatchQueue.main.fire()
        disable.proxy.unavailable = false
        ProfileStore.settings.onDemandEnabled = false
        disable.onDemandSettingsChanged()
        check(disable.starts == 1 && !disable.onDemandDisconnect.waiting,
              "disabling policy verifies real state and restores prior intent")

        let active = Client()
        active.proxy.unavailable = true
        active.onDemandSettingsChanged()
        active.proxy.unavailable = false
        active.proxy.code = 5
        _ = active.connectWithStoredCredentials(manual: true)
        check(active.starts == 0 && active.onDemandDisconnect.waiting, "live session forbids release of disconnect gate")
        active.proxy.code = 0
        active.proxy.held = true
        active.refreshStatus()
        check(active.starts == 0 && active.onDemandDisconnect.waiting, "held network forbids release of disconnect gate")
        active.proxy.held = false
        active.refreshStatus()
        check(active.starts == 1, "fresh idle and unheld state permits one connection")

        let generation = Client()
        generation.onDemandSettingsChanged()
        _ = generation.connectWithStoredCredentials(manual: true)
        let previousReplies = generation.proxy.replies
        generation.proxy.blocked = true
        generation.onDemandSettingsChanged()
        _ = generation.connectWithStoredCredentials(manual: true)
        previousReplies.forEach { $0() }
        check(generation.starts == 1 && generation.onDemandDisconnect.waiting,
              "previous operation reply cannot settle a newer generation")
        generation.proxy.blocked = false
        generation.proxy.drain()
        generation.refreshStatus()
        check(generation.starts == 2 && !generation.onDemandDisconnect.waiting,
              "new generation completes exactly once")

        let queued = Client()
        queued.proxy.blocked = true
        queued.onDemandSettingsChanged()
        _ = queued.connectWithStoredCredentials(manual: true)
        DispatchQueue.main.fire()
        check(queued.starts == 0, "queued old disconnect cannot be bypassed by timeout")
        queued.proxy.blocked = false
        queued.proxy.drain()
        check(queued.starts == 0, "expired observations cannot authorize a late connection")
        queued.refreshStatus()
        check(queued.starts == 1 && queued.proxy.code == 1, "status fence drains disconnect before new connect")
        queued.proxy.replies.forEach { $0() }
        check(queued.starts == 1 && queued.proxy.code == 1, "late reply cannot stop the new session")

        let cisco = Client()
        cisco.cisco = FakeCisco()
        cisco.onDemandSettingsChanged()
        _ = cisco.connectWithStoredCredentials(manual: true)
        DispatchQueue.main.fire()
        check(cisco.starts == 0, "Cisco local stop must settle even if background service is idle")
        CiscoEngine.observedState = "Connected"
        cisco.cisco?.finish()
        check(cisco.starts == 0 && cisco.onDemandDisconnect.waiting,
              "actual Cisco state is checked after local stop instead of trusting its notification")
        CiscoEngine.observedState = "Disconnected"
        cisco.refreshStatus()
        check(cisco.starts == 1, "Cisco final disconnect is fenced before manual connect")
        cisco.proxy.replies.forEach { $0() }
        check(cisco.starts == 1, "late Cisco service replies cannot reconnect twice")

        let view = ViewLifecycle()
        let probe = view.testProbe!
        let monitor = view.testMonitor!
        view.disappear()
        check(!view.testing && view.testGeneration == 11, "actual onDisappear resets testing and invalidates old results")
        check(probe.cancelled && monitor.cancelled && view.testProbe == nil && view.testMonitor == nil && view.testFacts == nil,
              "actual onDisappear cancels and releases test resources")
        print("\(count) production-wiring assertions passed")
    }
}
'''
for key, value in [('CALLBACKS', callbacks), ('HANDLERS', handlers), ('METHODS', body), ('DISAPPEAR', disappear)]:
    fixture = fixture.replace(key, value)
output.write_text(fixture)
