#!/usr/bin/env python3
"""Compile real HelperClient I/O bindings against deterministic XPC/Cisco stubs.
Policy fault sequences live in Rust on_demand/runtime.rs, not duplicated here.
"""
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:])
source = (root / 'Sources/App/HelperClient.swift').read_text()
service = (root / 'Sources/Helper/HelperDaemon.swift').read_text()
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
    'func connectWithStoredCredentials(', 'func disconnect(\n', 'private func watchRestore(',
    'func onDemandSettingsChanged()', 'func prepareForForcedRestore()',
    'func forcedRestoreAbandoned()', 'func forcedRestoreDone()', 'func disconnectByUser()', 'private func setKillSwitch('
]
body = '\n'.join(block(source, marker).replace('private func ', 'func ', 1) for marker in methods)
callbacks = '\n'.join(block(source, marker) for marker in [
    'onDemand.disconnect =', 'onDemand.waiting =', 'onDemand.connect =',
    'onDemand.stopUser =', 'onDemand.recheck =', 'onDemand.changed =', 'onDemand.refreshService ='])
view = (root / 'Sources/App/OnDemandSettings.swift').read_text()
editor = view[view.index('private struct OnDemandRuleEditor'):]
fill_methods = '\n'.join(block(editor, marker).replace('private func ', 'func ', 1) for marker in [
    'private func fillCurrentNetwork()', 'private func stopFill()', 'private func values('])
fill_methods = fill_methods.replace('monitor.pathUpdateHandler = { path in', 'monitor.pathUpdateHandler = { [self] path in')
fill_methods = fill_methods.replace('DispatchQueue.main.async {', 'DispatchQueue.main.async { [self] in')
fill_methods = fill_methods.replace('deadline: .now() + 3) {', 'deadline: .now() + 3) { [self] in')
disappear = block(view, '.onDisappear')[len('.onDisappear'):].replace('{', '{ [self] in', 1)

service_protection = block(service, 'func setKillSwitch(')

fixture = r'''
import Foundation
struct DispatchQueue {
    init(label: String) {}
    static let main = Queue()
    static func global(qos: DispatchQoS.QoSClass) -> Queue { main }
}
final class Queue {
    var timers: [() -> Void] = []
    func async(execute: () -> Void) { execute() }
    func asyncAfter(deadline: DispatchTime, execute: @escaping () -> Void) { timers.append(execute) }
}
struct AppRole { static let isSettings = false }
final class SettingsLink { static let shared = SettingsLink(); func send(_ action: String) {} }
struct Settings { var onDemandEnabled: Bool?; var onDemandRules: [OnDemandRule]?; var isDropProtectionOn = true }
enum ProfileStore {
    static var settings = Settings(onDemandEnabled: true, onDemandRules: [])
    static func loadAppSettings() -> Settings { settings }
}
enum HelperInstaller { static var installedHelperMatchesBundle = true }
struct Tracker { func noteUserStop() {} }
final class ServiceQueue {
    var blocked = false
    var pending: [() -> Void] = []
    func async(execute: @escaping () -> Void) { pending.append(execute); drain() }
    func drain() { while !blocked && !pending.isEmpty { pending.removeFirst()() } }
}
final class KillSwitch {
    enum Mode: Int { case off = 0, connected = 1, blocking = 2 }
    static let shared = KillSwitch()
    var held = false
    func set(mode: Mode, tunnelIf: String, gatewayIps: [String], reply: (Bool, String) -> Void) {
        held = mode != .off
        reply(true, "")
    }
}
final class Service {
    let queue = ServiceQueue()
    var userReleased = true
    SERVER_PROTECTION_BODY
}
final class Resource {
    var pathUpdateHandler: (() -> Void)?
    var cancelled = false
    func cancel() { cancelled = true }
}
struct FactsReader { func watch(enabled: Bool) {} }
final class Relay {}
final class Cisco {
    var completion: (() -> Void)?
    func disconnect(completion: @escaping () -> Void) { self.completion = completion }
}
enum CiscoEngine {
    static var observedState = "Disconnected"
    struct Result { var status: Int32; var output: String }
    static func run(_ args: [String], timeout: TimeInterval) -> Result {
        precondition(args == ["state"] && timeout == 5)
        return Result(status: 0, output: observedState)
    }
    static func parseState(_ text: String) -> String? { text }
}
final class Proxy {
    var code = 1
    var held = false
    var blocked = false
    var dropsStatus = false
    var queue: [() -> Void] = []
    var replies: [() -> Void] = []
    var calls: [String] = []
    func enqueue(_ work: @escaping () -> Void) { queue.append(work); drain() }
    func drain() { while !blocked && !queue.isEmpty { queue.removeFirst()() } }
    func disconnect(_ reply: @escaping () -> Void) {
        enqueue { self.calls.append("disconnect"); self.code = 0; self.held = false; self.replies.append(reply) }
    }
    func getStatus(_ reply: @escaping (Int, String) -> Void) {
        enqueue { self.calls.append("status"); if !self.dropsStatus { reply(self.code, "") } }
    }
    func getNetworkHeld(_ reply: @escaping (Bool) -> Void) {
        enqueue { self.calls.append("held"); reply(self.held) }
    }
    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String], reply: @escaping (Bool, String) -> Void) {
        let apply = { self.calls.append("arm"); self.held = mode != 0; reply(true, "") }
        if HelperInstaller.installedHelperMatchesBundle { enqueue(apply) } else { apply() }
    }
}
final class Client {
    let onDemand = OnDemandController()
    let onDemandDisconnect = OnDemandDisconnect()
    var onDemandPaused = false
    var onDemandRuleName: String?
    var awaitingRestartRecovery = false
    var onDemandDebounce: DispatchWorkItem?
    var pendingOnDemandFacts: Int?
    let networkFacts = FactsReader()
    let dropTracker = Tracker()
    var resettingNetwork = false
    var helperUnresponsive = false
    var hasCredentials = true
    var starts = 0
    var pfWarning: String?
    var cisco: Cisco?
    var usesCisco: Bool { cisco != nil }
    let proxy = Proxy()
    init() {
        setupOnDemandDisconnection()
        CALLBACKS
        onDemand.active = { true }
        onDemand.collect = { _, done in done(OnDemandFacts(network: "wifi", ssid: "Example-WiFi")) }
        var rule = OnDemandRule()
        rule.ssids = ["Example-WiFi"]
        ProfileStore.settings = Settings(onDemandEnabled: true, onDemandRules: [rule])
    }
    func ensureConnection(_ body: (Proxy) -> Void) { body(proxy) }
    func takeRelay() -> Relay? { Relay() }
    func retire(_ relay: Relay?) {}
    func refreshHeld() {}
    func refreshStatus() { onDemandDisconnect.recheck() }
    func markHelperReachable() { helperUnresponsive = false }
    func scheduleRestartRecovery(wasActive: Bool) {}
    func startStoredConnection() -> Bool { starts += 1; proxy.code = 1; return true }
    METHODS
}
final class NWPathMonitor {
    static var latest: NWPathMonitor?
    var pathUpdateHandler: ((Int) -> Void)?
    var cancelled = false
    init() { Self.latest = self }
    func start(queue: DispatchQueue) {}
    func cancel() { cancelled = true }
}
final class NetworkFacts {
    static var authorizationRequested = false
    func collect(path: Int, needsSSID: Bool, requestLocationAuthorization: Bool) -> OnDemandFacts {
        Self.authorizationRequested = requestLocationAuthorization
        return OnDemandFacts(network: "wifi", ssid: nil, domains: ["corp.example.com", "example.net"], servers: ["192.0.2.53"])
    }
}
final class RuleEditor {
    var rule = OnDemandRule(network: "wired")
    var filling = false
    var fillGeneration = 0
    var fillMonitor: NWPathMonitor?
    var fillReader: NetworkFacts?
    var fillNote: String?
    var ssids = "Custom"
    var domains = "Corp.Example.COM"
    var servers = "192.0.2.54"
    EDITOR_FILL_BODY
}
final class ViewLifecycle {
    var testing = true
    var testGeneration = 1
    var testProbe: Resource? = Resource()
    var testMonitor: Resource? = Resource()
    var testFacts: Resource? = Resource()
    func disappear() { let callback: () -> Void = DISAPPEAR; callback() }
}
@main struct WiringTest {
    static var count = 0
    static func check(_ result: @autoclosure () -> Bool, _ name: String) {
        precondition(result(), "FAIL " + name)
        count += 1
        print("PASS " + name)
    }
    static func main() {
        setbuf(stdout, nil)
        let client = Client()
        client.onDemandSettingsChanged()
        check(client.onDemandPaused && !client.onDemandDisconnect.waiting,
              "production bindings execute stop and pass raw observations to Rust without a disconnect reply")
        check(client.proxy.calls == ["disconnect", "status", "held"], "idle reads fence disconnect on the same proxy")
        _ = client.connectWithStoredCredentials(manual: true)
        check(client.starts == 1, "production manual entry dispatches Rust start action")
        client.proxy.replies.forEach { $0() }
        check(client.starts == 1 && client.proxy.code == 1, "late reply is forwarded without touching the new session")

        let queued = Client()
        queued.proxy.blocked = true
        queued.onDemandSettingsChanged()
        _ = queued.connectWithStoredCredentials(manual: true)
        check(queued.starts == 0, "queued system disconnect cannot be bypassed")
        queued.proxy.blocked = false
        queued.proxy.drain()
        check(queued.starts == 1 && queued.proxy.code == 1, "serial RPC observations release exactly one start")

        for finished in [false, true] {
            let cisco = Client()
            cisco.cisco = Cisco()
            cisco.onDemandSettingsChanged()
            cisco.prepareForForcedRestore()
            _ = cisco.connectWithStoredCredentials(manual: true)
            CiscoEngine.observedState = "Connected"
            cisco.cisco?.completion?()
            if finished { cisco.forcedRestoreDone() } else { cisco.forcedRestoreAbandoned() }
            check(cisco.starts == 0, "forced restore forwards raw Cisco state without declaring idle")
            CiscoEngine.observedState = "Disconnected"
            cisco.refreshStatus()
            check(cisco.starts == 1, "Cisco CLI observation and recovery callback reach Rust")
        }
        let delayed = Client()
        delayed.cisco = Cisco()
        delayed.proxy.blocked = true
        var timers: [(Double, () -> Void)] = []
        delayed.onDemandDisconnect.schedule = { timers.append(($0, $1)) }
        delayed.onDemandSettingsChanged()
        _ = delayed.connectWithStoredCredentials(manual: true)
        delayed.cisco?.completion?()
        timers.filter { $0.0 == 10 }.forEach { $0.1() }
        check(delayed.starts == 1, "bounded release reaches the production connection entry without status replies")
        HelperInstaller.installedHelperMatchesBundle = false
        delayed.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        check(!delayed.proxy.calls.contains("arm"), "new Cisco protection waits behind the old server disconnect")
        delayed.proxy.blocked = false
        delayed.proxy.drain()
        check(delayed.proxy.calls.firstIndex(of: "arm")! > delayed.proxy.calls.lastIndex(of: "disconnect")!
              && delayed.proxy.held,
              "old queued unload precedes rearm even on the old service")
        delayed.proxy.replies.forEach { $0() }
        check(delayed.starts == 1 && delayed.proxy.held, "late disconnect replies cannot unload new protection")

        HelperInstaller.installedHelperMatchesBundle = true
        let lost = Client()
        lost.cisco = Cisco()
        lost.proxy.blocked = true
        lost.proxy.dropsStatus = true
        var lostTimers: [(Double, () -> Void)] = []
        lost.onDemandDisconnect.schedule = { lostTimers.append(($0, $1)) }
        lost.onDemandSettingsChanged()
        _ = lost.connectWithStoredCredentials(manual: true)
        lost.cisco?.completion?()
        lostTimers.filter { $0.0 == 10 }.forEach { $0.1() }
        lost.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        lost.proxy.blocked = false
        lost.proxy.drain()
        check(lost.starts == 1 && lost.proxy.held, "new service arms protection even if every status reply is lost")
        lost.proxy.replies.forEach { $0() }
        check(lost.proxy.held, "late replies cannot remove the reply-independent arm")
        let service = Service()
        service.queue.blocked = true
        service.queue.async { KillSwitch.shared.held = false }
        service.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"]) { _, _ in }
        check(!KillSwitch.shared.held, "production service queues protection behind pending disconnect")
        service.queue.blocked = false
        service.queue.drain()
        check(KillSwitch.shared.held && !service.userReleased, "production service installs protection after old unload")

        let slow = Client()
        slow.cisco = Cisco()
        var deadlines: [() -> Void] = []
        slow.onDemandDisconnect.schedule = { _, done in deadlines.append(done) }
        slow.onDemandSettingsChanged()
        deadlines.forEach { $0() }
        DispatchQueue.main.timers.forEach { $0() }
        check(!slow.helperUnresponsive, "slow Cisco stop with a helper reply does not claim helper failure")

        let editor = RuleEditor()
        editor.fillCurrentNetwork()
        let monitor = NWPathMonitor.latest!
        monitor.pathUpdateHandler?(0)
        check(editor.rule.network == "wired" && editor.ssids == "Custom" && !NetworkFacts.authorizationRequested,
              "production fill keeps explicit network and SSID input without requesting authorization")
        check(editor.domains == "Corp.Example.COM, example.net" && editor.servers == "192.0.2.54, 192.0.2.53"
              && monitor.cancelled && editor.fillMonitor == nil && !editor.filling,
              "production fill merges facts and disposes the one-shot monitor")
        editor.fillCurrentNetwork()
        let lateFill = NWPathMonitor.latest!.pathUpdateHandler
        editor.stopFill()
        editor.domains = "custom.example"
        lateFill?(0)
        check(editor.domains == "custom.example", "cancelled editor rejects late network facts")

        let view = ViewLifecycle()
        let probe = view.testProbe!
        view.disappear()
        check(!view.testing && probe.cancelled && view.testProbe == nil && view.testMonitor == nil,
              "production settings disappearance cancels resources and restores test button")
        print("\(count) production I/O wiring assertions passed")
    }
}
'''
for key, value in [('CALLBACKS', callbacks), ('METHODS', body), ('DISAPPEAR', disappear), ('EDITOR_FILL_BODY', fill_methods), ('SERVER_PROTECTION_BODY', service_protection)]:
    fixture = fixture.replace(key, value)
output.write_text(fixture)
