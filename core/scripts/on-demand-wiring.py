#!/usr/bin/env python3
"""Compile real HelperClient I/O bindings against deterministic XPC/Cisco stubs.
Policy fault sequences live in Rust on_demand/runtime.rs, not duplicated here.
"""
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
    'func connectWithStoredCredentials(', 'func disconnect(\n', 'private func watchRestore(',
    'func onDemandSettingsChanged()', 'func prepareForForcedRestore()',
    'func forcedRestoreAbandoned()', 'func forcedRestoreDone()', 'func disconnectByUser()'
]
body = '\n'.join(block(source, marker).replace('private func ', 'func ', 1) for marker in methods)
callbacks = '\n'.join(block(source, marker) for marker in [
    'onDemand.disconnect =', 'onDemand.waiting =', 'onDemand.connect =',
    'onDemand.stopUser =', 'onDemand.recheck =', 'onDemand.changed =', 'onDemand.refreshService ='])
view = (root / 'Sources/App/OnDemandSettings.swift').read_text()
disappear = block(view, '.onDisappear')[len('.onDisappear'):].replace('{', '{ [self] in', 1)

fixture = r'''
import Foundation
struct DispatchQueue {
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
struct Settings { var onDemandEnabled: Bool?; var onDemandRules: [OnDemandRule]? }
enum ProfileStore {
    static var settings = Settings(onDemandEnabled: true, onDemandRules: [])
    static func loadAppSettings() -> Settings { settings }
}
struct Tracker { func noteUserStop() {} }
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
        precondition(args == ["state"] && timeout == 2)
        return Result(status: 0, output: observedState)
    }
    static func parseState(_ text: String) -> String? { text }
}
final class Proxy {
    var code = 1
    var held = false
    var blocked = false
    var queue: [() -> Void] = []
    var replies: [() -> Void] = []
    var calls: [String] = []
    func enqueue(_ work: @escaping () -> Void) { queue.append(work); drain() }
    func drain() { while !blocked && !queue.isEmpty { queue.removeFirst()() } }
    func disconnect(_ reply: @escaping () -> Void) {
        enqueue { self.calls.append("disconnect"); self.code = 0; self.held = false; self.replies.append(reply) }
    }
    func getStatus(_ reply: @escaping (Int, String) -> Void) {
        enqueue { self.calls.append("status"); reply(self.code, "") }
    }
    func getNetworkHeld(_ reply: @escaping (Bool) -> Void) {
        enqueue { self.calls.append("held"); reply(self.held) }
    }
    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String], reply: @escaping (Bool, String) -> Void) {
        enqueue { self.held = false; reply(true, "") }
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
    func markHelperReachable() {}
    func scheduleRestartRecovery(wasActive: Bool) {}
    func startStoredConnection() -> Bool { starts += 1; proxy.code = 1; return true }
    METHODS
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
        let view = ViewLifecycle()
        let probe = view.testProbe!
        view.disappear()
        check(!view.testing && probe.cancelled && view.testProbe == nil && view.testMonitor == nil,
              "production settings disappearance cancels resources and restores test button")
        print("\(count) production I/O wiring assertions passed")
    }
}
'''
for key, value in [('CALLBACKS', callbacks), ('METHODS', body), ('DISAPPEAR', disappear)]:
    fixture = fixture.replace(key, value)
output.write_text(fixture)
