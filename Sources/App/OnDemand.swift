import Foundation

struct OnDemandProbe: Codable, Equatable {
    var kind: String
    var target: String
}
struct OnDemandRule: Codable, Equatable, Identifiable {
    var id = UUID().uuidString
    var name = "新规则"
    var network = "any"
    var ssids: [String] = []
    var domains: [String] = []
    var servers: [String] = []
    var probe: OnDemandProbe?
    var action = "disconnect"
}
/// Editing only: retain original spelling/order and append previously absent facts.
enum OnDemandRuleInput {
    static func merge(_ existing: [String], _ added: [String], caseInsensitive: Bool = false) -> [String] {
        var seen = Set<String>()
        return (existing + added).filter { value in
            guard !value.isEmpty else { return false }
            return seen.insert(caseInsensitive ? value.lowercased() : value).inserted
        }
    }
}
struct OnDemandFacts: Codable, Equatable {
    var network: String?
    var ssid: String?
    var domains: [String] = []
    var servers: [String] = []
    var probes: [String: Bool] = [:]
    var interface_name: String?
    var link_addresses: [String] = []
}
struct OnDemandDecision: Decodable {
    var action: String
    var rule_id: String?
    var probe: OnDemandProbe?
}
struct OnDemandRuntime: Codable {
    var paused = false
    var resume = false
    var manual = false
    var rule_id: String?
}
enum OnDemandCore {
    struct Validation: Decodable {
        var valid: Bool
        var weak: Bool
        var error: String?
    }
    static func validate(_ rule: OnDemandRule) -> Validation {
        call(ac_on_demand_validate, rule) ?? Validation(valid: false, weak: false, error: "规则格式无效。")
    }
    struct Request: Encodable {
        var enabled: Bool
        var rules: [OnDemandRule]
        var facts: OnDemandFacts
    }
    static func call<Q: Encodable, A: Decodable>(_ fn: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?, _ q: Q)
        -> A?
    {
        guard let data = try? JSONEncoder().encode(q), let text = String(data: data, encoding: .utf8),
            let reply = text.withCString({ fn($0) })
        else { return nil }
        defer { on_demand_string_free(reply) }
        return try? JSONDecoder().decode(A.self, from: Data(String(cString: reply).utf8))
    }
    static func decide(enabled: Bool, rules: [OnDemandRule], facts: OnDemandFacts) -> OnDemandDecision {
        call(ac_on_demand_decide, Request(enabled: enabled, rules: rules, facts: facts))
            ?? OnDemandDecision(action: "connect")
    }
}

/// An opaque Rust state snapshot. Swift stores it but never changes its fields.
final class OnDemandMachine {
    let kind: String
    private(set) var state: [String: Any] = [:]
    init(_ kind: String) { self.kind = kind }
    @discardableResult
    func send(_ event: [String: Any], context: [String: Any] = [:],
              execute: ([String: Any]) -> Void = { _ in }) -> Bool {
        let request: [String: Any] = ["kind": kind, "state": state, "event": event, "context": context]
        guard let data = try? JSONSerialization.data(withJSONObject: request),
              let text = String(data: data, encoding: .utf8),
              let answer = text.withCString({ ac_on_demand_step($0) }) else { return false }
        defer { on_demand_string_free(answer) }
        guard let reply = try? JSONSerialization.jsonObject(with: Data(String(cString: answer).utf8)) as? [String: Any],
              let state = reply["state"] as? [String: Any] else { return false }
        self.state = state  // Install before executing callbacks, which may re-enter.
        for action in reply["actions"] as? [[String: Any]] ?? [] { execute(action) }
        return reply["allowed"] as? Bool ?? false
    }
}

/// Opaque Rust tickets; no Swift generation counters or validity decisions.
final class OnDemandProtection {
    struct Ticket {
        let session: UInt64
        let intent: UInt64
    }
    enum Boundary: String {
        case manualStop = "manual_stop", forcedRestore = "forced_restore"
        case modeChanged = "mode_changed", serverChanged = "server_changed"
        case onDemandStop = "on_demand_stop", disconnect
    }
    private let machine = OnDemandMachine("protection")
    @discardableResult
    func invalidate(_ reason: Boundary) -> UInt64 {
        machine.send(["kind": reason.rawValue])
        return machine.state["session"] as? UInt64 ?? 0
    }
    func startSession(usesCisco: Bool) {
        machine.send(["kind": "session_start", "uses_cisco": usesCisco])
    }
    func restoreAbandoned(managing: Bool, usesCisco: Bool, rearm: () -> Void) {
        machine.send(["kind": "restore_abandoned", "managing": managing, "uses_cisco": usesCisco]) { action in
            if action["kind"] as? String == "rearm" { rearm() }
        }
    }
    func request(_ mode: Int) -> Ticket? {
        var ticket: Ticket?
        machine.send(["kind": "request", "mode": mode]) { action in
            if let session = action["session"] as? UInt64, let intent = action["intent"] as? UInt64 {
                ticket = Ticket(session: session, intent: intent)
            }
        }
        return ticket
    }
    func claim(_ ticket: Ticket) -> Bool { query("claim", ticket) }
    func isCurrent(_ ticket: Ticket) -> Bool { query("is_current", ticket) }
    func isSessionCurrent(_ session: UInt64) -> Bool {
        machine.send(["kind": "session_current", "session": session])
    }
    private func query(_ kind: String, _ ticket: Ticket) -> Bool {
        machine.send(["kind": kind, "session": ticket.session, "intent": ticket.intent])
    }
}

/// System effects only: read facts, run a probe, or notify the App. Rust owns order and intent.
final class OnDemandController {
    var collect: (Bool, @escaping (OnDemandFacts) -> Void) -> Void = { _, done in done(OnDemandFacts()) }
    var probe: (OnDemandProbe, OnDemandFacts, @escaping (Bool) -> Void) -> Void = { _, _, done in done(false) }
    var disconnect: () -> Void = {}
    var connect: () -> Void = {}
    var stopUser: () -> Void = {}
    var changed: () -> Void = {}
    var cancelProbe: () -> Void = {}
    var debounce: (TimeInterval, @escaping () -> Void) -> Void = { _, _ in }
    var recheck: () -> Void = {}
    var refreshService: () -> Void = {}
    var active: () -> Bool = { false }
    var autoConnect: () -> Bool = { false }
    var waiting: () -> Bool = { false }
    private let machine = OnDemandMachine("controller")
    // Closures are system resources, not policy state. Rust decides when to invoke them.
    private var automaticBody: (() -> Void)?
    private var recoveryBody: (() -> Void)?
    var state: OnDemandRuntime { decode(machine.state["policy"]) ?? OnDemandRuntime() }
    var ruleName: String? { machine.state["rule_name"] as? String }

    func configure(enabled: Bool, rules: [OnDemandRule]) {
        send(["kind": "configure", "enabled": enabled, "rules": encode(rules)])
    }
    func manualConnect() { send(["kind": "manual"]) }
    func automatic(_ body: @escaping () -> Void) { requestConnection(manual: false, body) }
    func requestConnection(manual: Bool, _ body: @escaping () -> Void) {
        automaticBody = body
        send(["kind": manual ? "manual_request" : "automatic"])
    }
    func networkWillChange() { send(["kind": "network_will_change"]) }
    func networkChanged() { send(["kind": "network"]) }
    func holdLaunch() { send(["kind": "hold_launch"]) }
    func launchFinished(_ automatic: Bool) { send(["kind": "launch_finished", "automatic": automatic]) }
    func disconnectSettled() { send(["kind": "disconnect_settled"]) }
    func cancelResume() { send(["kind": "cancel_resume"]) }
    func userStop() { send(["kind": "user_stop"]) }
    func serviceRecovered(_ body: @escaping () -> Void) {
        recoveryBody = body
        send(["kind": "service_recovered"])
    }
    func permitsConnection() -> Bool { send(["kind": "permit"]) }
    private func encode<T: Encodable>(_ value: T) -> Any {
        guard let data = try? JSONEncoder().encode(value),
              let json = try? JSONSerialization.jsonObject(with: data) else { return NSNull() }
        return json
    }
    private func decode<T: Decodable>(_ value: Any?) -> T? {
        guard let value, let data = try? JSONSerialization.data(withJSONObject: value) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
    @discardableResult
    private func send(_ event: [String: Any]) -> Bool {
        machine.send(event, context: ["active": active(), "auto_connect": autoConnect(), "waiting": waiting()]) {
            [weak self] action in self?.execute(action)
        }
    }
    private func execute(_ action: [String: Any]) {
        switch action["kind"] as? String {
        case "cancel_probe": cancelProbe()
        case "update_ui": changed()
        case "disconnect": disconnect()
        case "start": connect()
        case "start_auto":
            let body = automaticBody
            automaticBody = nil
            body?()
        case "stop_user": stopUser()
        case "recheck": recheck()
        case "refresh_service": refreshService()
        case "recover_service":
            let body = recoveryBody
            recoveryBody = nil
            body?()
        case "debounce":
            debounce(action["seconds"] as? Double ?? 1.5) { [weak self] in self?.send(["kind": "network", "token": action["token"]!]) }
        case "collect":
            collect(action["needs_ssid"] as? Bool ?? false) { [weak self] facts in
                guard let self else { return }
                self.send(["kind": "facts", "token": action["token"]!,
                           "reason": action["reason"]!, "facts": self.encode(facts)])
            }
        case "probe":
            guard let probe: OnDemandProbe = decode(action["probe"]),
                  let facts: OnDemandFacts = decode(action["facts"]) else { return }
            self.probe(probe, facts) { [weak self] matched in
                self?.send(["kind": "probe", "token": action["token"]!, "rule_id": action["rule_id"]!,
                            "facts": action["facts"]!, "probe_epoch": action["probe_epoch"]!, "matched": matched])
            }
        default: break
        }
    }
}
@_silgen_name("ac_on_demand_step")
func ac_on_demand_step(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_on_demand_decide")
func ac_on_demand_decide(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_on_demand_transition")
func ac_on_demand_transition(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_on_demand_probe")
func ac_on_demand_probe(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func on_demand_string_free(_ s: UnsafeMutablePointer<CChar>?)

@_silgen_name("ac_on_demand_validate")
func ac_on_demand_validate(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
