import Foundation

struct OnDemandProbe: Codable, Equatable { var kind: String; var target: String }
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
    struct Request: Encodable { var enabled: Bool; var rules: [OnDemandRule]; var facts: OnDemandFacts }
    struct Transition: Encodable {
        var state: OnDemandRuntime; var event: String; var action: String
        var rule_id: String?; var active: Bool; var auto_connect: Bool
    }
    struct Effect: Decodable { var state: OnDemandRuntime; var effect: String }
    static func call<Q: Encodable, A: Decodable>(_ fn: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?, _ q: Q) -> A? {
        guard let data = try? JSONEncoder().encode(q), let text = String(data: data, encoding: .utf8),
              let reply = text.withCString({ fn($0) }) else { return nil }
        defer { on_demand_string_free(reply) }
        return try? JSONDecoder().decode(A.self, from: Data(String(cString: reply).utf8))
    }
    static func decide(enabled: Bool, rules: [OnDemandRule], facts: OnDemandFacts) -> OnDemandDecision {
        call(ac_on_demand_decide, Request(enabled: enabled, rules: rules, facts: facts))
            ?? OnDemandDecision(action: "connect")
    }
}

/// Event-driven system shell. Policy transitions are in the core; generation
/// checks prevent a stale probe from disconnecting a newer manual connection.
final class OnDemandController {
    var collect: (_ needsSSID: Bool, _ done: @escaping (OnDemandFacts) -> Void) -> Void = { _, done in done(OnDemandFacts()) }
    var probe: (_ probe: OnDemandProbe, _ facts: OnDemandFacts, _ done: @escaping (Bool) -> Void) -> Void = { _, _, done in done(false) }
    var disconnect: () -> Void = {}
    var connect: () -> Void = {}
    var changed: () -> Void = {}
    var cancelProbe: () -> Void = {}
    var active: () -> Bool = { false }
    var autoConnect: () -> Bool = { false }
    private(set) var state = OnDemandRuntime()
    private(set) var rules: [OnDemandRule] = []
    private var enabled = false
    private var ready = false
    private var evaluating = false
    private var generation = 0
    private var pendingAuto: (() -> Void)?
    private var lastFacts: OnDemandFacts?
    private var collectedFacts: OnDemandFacts?

    func configure(enabled: Bool, rules: [OnDemandRule]) {
        self.enabled = enabled; self.rules = rules
        evaluate(event: "settings")
    }
    func manualConnect() {
        generation += 1; cancelProbe(); evaluating = false; pendingAuto = nil; ready = true
        lastFacts = collectedFacts ?? lastFacts
        transition(event: "manual")
    }
    func automatic(_ body: @escaping () -> Void) {
        guard ready else {
            pendingAuto = body
            if !evaluating { evaluate(event: "startup") }
            return
        }
        if !state.paused { body() }
    }
    func networkWillChange() {
        generation += 1; cancelProbe(); ready = false; evaluating = true
    }
    func networkChanged() { evaluate(event: "network") }
    private func transition(event: String, decision: OnDemandDecision = OnDemandDecision(action: "ignore")) {
        let request = OnDemandCore.Transition(state: state, event: event, action: decision.action,
            rule_id: decision.rule_id, active: active(), auto_connect: autoConnect())
        guard let effect: OnDemandCore.Effect = OnDemandCore.call(ac_on_demand_transition, request) else { return }
        state = effect.state; changed()
        if effect.effect == "disconnect" { disconnect() }
        if effect.effect == "connect" { connect() }
    }
    private func evaluate(event: String) {
        generation += 1; cancelProbe(); let token = generation
        ready = false; evaluating = true
        // No facts, SSID, permission requests or probes at all when disabled.
        guard enabled else {
            transition(event: "settings")
            transition(event: "decision", decision: OnDemandDecision(action: "connect"))
            finish(token); return
        }
        collect(rules.contains { !$0.ssids.isEmpty }) { [weak self] facts in
            guard let self, self.generation == token else { return }
            // VPN route changes must not cancel a manual override. Only
            // changes in the physical facts count as a new network.
            if event == "network", self.lastFacts == facts { self.finish(token); return }
            self.collectedFacts = facts
            if event == "network" || event == "settings" { self.transition(event: event) }
            self.decide(facts, token: token)
        }
    }
    private func decide(_ facts: OnDemandFacts, token: Int) {
        guard token == generation else { return }
        let d = OnDemandCore.decide(enabled: enabled, rules: rules, facts: facts)
        if let p = d.probe, let id = d.rule_id {
            probe(p, facts) { [weak self] matched in
                guard let self, self.generation == token else { return }
                var next = facts; next.probes[id] = matched
                self.decide(next, token: token)
            }
        } else {
            var offline = facts; offline.probes = [:]; lastFacts = offline
            transition(event: "decision", decision: d)
            finish(token)
        }
    }
    private func finish(_ token: Int) {
        guard token == generation else { return }
        ready = true; evaluating = false
        let next = pendingAuto; pendingAuto = nil
        if !state.paused { next?() }
    }
}
@_silgen_name("ac_on_demand_decide")
func ac_on_demand_decide(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_on_demand_transition")
func ac_on_demand_transition(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_on_demand_probe")
func ac_on_demand_probe(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func on_demand_string_free(_ s: UnsafeMutablePointer<CChar>?)
