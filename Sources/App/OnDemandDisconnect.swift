import Foundation

/// Executes disconnect effects. Rust owns generations, observations and settling conditions.
final class OnDemandDisconnect {
    typealias Token = UInt64
    var stop: (Token, @escaping () -> Void, @escaping () -> Void) -> Void = { _, _, _ in }
    var verifyIdle: (@escaping (Int, Bool, String?) -> Void) -> Void = { done in done(-1, true, nil) }
    var settled: () -> Void = {}
    var needsAttention: () -> Void = {}
    var restartRecovery: (Bool) -> Void = { _ in }
    var usesCisco: () -> Bool = { false }
    var schedule: (TimeInterval, @escaping () -> Void) -> Void = { seconds, action in
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: action)
    }
    private let machine = OnDemandMachine("disconnect")
    var waiting: Bool { machine.state["waiting"] as? Bool ?? false }
    func isCurrent(_ token: Token) -> Bool { send(["kind": "is_current", "token": token]) }
    func begin() { send(["kind": "begin"]) }
    func transportLost(active: Bool = false, resetting: Bool = false, invalidated: Bool = true) {
        send(["kind": "transport_lost", "active": active, "resetting": resetting, "invalidated": invalidated])
    }
    func suspend() { send(["kind": "suspend"]) }
    func recover() { send(["kind": "recover"]) }
    func recheck() { send(["kind": "recheck"]) }
    @discardableResult
    private func send(_ event: [String: Any]) -> Bool {
        machine.send(event) { [weak self] action in self?.execute(action) }
    }
    private func execute(_ action: [String: Any]) {
        let token = action["token"] as? UInt64 ?? 0
        switch action["kind"] as? String {
        case "stop":
            stop(token, { [weak self] in self?.send(["kind": "local_stopped", "token": token]) },
                 { [weak self] in self?.send(["kind": "reply", "token": token]) })
        case "deadline", "release_deadline":
            let kind = action["kind"] as? String ?? "deadline"
            schedule(action["seconds"] as? Double ?? 3) { [weak self] in
                self?.send(["kind": kind, "token": token])
            }
        case "verify":
            let observation = action["observation"]!
            let cisco = usesCisco()
            verifyIdle { [weak self] status, held, state in
                self?.send(["kind": "result", "token": token, "observation": observation,
                            "status": status, "held": held, "uses_cisco": cisco, "cisco": state as Any? ?? NSNull()])
            }
            schedule(action["seconds"] as? Double ?? 3) { [weak self] in
                self?.send(["kind": "verify_timeout", "token": token, "observation": observation])
            }
        case "attention": needsAttention()
        case "settled": settled()
        case "recover_service": restartRecovery(action["active"] as? Bool ?? false)
        default: break
        }
    }
}
