import Foundation

/// System adapters execute the effects; Rust owns ticket validity and budgets.
final class RelayHandover {
    struct Reply: Decodable {
        let ok: Bool
        let code: String
        let ticket: String?
        let target: String?
        let attempt: UInt32
        let epoch: String?
        let remaining_ms: UInt32?
    }

    let handle: OpaquePointer
    private var deadlineWork: DispatchWorkItem?
    init(budgetMilliseconds: UInt32 = 60_000) {
        handle = ac_relay_switch_new_with_budget(budgetMilliseconds)!
    }

    /// Dispatch only delivers the clock event; Rust checks intent, epoch,
    /// waiting phase and elapsed budget before accepting the timeout.
    func watchDeadline(session: String, queue: DispatchQueue, expired: @escaping () -> Void) {
        guard let (reply, _) = command(["op": "watch", "session": session]),
              reply.ok, let epoch = reply.epoch, let remaining = reply.remaining_ms else { return }
        deadlineWork?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.command(["op": "expire", "session": session, "epoch": epoch])?.0.code == "redirect_deadline"
            else { return }
            self.deadlineWork = nil
            expired()
        }
        deadlineWork = work
        queue.asyncAfter(deadline: .now() + Double(remaining) / 1000, execute: work)
    }
    deinit { deadlineWork?.cancel(); ac_relay_switch_free(handle) }

    func command(_ fields: [String: Any]) -> (Reply, String)? {
        guard let data = try? JSONSerialization.data(withJSONObject: fields),
              let text = String(data: data, encoding: .utf8),
              let raw = ac_relay_switch_command(handle, text) else { return nil }
        defer { ac_handover_string_free(raw) }
        let result = String(cString: raw)
        guard let decoded = try? JSONDecoder().decode(Reply.self, from: Data(result.utf8)) else { return nil }
        if decoded.ok && ["registered", "start_engine", "cancelled", "failed"].contains(decoded.code) {
            deadlineWork?.cancel()
            deadlineWork = nil
        }
        return (decoded, result)
    }

    static func target(_ server: String) -> String? {
        guard let address = GatewayAddress(server) else { return nil }
        return "https://\(address.host.lowercased()):\(address.port)/"
    }
}

struct RelayConnectionContext: Codable {
    let session: String
    let target: String
    let pin: String
    let allowed: [String]
}

@_silgen_name("ac_relay_switch_new_with_budget") private func ac_relay_switch_new_with_budget(_ milliseconds: UInt32) -> OpaquePointer?
@_silgen_name("ac_relay_switch_free") private func ac_relay_switch_free(_ handle: OpaquePointer)
@_silgen_name("ac_relay_switch_command") private func ac_relay_switch_command(_ handle: OpaquePointer, _ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free") private func ac_handover_string_free(_ text: UnsafeMutablePointer<CChar>)
