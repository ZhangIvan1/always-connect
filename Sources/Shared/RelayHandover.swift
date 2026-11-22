import Foundation

/// System adapters execute the effects; Rust owns ticket validity and budgets.
final class RelayHandover {
    struct Reply: Decodable {
        let ok: Bool
        let code: String
        let ticket: String?
        let target: String?
        let attempt: UInt32
    }

    let handle = ac_relay_switch_new()!
    deinit { ac_relay_switch_free(handle) }

    func command(_ fields: [String: Any]) -> (Reply, String)? {
        guard let data = try? JSONSerialization.data(withJSONObject: fields),
              let text = String(data: data, encoding: .utf8),
              let raw = ac_relay_switch_command(handle, text) else { return nil }
        defer { ac_handover_string_free(raw) }
        let result = String(cString: raw)
        guard let decoded = try? JSONDecoder().decode(Reply.self, from: Data(result.utf8)) else { return nil }
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

@_silgen_name("ac_relay_switch_new") private func ac_relay_switch_new() -> OpaquePointer?
@_silgen_name("ac_relay_switch_free") private func ac_relay_switch_free(_ handle: OpaquePointer)
@_silgen_name("ac_relay_switch_command") private func ac_relay_switch_command(_ handle: OpaquePointer, _ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free") private func ac_handover_string_free(_ text: UnsafeMutablePointer<CChar>)
