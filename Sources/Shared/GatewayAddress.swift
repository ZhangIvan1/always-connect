import Foundation

/// Host and port of a gateway address as the user or a Cisco profile
/// writes it: "host", "host/group", "host:8443", "https://host:8443/x".
/// Shared by the App's certificate relay (which listens on 127.0.0.1 at
/// the same port) and the Helper (which points openconnect's --resolve
/// at it), so both sides agree on the pair (DESIGN.md §二十三).
struct GatewayAddress: Equatable {
    var host: String
    var port: UInt16

    init?(_ server: String) {
        var text = server.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }
        if !text.contains("://") { text = "https://" + text }
        guard let components = URLComponents(string: text),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil
        else { return nil }
        let port = components.port ?? 443
        guard (1...65535).contains(port) else { return nil }
        self.host = host
        self.port = UInt16(port)
    }
}
