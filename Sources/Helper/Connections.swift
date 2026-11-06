import Foundation

// The connections page (DESIGN.md §28.7): Rust lists and classifies
// (core/src/connections.rs); the engine shell asks with its session's
// context (CLIOrchestrator.connectionsJSON).

/// The interface the kernel routes an address through (routing socket,
/// RTM_GET; Rust).
enum RouteCache {
    static func interface(for ip: String) -> String? {
        guard let raw = ac_route_interface(ip) else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }
}

@_silgen_name("ac_route_interface")
func ac_route_interface(_ ip: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
