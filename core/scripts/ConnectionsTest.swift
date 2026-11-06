// The connections page through the daemon's shell (DESIGN.md §28.7,
// §32.9): the Rust listing decodes as the App's ConnectionRow array, and
// the kernel route lookup answers. Classification has cargo tests
// (core/src/connections.rs). Reads this Mac's sockets and routing table
// only; changes nothing.
import Foundation

@main
struct ConnectionsTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        check("kernel route lookup answers (lo0 for 127.0.0.1)", RouteCache.interface(for: "127.0.0.1") == "lo0")
        let t0 = Date()
        for _ in 0..<500 { _ = RouteCache.interface(for: "8.8.8.8") }
        check("route lookups are cheap (\(Int(Date().timeIntervalSince(t0) * 1000)) ms for 500)",
              Date().timeIntervalSince(t0) < 1)
        let raw = ac_oc_connections_json(nil, "")
        let json = raw.map { String(cString: $0) } ?? "[]"
        ac_string_free(raw)
        let rows = try? JSONDecoder().decode([ConnectionRow].self, from: Data(json.utf8))
        check("the listing decodes as ConnectionRow (\(rows?.count ?? -1) rows)", rows != nil)
        check("every row is classified", rows?.allSatisfy { ["vpn", "direct", "local"].contains($0.via) } ?? false)
        print("connections FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}

@_silgen_name("ac_oc_connections_json")
func ac_oc_connections_json(_ e: OpaquePointer?, _ fallback: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)
