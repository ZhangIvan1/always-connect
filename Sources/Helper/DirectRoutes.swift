import Foundation
import SystemConfiguration

/// Host and network routes that send the split's direct addresses out the
/// physical interface (DESIGN.md §26.5), with their journal (written
/// before a route is added; undone on disconnect, at the next daemon
/// start of the same boot and by the reset tool). The journal, the route
/// commands and the choice of networks are Rust (core/src/direct_routes.rs,
/// §32.10); this is the orchestrator's shell, same interface as before.
final class DirectRoutes {
    private let handle: OpaquePointer

    init(supportDir: URL, noRoutes: Bool) {
        handle = ac_routes_new(supportDir.appendingPathComponent("direct-routes").path,
                               BootSession.id ?? "", noRoutes)!
    }

    deinit { ac_routes_free(handle) }

    /// Route `ips` via `gateway` (the physical default gateway). Returns
    /// once the routes are in place.
    func add(_ ips: [String], via gateway: String) {
        guard !ips.isEmpty else { return }
        ac_routes_add(handle, ips.joined(separator: ","), gateway)
    }

    /// The physical network changed (§28.1): every route moves to `gateway`.
    func repoint(to gateway: String) { ac_routes_repoint(handle, gateway) }

    /// Takes routes out mid-session (a network rule removed from the list).
    func remove(_ entries: [String]) {
        guard !entries.isEmpty else { return }
        ac_routes_remove(handle, entries.joined(separator: ","))
    }

    /// Every route in the journal out, then the journal.
    func removeAll() { ac_routes_remove_all(handle) }

    var addresses: [String] { Self.list(ac_routes_addresses(handle)) }

    /// Daemon start: a journal from this boot is undone, one from another
    /// boot only dropped. "none", "dropped" or "removed N".
    @discardableResult
    static func undoAtStart(supportDir: URL, noRoutes: Bool) -> String {
        guard let raw = ac_routes_undo_at_start(supportDir.appendingPathComponent("direct-routes").path,
                                                BootSession.id, noRoutes) else { return "none" }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }

    /// Which networks get a route via the physical gateway (§28.5): all
    /// but those inside a network the Mac sits on.
    static func networksToRoute(_ networks: [String], attached: [(UInt32, UInt32)]) -> [String] {
        list(ac_routes_networks_to_route(networks.joined(separator: ","),
                                          attached.map { "\($0.0)-\($0.1)" }.joined(separator: ",")))
    }

    /// The IPv4 networks of every wired/Wi-Fi interface that is up.
    static func attachedNetworks() -> [(UInt32, UInt32)] {
        list(ac_routes_attached()).compactMap { item in
            let parts = item.split(separator: "-")
            guard parts.count == 2, let a = UInt32(parts[0]), let b = UInt32(parts[1]) else { return nil }
            return (a, b)
        }
    }

    private static func list(_ raw: UnsafeMutablePointer<CChar>?) -> [String] {
        guard let raw else { return [] }
        defer { ac_string_free(raw) }
        return String(cString: raw).split(separator: ",").map(String.init)
    }
}

@_silgen_name("ac_routes_new")
func ac_routes_new(_ journal: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>, _ noRoutes: Bool) -> OpaquePointer?
@_silgen_name("ac_routes_free")
func ac_routes_free(_ r: OpaquePointer)
@_silgen_name("ac_routes_add")
func ac_routes_add(_ r: OpaquePointer, _ entries: UnsafePointer<CChar>, _ gateway: UnsafePointer<CChar>)
@_silgen_name("ac_routes_repoint")
func ac_routes_repoint(_ r: OpaquePointer, _ gateway: UnsafePointer<CChar>)
@_silgen_name("ac_routes_remove")
func ac_routes_remove(_ r: OpaquePointer, _ entries: UnsafePointer<CChar>)
@_silgen_name("ac_routes_remove_all")
func ac_routes_remove_all(_ r: OpaquePointer)
@_silgen_name("ac_routes_addresses")
func ac_routes_addresses(_ r: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_routes_undo_at_start")
func ac_routes_undo_at_start(_ journal: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>?,
                             _ noRoutes: Bool) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_routes_attached")
func ac_routes_attached() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_routes_networks_to_route")
func ac_routes_networks_to_route(_ networks: UnsafePointer<CChar>, _ attached: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

/// The IPv4 network an interface sits on ("a.b.c.0/n"), from its own
/// address and mask; nil when it has none.
/// The Mac's physical network (§28.1): the router of a wired/Wi-Fi
/// service, read from configd, so it is known also while our tunnel
/// holds the default route. The given interface wins when it still has
/// one; otherwise any other en* (Wi-Fi to Ethernet, a phone hotspot).
enum PhysicalNetwork {
    static func current(preferring interface: String) -> (gateway: String, interface: String)? {
        guard let store = SCDynamicStoreCreate(nil, "AlwaysConnect" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/IPv4" as CFString) as? [String]
        else { return nil }
        var found: [(gateway: String, interface: String)] = []
        for key in keys {
            guard let ipv4 = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let name = ipv4["InterfaceName"] as? String, name.hasPrefix("en"),
                  let router = ipv4["Router"] as? String, isValidIPv4(router) else { continue }
            found.append((router, name))
        }
        return found.first { $0.interface == interface } ?? found.sorted { $0.interface < $1.interface }.first
    }
}

/// IPv4 dotted quad only.
func isValidIPv4(_ value: String) -> Bool {
    var v4 = in_addr()
    return inet_pton(AF_INET, value, &v4) == 1
}

/// The local network's own DNS servers: the ones configd keeps for the
/// service on the physical interface (our tunnel entries are separate
/// keys, so they are never mistaken for these), else DHCP's.
enum LocalDNS {
    static func servers(for interface: String) -> [String] {
        if let store = SCDynamicStoreCreate(nil, "AlwaysConnect" as CFString, nil, nil),
           let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/IPv4" as CFString) as? [String] {
            for key in keys {
                guard let ipv4 = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                      ipv4["InterfaceName"] as? String == interface else { continue }
                let dnsKey = key.replacingOccurrences(of: "/IPv4", with: "/DNS")
                if let dns = SCDynamicStoreCopyValue(store, dnsKey as CFString) as? [String: Any],
                   let servers = dns["ServerAddresses"] as? [String] {
                    let v4 = servers.filter(isValidIPv4)
                    if !v4.isEmpty { return v4 }
                }
            }
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/ipconfig")
        p.arguments = ["getoption", interface, "domain_name_server"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return [] }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        let one = out.trimmingCharacters(in: .whitespacesAndNewlines)
        return isValidIPv4(one) ? [one] : []
    }
}
