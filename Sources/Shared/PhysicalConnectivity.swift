import Foundation
import SystemConfiguration
import Darwin

/// Read-only physical service facts; a VPN default route cannot hide loss of
/// every en* router. No DNS request, location request or reachability poll.
enum PhysicalConnectivity {
    static func available() -> Bool {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return true } // Unknown is not offline.
        defer { freeifaddrs(head) }
        var active = Set<String>()
        var cursor = head
        while let entry = cursor {
            let item = entry.pointee
            let name = String(cString: item.ifa_name)
            let required = UInt32(IFF_UP | IFF_RUNNING)
            if name.hasPrefix("en"), item.ifa_flags & required == required {
                active.insert(name)
            }
            cursor = item.ifa_next
        }
        guard let store = SCDynamicStoreCreate(nil, "AlwaysConnect physical availability" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/IPv[46]" as CFString) as? [String]
        else { return true }
        return keys.contains { key in
            guard let service = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let name = service["InterfaceName"] as? String, active.contains(name),
                  let router = service["Router"] as? String, !router.isEmpty else { return false }
            return true
        }
    }
}
