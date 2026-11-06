import Darwin
import Foundation

/// Which boot of this Mac we are in (DESIGN.md §23.12, §25.2).
///
/// The network gate's record is fail-closed memory for a background
/// service that restarts while the machine keeps running (a crash, an
/// update). Across a reboot it is stale: the tunnel, the App and every
/// route are gone, and a blocking set loaded at boot — with no App
/// running and no way to restore from the panel — cut the user's Mac
/// off the network (2026-11-04). kern.bootsessionuuid changes on every
/// boot; a wall-clock comparison (the first fix) could be fooled by a
/// clock change.
enum BootSession {
    /// kern.bootsessionuuid, nil when it cannot be read.
    static let id: String? = {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return nil }
        let value = String(cString: buffer)
        return value.isEmpty ? nil : value
    }()

    /// A record from `recorded` belongs to this boot. Unknown on either
    /// side counts as another boot: a held network nobody can release
    /// is the worse failure than one missed restore after a crash.
    static func isCurrent(_ recorded: String?) -> Bool {
        guard let recorded, let id else { return false }
        return recorded == id
    }
}
