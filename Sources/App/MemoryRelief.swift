import Darwin
import Foundation

/// Hands freed heap back to the system (DESIGN.md §45.5; user, 2026-11-12:
/// "这么多内存是都在干嘛？" then "做"). The allocator keeps pages a
/// program has freed for reuse until the system is short of memory; on
/// the user's Mac about 10 of the App's 29 MB were such pages, left by
/// opening the panel and by connecting. Asked once at those moments
/// (not on a timer), a short while after, so the freed objects are gone.
enum MemoryRelief {
    private static var pending = false

    /// Once, `delay` seconds from now; repeated calls in between collapse.
    static func soon(after delay: TimeInterval = 2) {
        guard !pending else { return }
        pending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            pending = false
            _ = malloc_zone_pressure_relief(nil, 0)
        }
    }
}
