import Foundation

@_silgen_name("ac_speed_totals")
private func ac_speed_totals() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_speed_totals_stop")
private func ac_speed_totals_stop()
@_silgen_name("ac_string_free")
private func speed_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// The panel's 网速 card (DESIGN.md §45.4; user, 2026-11-12: not in the
/// menu bar all the time, only when the panel is opened). Lives with the
/// panel's SwiftUI tree: `start` on appear, `stop` on disappear (the
/// panel is released when it closes, §32.1). While open, every 3 s with
/// tolerance, the Rust core reads the interface counters once (one
/// sysctl, about 0.4 ms, no process) and returns the totals.
final class PanelSpeed: ObservableObject {
    struct Totals: Decodable, Equatable {
        var ready: Bool
        var total: [Int]
        var vpn: [Int]
        var direct: [Int]
    }

    /// Nil until the second reading (a speed needs two).
    @Published private(set) var totals: Totals?
    private var timer: Timer?

    func start() {
        guard timer == nil else { return }
        read()
        // The first numbers after 1 s, then every 3 s.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self, self.timer != nil else { return }
            self.read()
        }
        let t = Timer(timeInterval: 3, repeats: true) { [weak self] _ in self?.read() }
        t.tolerance = 0.5
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func stop() {
        guard let timer else { return }
        timer.invalidate()
        self.timer = nil
        totals = nil
        ac_speed_totals_stop()
    }

    deinit {
        if let timer {
            timer.invalidate()
            ac_speed_totals_stop()
        }
    }

    private func read() {
        guard let raw = ac_speed_totals() else { return }
        defer { speed_string_free(raw) }
        let decoded = try? JSONDecoder().decode(Totals.self, from: Data(String(cString: raw).utf8))
        let next = decoded?.ready == true ? decoded : nil
        if next != totals { totals = next }
    }

    /// "2.4 MB/s", "180 KB/s", "980 B/s".
    static func text(_ bytes: Int) -> String {
        switch bytes {
        case ..<1000: return "\(bytes) B/s"
        case ..<1_000_000: return "\(bytes / 1000) KB/s"
        case ..<10_000_000: return String(format: "%.1f MB/s", Double(bytes) / 1_000_000)
        default: return "\(bytes / 1_000_000) MB/s"
        }
    }
}
