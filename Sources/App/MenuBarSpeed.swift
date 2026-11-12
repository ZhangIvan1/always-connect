import AppKit
import Foundation

@_silgen_name("ac_speed_totals")
private func ac_speed_totals() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_speed_totals_stop")
private func ac_speed_totals_stop()
@_silgen_name("ac_string_free")
private func speed_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// "菜单栏显示网速" (DESIGN.md §四十五; user, 2026-11-12: an option, off
/// by default). Off: nothing runs. On: every 2 s (with tolerance) the
/// Rust core reads the interface counters once (one sysctl, no process)
/// and returns the totals; the menu bar shows the whole Mac's speed next
/// to the icon, the panel the VPN and direct parts.
final class MenuBarSpeed: ObservableObject {
    static let shared = MenuBarSpeed()

    struct Totals: Decodable, Equatable {
        var ready: Bool
        var total: [Int]
        var vpn: [Int]
        var direct: [Int]
    }

    /// Nil while off or before the second reading.
    @Published private(set) var totals: Totals?
    /// The menu bar text changed (AlwaysConnectApp redraws the item).
    var onChange: (() -> Void)?
    private var timer: Timer?

    var isOn: Bool { timer != nil }

    /// Settings → 通用 changed it (from the settings process too, via
    /// SettingsLink "menuBarSpeed").
    static func settingsChanged() {
        if AppRole.isSettings { SettingsLink.shared.send("menuBarSpeed"); return }
        shared.apply()
    }

    /// Starts or stops to match the stored setting.
    func apply() {
        let on = ProfileStore.loadAppSettings().isMenuBarSpeedOn
        if on, timer == nil {
            read()
            let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.read() }
            t.tolerance = 0.5
            RunLoop.main.add(t, forMode: .common)
            timer = t
        } else if !on, let timer {
            timer.invalidate()
            self.timer = nil
            totals = nil
            ac_speed_totals_stop()
        }
        onChange?()
    }

    private func read() {
        guard let raw = ac_speed_totals() else { return }
        defer { speed_string_free(raw) }
        let decoded = try? JSONDecoder().decode(Totals.self, from: Data(String(cString: raw).utf8))
        let next = decoded?.ready == true ? decoded : nil
        guard next != totals else { return }
        totals = next
        onChange?()
    }

    /// "↓2.4M ↑180K" for the menu bar; "↓0 ↑0" before the second reading.
    var menuBarText: String {
        let t = totals?.total ?? [0, 0]
        return "↓" + Self.rate(t[0]) + " ↑" + Self.rate(t[1])
    }

    static func rate(_ bytes: Int) -> String { ConnectionsPage.rate(bytes) }
}
