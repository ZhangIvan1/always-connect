import AppKit

/// Global hotkey (UI-DESIGN.md §五通用页, default off).
///
/// The combo is recorded by the General page (key code + device
/// independent modifier flags + display characters) and stored in
/// AppSettings. The global monitor needs Input Monitoring permission;
/// without it the monitor silently never fires, so the General page
/// carries a hint line. A plain key without modifiers is never
/// accepted at record time, so normal typing cannot toggle the VPN.
final class HotkeyManager: ObservableObject {
    static let shared = HotkeyManager()

    /// Called when the recorded combo is pressed: AppDelegate wires it
    /// to connect/disconnect.
    var onHotkey: (() -> Void)?

    private var globalMonitor: Any?
    private var localMonitor: Any?

    private init() {}

    func apply(_ settings: AppSettings) {
        // The global hotkey belongs to the menu-bar App (§32.15).
        if AppRole.isSettings { SettingsLink.shared.send("hotkey"); return }
        if let monitor = globalMonitor {
            NSEvent.removeMonitor(monitor)
            globalMonitor = nil
        }
        guard settings.globalHotkeyEnabled,
              let code = settings.hotkeyKeyCode,
              let mods = settings.hotkeyModifiers else { return }
        globalMonitor = NSEvent.addGlobalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard event.keyCode == code,
                  event.modifierFlags.intersection(.deviceIndependentFlagsMask).rawValue == mods else { return }
            self?.onHotkey?()
        }
    }

    func startRecording(onCaptured: @escaping (UInt16, UInt, String) -> Void) {
        stopRecording()
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask).rawValue
            guard mods != 0 else { return event }
            onCaptured(event.keyCode, mods, event.charactersIgnoringModifiers ?? "")
            return event
        }
    }

    func stopRecording() {
        if let monitor = localMonitor {
            NSEvent.removeMonitor(monitor)
            localMonitor = nil
        }
    }

    /// Display string for a recorded combo, e.g. "⌃⌥V".
    static func describe(settings: AppSettings) -> String {
        guard let code = settings.hotkeyKeyCode,
              let mods = settings.hotkeyModifiers else { return "未设置" }
        var symbols = ""
        let flags = NSEvent.ModifierFlags(rawValue: mods)
        if flags.contains(.control) { symbols += "⌃" }
        if flags.contains(.option) { symbols += "⌥" }
        if flags.contains(.shift) { symbols += "⇧" }
        if flags.contains(.command) { symbols += "⌘" }
        let chars = settings.hotkeyCharacters ?? ""
        if chars.isEmpty {
            return "\(symbols)按键 \(code)"
        }
        return symbols + chars.uppercased()
    }
}
