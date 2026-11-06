import AppKit
import SwiftUI

/// Owns the Settings window (UI-DESIGN.md §二主窗口).
///
/// Deliberately AppKit-managed, not a SwiftUI Settings scene: the
/// scene's programmatic openers (SettingsLink, openSettings) need
/// macOS 14, while this app targets macOS 13. The menu-bar panel is
/// the entry point (LSUIElement apps have no app menu), so the panel
/// entries call show() directly. The window and its SwiftUI pages are
/// released when it closes (§28.6: kept forever they held the App's
/// memory up all day); the next open builds them again.
///
/// In the menu-bar App, show() starts the settings process instead
/// (§32.15); the window itself only ever lives in that process, which
/// exits when it closes.
final class SettingsWindow: NSObject, NSWindowDelegate {
    static let shared = SettingsWindow()
    static let size = NSSize(width: 620, height: 560)

    private var window: NSWindow?

    private override init() {}

    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? NSWindow, closing === window else { return }
        closing.delegate = nil
        // Let the close finish first, then drop the pages and the window.
        DispatchQueue.main.async { [weak self] in
            closing.contentViewController = nil
            if self?.window === closing { self?.window = nil }
            // The settings process has done its job: everything it used
            // goes back to the system with it. Never the quit path, which
            // would end the VPN.
            if AppRole.isSettings { exit(0) }
        }
    }

    /// A menu-bar (LSUIElement) app is not active when its status item
    /// is clicked, so a plain makeKeyAndOrderFront left the window
    /// behind whatever app was in front (user report, 2026-11-03):
    /// activate first, then bring the window up.
    func show(tab: String? = nil) {
        guard AppRole.isSettings else {
            SettingsLink.shared.show(tab: tab)
            return
        }
        if let tab {
            UserDefaults.standard.set(tab, forKey: "settingsTab")
        }
        NSApp.activate(ignoringOtherApps: true)
        if let window {
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
        }
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: Self.size),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.contentViewController = NSHostingController(rootView: SettingsView())
        window.title = "AlwaysConnect 设置"
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        self.window = window
    }
}
