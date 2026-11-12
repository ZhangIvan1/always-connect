import Combine
import SwiftUI

/// Menu-bar-only app (LSUIElement): no Dock icon.
/// The menu bar panel is the primary interface; the main window remains as
/// the second entry point for Settings and rule editing (per Apple HIG,
/// a menu bar extra must not be the sole route to a feature).
@main
struct AlwaysConnectApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        // The real Settings window is AppKit-managed (SettingsWindow)
        // and opened from the menu bar panel: SwiftUI's programmatic
        // Settings openers need macOS 14 while this app targets 13.
        // An empty Settings scene is only the required placeholder:
        // unlike a WindowGroup, it opens no window at launch (a
        // WindowGroup put a blank 900x450 window on screen, measured
        // 2026-11-03).
        Settings {
            EmptyView()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var panelController: PanelController?
    private var cancellables = Set<AnyCancellable>()
    private var wizardWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // One administrator AppleScript for the App, then gone (§32.16).
        if AdminScript.isChild { AdminScript.serveAndExit() }
        // The settings process (§32.15): only the Settings window, its
        // state mirrored from the menu-bar App that started it.
        if AppRole.isSettings {
            SettingsLink.shared.startSettingsSide { SettingsWindow.shared.show() }
            return
        }
        // One App at a time (§25.4, F13): a second copy would see the
        // first one's disconnect as a drop and fight over the relay
        // port. Hand over to the running one and leave WITHOUT the quit
        // path — that would disconnect the first copy's VPN.
        if let other = Self.otherRunningCopy() {
            other.activate(options: [])
            exit(0)
        }
        panelController = PanelController(manager: HelperClient.shared)
        // On a notched display the space right of the notch is shared
        // with the frontmost app's overflowing menus; the newest status
        // item (leftmost) is the first one macOS hides — the "icon
        // vanishes when I switch displays" report (2026-11-03). Start
        // next to the system items on the right instead, unless the
        // user has already ⌘-dragged it somewhere (then keep that).
        let positionKey = "NSStatusItem Preferred Position AlwaysConnectStatusItem"
        if UserDefaults.standard.object(forKey: positionKey) == nil {
            UserDefaults.standard.set(230, forKey: positionKey)
        }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem?.autosaveName = "AlwaysConnectStatusItem"
        // The icon is the App's only way in, so it always comes back on
        // launch. AppKit saves isVisible under the autosave name: the
        // quit path hides the icon at once (§23.8), that "hidden" was
        // saved, and the next launch showed no icon at all (2026-11-05).
        statusItem?.isVisible = true
        statusItem?.button?.target = self
        statusItem?.button?.action = #selector(togglePanel(_:))
        updateStatusIcon(state: HelperClient.shared.state, held: false)
        // "菜单栏显示网速" (§四十五): off by default; nothing runs then.
        MenuBarSpeed.shared.onChange = { [weak self] in self?.updateSpeedTitle() }
        MenuBarSpeed.shared.apply()
        HelperClient.shared.$state
            .combineLatest(HelperClient.shared.$networkHeld)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state, held in self?.updateStatusIcon(state: state, held: held) }
            .store(in: &cancellables)
        // Attach to the Helper first: a session it kept running while
        // the App was closed must show up even without auto-connect.
        HelperClient.shared.refreshStatus()
        Notifier.shared.requestAuthorization()
        SettingsLink.shared.startAppSide()
        ApprovalPrompt.shared.anchor = { [weak self] in self?.statusItem?.button }
        ApprovalPrompt.shared.openPanel = { [weak self] in self?.togglePanel(nil) }
        ApprovalPrompt.shared.start()
        HelperClient.shared.checkLastRelease()
        // Update check (DESIGN.md §三十三): no timer; at most once a day,
        // here and on panel open, after the launch's own work settled.
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            UpdateChecker.shared.checkIfDue()
        }
        // Auto-connect on launch when credentials are stored — after
        // updating a background service older than this App (one
        // password prompt, §30.5), so the update never lands on a live
        // session.
        // Servers saved in the Mac's Cisco join the list, changes there
        // are followed (DESIGN.md §三十八): read-only, once per launch.
        ProfileStore.syncWithCisco()
        let profile = ProfileStore.loadProfile()
        HelperClient.shared.updateHelperAtLaunch(thenConnect: profile.autoConnectOnLaunch)
        // Global hotkey (General page): toggles the connection.
        HotkeyManager.shared.onHotkey = {
            guard !SettingsLink.shared.settingsInFront else { return }
            if HelperClient.shared.switchIsOn {
                HelperClient.shared.disconnect()
            } else {
                _ = HelperClient.shared.connectWithStoredCredentials()
            }
        }
        HotkeyManager.shared.apply(ProfileStore.loadAppSettings())
        // First run: no username stored yet -> show the wizard.
        if ProfileStore.loadUsername() == nil {
            showWizard()
        }
    }

    /// Another running AlwaysConnect (same bundle id, another pid).
    static func otherRunningCopy() -> NSRunningApplication? {
        guard let id = Bundle.main.bundleIdentifier else { return nil }
        let me = ProcessInfo.processInfo.processIdentifier
        return NSRunningApplication.runningApplications(withBundleIdentifier: id)
            .first { $0.processIdentifier != me && !$0.isTerminated }
    }

    @objc private func togglePanel(_ sender: Any?) {
        guard let button = statusItem?.button else { return }
        ApprovalPrompt.shared.panelOpened()
        panelController?.toggle(relativeTo: button)
    }

    private func showWizard() {
        let view = WizardView(onDone: { [weak self] in
            self?.wizardWindow?.close()
        })
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 480),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: view)
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        wizardWindow = window
        // Closed = gone (§32.1): the wizard is shown once, its pages
        // need not stay for the rest of the run.
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
            token.map(NotificationCenter.default.removeObserver)
            DispatchQueue.main.async {
                window.contentViewController = nil
                if self?.wizardWindow === window { self?.wizardWindow = nil }
            }
        }
    }

    /// Opening the App again (Finder, Spotlight, Launchpad) while it
    /// runs shows the Settings window: with a crowded menu bar (notch,
    /// many icons, the other display active) macOS may hide our status
    /// icon, and this keeps every function reachable anyway.
    ///
    /// Not right after launch, though (DESIGN.md §21.20): several
    /// `open` calls landing together (a script, a login item plus a
    /// click, an impatient double launch) start the App once and send
    /// every later one as a reopen event, which put the Settings
    /// window on screen at launch (measured 2026-11-04: three `open`
    /// within 90 ms -> one launch + two reopens). A reopen within the
    /// first few seconds is part of that same launch, not a request.
    private let launchedAt = Date()
    static let reopenGraceSeconds: TimeInterval = 5

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if AppRole.isSettings {
            SettingsWindow.shared.show()
            return false
        }
        if Date().timeIntervalSince(launchedAt) < Self.reopenGraceSeconds {
            return false
        }
        NSApp.activate(ignoringOtherApps: true)
        SettingsWindow.shared.show()
        return false
    }

    /// Every quit path (panel button, ⌘Q in Settings, logout) ends the
    /// VPN and restores the direct network first (DESIGN.md §21.5). A
    /// Helper that does not answer cannot hold the quit hostage: after
    /// 15 s the App quits anyway.
    private var quitting = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // ⌘Q in the settings process closes Settings only; the VPN is the
        // menu-bar App's (§32.15).
        if AppRole.isSettings { return .terminateNow }
        if quitting { return .terminateNow }
        quitting = true
        // Answer the click at once (DESIGN.md §23.8): the icon and any
        // window go now; the VPN wind-down below can take a while when
        // Cisco is in the middle of a login waiting for the phone.
        statusItem?.isVisible = false
        NSApp.windows.forEach { $0.orderOut(nil) }
        // Cisco's windows are closed only when the App was running the
        // Cisco session itself (§25.4): never in the own-connection
        // mode, never for a session the user started in Cisco.
        let closeCiscoWindows = HelperClient.shared.cisco?.isManaging ?? false
        var replied = false
        let reply = {
            guard !replied else { return }
            replied = true
            // Nothing of ours outlives the App (DESIGN.md §23.11): a
            // Cisco CLI call the 15 s cap cut short, an openssl or ping
            // still running, and Cisco's own windows.
            DispatchQueue.global(qos: .userInitiated).async {
                Self.cleanUpBeforeExit(closeCiscoWindows: closeCiscoWindows)
                // From the run loop, not the main queue (§37): the
                // reply must land even if terminate was called from
                // inside a main-queue block.
                AppQuit.onRunLoop {
                    NSApp.reply(toApplicationShouldTerminate: true)
                }
            }
        }
        HelperClient.shared.shutdownForQuit { reply() }
        // The 15 s cap is a run-loop timer in every mode, not a main-queue
        // block: it fires even when the quit was started from inside one
        // and the main queue is stalled (§37).
        let cap = Timer(timeInterval: 15, repeats: false) { _ in reply() }
        RunLoop.main.add(cap, forMode: .common)
        return .terminateLater
    }

    /// Cisco Secure Client's window app and its login browser: asked to
    /// quit (never forced) — the user wants nothing VPN-related left
    /// open after quitting. Cisco's system parts (vpnagentd, the
    /// network extension) are Cisco's and stay.
    static let ciscoWindowBundleIDs = [CiscoEngine.guiBundleID, "com.cisco.anyconnect.acwebhelper"]

    private static func cleanUpBeforeExit(closeCiscoWindows: Bool) {
        let ciscoApps = closeCiscoWindows ? ciscoWindowBundleIDs.flatMap {
            NSRunningApplication.runningApplications(withBundleIdentifier: $0)
        } : []
        ciscoApps.forEach { $0.terminate() }
        let killed = ProcessSweep.terminateDescendants(grace: 2)
        if !killed.isEmpty {
            NSLog("AlwaysConnect: quit force-ended %d child process(es)", killed.count)
        }
        for _ in 0..<20 where !ciscoApps.allSatisfy({ $0.isTerminated }) {
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // The VPN was already ended in applicationShouldTerminate.
        // A crash never gets here: then the Helper keeps whatever kill
        // switch was in force (fail closed), and reopening the App
        // shows it with the restore button.
    }

    /// The speed next to the icon when "菜单栏显示网速" is on. A fixed
    /// width (the widest text) so the menu bar does not shift each time.
    private func updateSpeedTitle() {
        guard let item = statusItem, let button = item.button else { return }
        let speed = MenuBarSpeed.shared
        guard speed.isOn else {
            button.title = ""
            button.imagePosition = .imageOnly
            item.length = NSStatusItem.squareLength
            return
        }
        let font = NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        let widest = ("↓8.8M ↑888K" as NSString).size(withAttributes: [.font: font]).width
        item.length = ceil(widest) + 30
        button.imagePosition = .imageLeft
        button.attributedTitle = NSAttributedString(string: speed.menuBarText, attributes: [.font: font])
    }

    /// Color + shape double encoding (UI-DESIGN.md §一.2/§三): green
    /// solid = connected, yellow triangle = connecting/authenticating/
    /// awaiting approval, red hollow = disconnected with kill switch
    /// on (reconnecting, or disconnected with the network still held),
    /// gray ring = manual disconnect.
    private func updateStatusIcon(state: HelperClient.State, held: Bool) {
        guard let button = statusItem?.button else { return }
        let look = StatusLook.of(state, held: held,
                                 hasCredentials: HelperClient.shared.hasCredentials)
        // Globe + state badge (GlobeIcon); drawn with label
        // colours, so it follows the light/dark menu bar by itself.
        button.image = GlobeIcon.image(GlobeIcon.badge(for: state, held: held))
        button.contentTintColor = nil
        button.toolTip = "AlwaysConnect：\(look.headline)"
    }

}
