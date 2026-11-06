import AppKit
import Combine
import Foundation

/// The Settings window runs in its own short-lived process (DESIGN.md
/// §32.15, user: "用完后不再用的，及时回收"): the same App binary started
/// with `--settings`. Closing the window ends that process, so every byte
/// its SwiftUI pages used goes back to the system — a window released in
/// the long-running App still left ~15 MB of scattered memory behind.
///
/// The menu-bar App stays the only one that acts: the settings process
/// sends it what the user did (connect, split switch, drop protection,
/// list and network changes, hotkey, reminder setting, drop history) and
/// shows the state the App sends back. Read-only questions to the
/// background service (connections, diagnostics, traffic) it asks
/// directly, disconnecting after each answer. It never quits the VPN: its
/// quit is a plain exit, and it exits when the App does.
enum AppRole {
    static let isSettings = CommandLine.arguments.contains("--settings")
    /// Shared secret between the App and the settings process it started:
    /// actions without it are ignored.
    static let token: String = {
        if isSettings { return ProcessInfo.processInfo.environment["ALWAYSCONNECT_SETTINGS_TOKEN"] ?? "" }
        return UUID().uuidString
    }()
}

final class SettingsLink {
    static let shared = SettingsLink()

    private enum Name {
        static let state = Notification.Name("com.alwaysconnect.app.settings.state")
        static let request = Notification.Name("com.alwaysconnect.app.settings.request")
        static let action = Notification.Name("com.alwaysconnect.app.settings.action")
        static let reply = Notification.Name("com.alwaysconnect.app.settings.reply")
        static let show = Notification.Name("com.alwaysconnect.app.settings.show")
    }

    private let center = DistributedNotificationCenter.default()
    private var process: Process?
    private var cancellables = Set<AnyCancellable>()
    private var pendingReplies: [String: (String?) -> Void] = [:]
    private var parentWatch: DispatchSourceProcess?

    private init() {}

    // MARK: - Menu-bar App side

    /// The settings process is the app in front (its key presses reach
    /// the App's global hotkey monitor, which must not toggle the VPN
    /// while a new hotkey is being recorded there).
    var settingsInFront: Bool {
        guard let process, process.isRunning else { return false }
        return NSWorkspace.shared.frontmostApplication?.processIdentifier == process.processIdentifier
    }

    /// Opens Settings on `tab`: starts the settings process, or brings the
    /// running one forward.
    func show(tab: String?) {
        if let process, process.isRunning {
            center.postNotificationName(Name.show, object: nil,
                                        userInfo: ["tab": tab ?? "", "token": AppRole.token],
                                        deliverImmediately: true)
            return
        }
        if let tab { UserDefaults.standard.set(tab, forKey: "settingsTab") }
        guard let executable = Bundle.main.executableURL else { return }
        let p = Process()
        p.executableURL = executable
        p.arguments = ["--settings"]
        var env = ProcessInfo.processInfo.environment
        env["ALWAYSCONNECT_SETTINGS_TOKEN"] = AppRole.token
        p.environment = env
        p.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.process = nil }
        }
        do {
            try p.run()
            process = p
        } catch {
            NSLog("AlwaysConnect: settings process failed to start")
        }
    }

    /// The App answers the settings process: state on request and on
    /// every change while it runs, and the actions it forwards.
    func startAppSide() {
        center.addObserver(forName: Name.request, object: nil, queue: .main) { [weak self] note in
            guard Self.trusted(note) else { return }
            self?.sendState()
        }
        center.addObserver(forName: Name.action, object: nil, queue: .main) { [weak self] note in
            guard Self.trusted(note), let info = note.userInfo as? [String: String],
                  let name = info["name"] else { return }
            self?.perform(name, argument: info["arg"] ?? "", id: info["id"])
        }
        HelperClient.shared.objectWillChange
            .debounce(for: .milliseconds(150), scheduler: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self, let p = self.process, p.isRunning else { return }
                self.sendState()
            }
            .store(in: &cancellables)
    }

    private static func trusted(_ note: Notification) -> Bool {
        (note.userInfo?["token"] as? String) == AppRole.token && !AppRole.token.isEmpty
    }

    private func sendState() {
        let json = HelperClient.shared.remoteSnapshot()
        center.postNotificationName(Name.state, object: nil,
                                    userInfo: ["json": json, "token": AppRole.token],
                                    deliverImmediately: true)
    }

    private func reply(_ id: String?, _ result: String?) {
        guard let id else { return }
        var info = ["id": id, "token": AppRole.token]
        if let result { info["result"] = result }
        center.postNotificationName(Name.reply, object: nil, userInfo: info, deliverImmediately: true)
    }

    private func perform(_ name: String, argument: String, id: String?) {
        let client = HelperClient.shared
        switch name {
        case "setSplit": client.setSplit(on: argument == "1")
        case "deleteDrop": if let uuid = UUID(uuidString: argument) { client.deleteDrop(uuid) }
        case "clearDropHistory": client.clearDropHistory()
        case "dropProtectionChanged": client.dropProtectionChanged()
        case "credentialsChanged": client.credentialsChanged()
        case "connect": reply(id, client.connectWithStoredCredentials() ? "1" : "0"); return
        case "refreshStatus": client.refreshStatus()
        case "hotkey": HotkeyManager.shared.apply(ProfileStore.loadAppSettings())
        case "approvalCard": ApprovalPrompt.shared.settingsChanged()
        case "quit": NSApp.terminate(nil)  // the uninstaller, from Settings
        case "installUpdate": UpdateChecker.shared.installAvailable()  // §35.4
        case "pushDirectDomains":
            client.pushDirectDomains { [weak self] ok in self?.reply(id, ok.map { $0 ? "1" : "0" }) }
            return
        case "updateAllowNetworks":
            let networks = argument.split(separator: "\n").map(String.init)
            client.updateAllowNetworks(networks) { [weak self] ok in self?.reply(id, ok.map { $0 ? "1" : "0" }) }
            return
        default: break
        }
        reply(id, "1")
    }

    // MARK: - Settings process side

    /// Mirrors the App's state into this process's HelperClient, and ends
    /// this process when the App goes.
    /// `onReady` runs once the App's state is in (or after 1.5 s without
    /// it): the window must not open on the defaults — a page reading
    /// "disconnected" took our own tunnel and DNS forwarder for another
    /// VPN's (user screenshot, 2026-11-06).
    func startSettingsSide(onReady: @escaping () -> Void) {
        var ready = false
        let fire = {
            guard !ready else { return }
            ready = true
            onReady()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { fire() }
        center.addObserver(forName: Name.state, object: nil, queue: .main) { note in
            guard Self.trusted(note), let json = note.userInfo?["json"] as? String else { return }
            HelperClient.shared.applyRemoteSnapshot(json)
            fire()
        }
        center.addObserver(forName: Name.reply, object: nil, queue: .main) { [weak self] note in
            guard Self.trusted(note), let info = note.userInfo as? [String: String],
                  let id = info["id"], let done = self?.pendingReplies.removeValue(forKey: id) else { return }
            done(info["result"])
        }
        center.addObserver(forName: Name.show, object: nil, queue: .main) { note in
            guard Self.trusted(note) else { return }
            let tab = (note.userInfo?["tab"] as? String) ?? ""
            SettingsWindow.shared.show(tab: tab.isEmpty ? nil : tab)
        }
        center.postNotificationName(Name.request, object: nil, userInfo: ["token": AppRole.token],
                                    deliverImmediately: true)
        // The App is this process's parent: when it goes (quit, crash),
        // so does Settings — it must never outlive it.
        let parent = getppid()
        let watch = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: .main)
        watch.setEventHandler { exit(0) }
        watch.resume()
        parentWatch = watch
        if getppid() != parent || parent == 1 { exit(0) }
    }

    /// Forwards one action to the App; `done` gets its answer (nil after 3 s).
    func send(_ name: String, _ argument: String = "", done: ((String?) -> Void)? = nil) {
        var info = ["name": name, "arg": argument, "token": AppRole.token]
        if let done {
            let id = UUID().uuidString
            info["id"] = id
            pendingReplies[id] = done
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                self?.pendingReplies.removeValue(forKey: id)?(nil)
            }
        }
        center.postNotificationName(Name.action, object: nil, userInfo: info, deliverImmediately: true)
    }
}
