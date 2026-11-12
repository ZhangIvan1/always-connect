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

}

final class SettingsLink {
    static let shared = SettingsLink()

    private var transport: SettingsTransport?
    private var process: Process?
    private var cancellables = Set<AnyCancellable>()
    private var pendingReplies: [String: (String?) -> Void] = [:]

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
            transport?.send(["type": "show", "tab": tab ?? ""])
            return
        }
        if let tab { UserDefaults.standard.set(tab, forKey: "settingsTab") }
        guard let executable = Bundle.main.executableURL else { return }
        let p = Process()
        p.executableURL = executable
        p.arguments = ["--settings"]
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { return }
        _ = fcntl(pair[0], F_SETFD, FD_CLOEXEC)
        _ = fcntl(pair[1], F_SETFD, FD_CLOEXEC)
        let child = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        p.standardInput = child
        p.standardOutput = child
        p.standardError = FileHandle.nullDevice
        p.terminationHandler = { [weak self] ended in
            DispatchQueue.main.async {
                guard let self, self.process === ended else { return }
                self.transport?.close()
                self.transport = nil
                self.process = nil
            }
        }
        do {
            try p.run()
            try? child.close()
            process = p
            let output = dup(pair[0])
            guard output >= 0 else { Darwin.close(pair[0]); p.terminate(); return }
            transport = SettingsTransport(input: pair[0], output: output, receive: { [weak self] info in
                guard self?.process === p else { return }
                if info["type"] == "request" { self?.sendState() }
                if info["type"] == "action", let name = info["name"] {
                    self?.perform(name, argument: info["arg"] ?? "", id: info["id"])
                }
            }, ended: { [weak p] in if let p, p.isRunning { p.terminate() } })
        } catch {
            try? child.close()
            Darwin.close(pair[0])
            NSLog("AlwaysConnect: settings process failed to start")
        }
    }

    /// The App answers the settings process: state on request and on
    /// every change while it runs, and the actions it forwards.
    func startAppSide() {
        HelperClient.shared.objectWillChange
            .debounce(for: .milliseconds(150), scheduler: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self, let p = self.process, p.isRunning else { return }
                self.sendState()
            }
            .store(in: &cancellables)
    }

    private func sendState() {
        transport?.send(["type": "state", "json": HelperClient.shared.remoteSnapshot()])
    }

    private func reply(_ id: String?, _ result: String?) {
        guard let id else { return }
        var info = ["type": "reply", "id": id]
        if let result { info["result"] = result }
        transport?.send(info)
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
        case "menuBarSpeed": MenuBarSpeed.shared.apply()
        case "quit": AppQuit.request()  // the uninstaller, from Settings (not from this block, §37)
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
        guard AppIdentity.hasAppParent() else { exit(77) }
        var ready = false
        let fire = {
            guard !ready else { return }
            ready = true
            onReady()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { fire() }
        transport = SettingsTransport(input: STDIN_FILENO, output: STDOUT_FILENO, receive: { [weak self] info in
            switch info["type"] {
            case "state":
                guard let json = info["json"] else { return }
                HelperClient.shared.applyRemoteSnapshot(json)
                fire()
            case "reply":
                guard let id = info["id"], let done = self?.pendingReplies.removeValue(forKey: id) else { return }
                done(info["result"])
            case "show":
                let tab = info["tab"] ?? ""
                SettingsWindow.shared.show(tab: tab.isEmpty ? nil : tab)
            default: break
            }
        }, ended: { exit(0) })
        transport?.send(["type": "request"])
    }

    /// Forwards one action to the App; `done` gets its answer (nil after 3 s).
    func send(_ name: String, _ argument: String = "", done: ((String?) -> Void)? = nil) {
        var info = ["type": "action", "name": name, "arg": argument]
        if let done {
            let id = UUID().uuidString
            info["id"] = id
            pendingReplies[id] = done
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                self?.pendingReplies.removeValue(forKey: id)?(nil)
            }
        }
        transport?.send(info)
    }
}
