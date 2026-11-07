import AppKit
import Foundation
import ServiceManagement

/// Settings → 通用 → "卸载 AlwaysConnect" (DESIGN.md §31): takes the App
/// off this Mac and leaves nothing behind.
///
/// Order, so that a cancelled password dialog changes nothing:
///   1 the bundled uninstall.sh as root, behind the administrator password
///     dialog. It only stages a root-only copy of itself and returns; the
///     copy waits for this App to quit, then restores the direct network
///     and removes every file (system and the user's), the App included.
///   2 only after that succeeded: the keychain password (unless kept) and
///     the login item, which need this App's own identity
///   3 a normal quit: it ends the VPN and releases the network the usual
///     way (DESIGN.md §21.5) before the script takes over.
enum Uninstaller {
    enum Outcome {
        case started
        case failed(String)
        case cancelled
    }

    static func start(keepPassword: Bool, keepSettings: Bool,
                      completion: @escaping (Outcome) -> Void) {
        var arguments = [
            "--from-app",
            "--user", NSUserName(),
            // The menu-bar App's: from the settings process, its parent (§32.15).
            "--app-pid", String(AppRole.isSettings ? getppid() : ProcessInfo.processInfo.processIdentifier),
            "--app", Bundle.main.bundlePath,
        ]
        if keepSettings { arguments.append("--keep-settings") }
        PrivilegedBundle.run(resource: "uninstall.sh", arguments: arguments,
                             prompt: "AlwaysConnect 要卸载自己：断开 VPN、恢复直连，删除后台服务、随附组件和它留下的文件。") { result in
                if let code = result.errorNumber {
                    if code == -128 {
                        completion(.cancelled)
                    } else {
                        completion(.failed(result.errorMessage ?? "卸载没有开始"))
                    }
                    return
                }
                if !keepPassword {
                    KeychainStore.deleteAll()
                }
                // Harmless when it was never registered (or cannot be,
                // in builds without a developer team).
                try? SMAppService.mainApp.unregister()
                completion(.started)
                // Let the window show "正在卸载…" for a moment, then the
                // normal quit (VPN off, network released).
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                    if AppRole.isSettings {
                        SettingsLink.shared.send("quit")
                    } else {
                        AppQuit.request()
                    }
                }
        }
    }

}
