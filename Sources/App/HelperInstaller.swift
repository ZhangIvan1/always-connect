import AppKit
import Security
import ServiceManagement

/// Installs the privileged Helper as a LaunchDaemon via SMAppService
/// (UI-DESIGN.md §七 Helper 未装 / 未运行).
///
/// The daemon plist + Helper binary are embedded in the App bundle by
/// the "Embed Helper daemon" build phase (project.yml):
/// Contents/Library/LaunchDaemons/. Real install effect needs a
/// signed build and admin authorization, so it is Mac-only to verify;
/// this code only compiles on CI.
///
/// register() on an already-registered service is treated as success:
/// the panel's install button must be idempotent. A first register()
/// of a daemon succeeds but leaves it in .requiresApproval until the
/// user enables it under System Settings > Login Items; that is not
/// success (the daemon is not running yet), so the installer opens
/// that pane and reports the pending approval instead.
enum HelperInstaller {
    /// The file name inside Contents/Library/LaunchDaemons, extension
    /// included: SMAppService looks the plist up by exact file name.
    private static let plistName = "com.alwaysconnect.app.helper.plist"

    enum InstallError: LocalizedError {
        case approvalRequired
        case notEnabled
        case cancelled
        case scriptFailed(String)

        var errorDescription: String? {
            switch self {
            case .approvalRequired:
                return "请在系统设置的登录项中允许 AlwaysConnect，再回到这里"
            case .notEnabled:
                return "后台服务未能启用，请检查系统设置中的登录项"
            case .cancelled:
                return "已取消：需要输入电脑密码才能安装"
            case .scriptFailed(let message):
                return "安装失败：\(message)"
            }
        }
    }

    /// Install failure in the user's words.
    static func failureText(_ error: Error) -> String {
        if let error = error as? InstallError {
            return error.errorDescription ?? "安装失败"
        }
        return "安装失败：\(error.localizedDescription)"
    }

    static var isTeamSigned: Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return false }
        return dict[kSecCodeInfoTeamIdentifier as String] != nil
    }

    static var status: SMAppService.Status {
        SMAppService.daemon(plistName: plistName).status
    }

    /// A build without a developer-team signature cannot use
    /// SMAppService at all. It installs the same daemon the classic way
    /// instead (DESIGN.md §21.8): the bundled dev-helper.sh, run as root
    /// behind the standard macOS administrator password dialog — the
    /// user never has to open a terminal.
    static let installPrompt = "AlwaysConnect 要安装后台服务（断线时封网用）。"
    static let updatePrompt = "AlwaysConnect 已更新，要同时更新后台服务（断线时封网用）。"

    private static func installWithAdminPassword(
        prompt: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard let script = Bundle.main.path(forResource: "dev-helper", ofType: "sh"),
              let helper = bundledHelperPath
        else {
            completion(.failure(InstallError.scriptFailed("App 包里缺少安装脚本")))
            return
        }
        func quoted(_ s: String) -> String {
            "quoted form of \"" + s.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let source = "do shell script (\(quoted(script))) & \" install \" & (\(quoted(helper))) "
            + "with prompt \"\(prompt)\" with administrator privileges"
        AdminScript.run(source) { result in
            if let code = result.errorNumber {
                completion(.failure(code == -128 ? InstallError.cancelled
                                                 : InstallError.scriptFailed(result.errorMessage ?? "未知错误")))
            } else {
                completion(.success(()))
            }
        }
    }

    /// The way out when the background service does not answer
    /// (DESIGN.md §25.5, F9): the bundled dev-helper.sh `recover`, as
    /// root behind the standard administrator password dialog —
    /// restores routes/DNS, empties our pf anchor, gives our pf enable
    /// reference back and clears the held state, without the service.
    static func forceRecover(completion: @escaping (Result<Void, Error>) -> Void) {
        guard let script = Bundle.main.path(forResource: "dev-helper", ofType: "sh") else {
            completion(.failure(InstallError.scriptFailed("App 包里缺少恢复脚本")))
            return
        }
        let quoted = "quoted form of \"" + script.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        let source = "do shell script (\(quoted)) & \" recover\" "
            + "with prompt \"AlwaysConnect 要强制恢复网络（后台服务没有响应）。\" with administrator privileges"
        AdminScript.run(source) { result in
            if let code = result.errorNumber {
                completion(.failure(code == -128 ? InstallError.cancelled
                                                 : InstallError.scriptFailed(result.errorMessage ?? "未知错误")))
            } else {
                completion(.success(()))
            }
        }
    }

    private static var bundledHelperPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LaunchDaemons/AlwaysConnectHelper").path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    /// Dev install only: the installed daemon's code differs from the
    /// one in this App (the App was rebuilt), so the panel offers an
    /// update. Compares the code-directory hashes, not the files: every
    /// rebuild re-signs with a new signing time, which made identical
    /// code look outdated and asked for the admin password for nothing.
    static var installedHelperOutdated: Bool {
        guard !isTeamSigned, let bundled = bundledHelperPath,
              let installed = codeHash(
                atPath: "/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper"),
              let current = codeHash(atPath: bundled)
        else { return false }
        return installed != current
    }

    private static func codeHash(atPath path: String) -> Data? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data
    }

    static func install(prompt: String = installPrompt,
                        completion: @escaping (Result<Void, Error>) -> Void) {
        guard isTeamSigned else {
            installWithAdminPassword(prompt: prompt, completion: completion)
            return
        }
        let service = SMAppService.daemon(plistName: plistName)
        if service.status == .enabled {
            completion(.success(()))
            return
        }
        do {
            if service.status != .requiresApproval {
                try service.register()
            }
            switch service.status {
            case .enabled:
                completion(.success(()))
            case .requiresApproval:
                SMAppService.openSystemSettingsLoginItems()
                completion(.failure(InstallError.approvalRequired))
            default:
                completion(.failure(InstallError.notEnabled))
            }
        } catch {
            completion(.failure(error))
        }
    }
}
