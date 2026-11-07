import Foundation

/// Build the trusted bootstrap itself in the running App. The root shell
/// copies first and verifies that private snapshot before executing code.
enum PrivilegedBundle {
    static func shellQuoted(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScriptString(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func source(resource: String, arguments: [String], helper: Bool = false, prompt: String) -> String? {
        guard ["dev-helper.sh", "reset-network.sh", "uninstall.sh"].contains(resource),
              let requirement = AppIdentity.leafRequirement else { return nil }
        let command = bootstrap(bundle: Bundle.main.bundlePath, requirement: requirement,
                                resource: resource, arguments: arguments, helper: helper)
        return "do shell script \(appleScriptString("/bin/bash -c " + shellQuoted(command))) "
            + "with prompt \(appleScriptString(prompt)) with administrator privileges"
    }

    static let unsignedMessage = "此开发构建没有可验证的签名证书，不能通过密码框运行管理脚本。请使用已有开发证书重新构建；手动终端安装或恢复仍可用。"

    // Internal for the non-root harness: all interpolated values are quoted,
    // including the path and requirement. No executable comes from the source
    // bundle until the root-owned snapshot passes strict deep verification.
    static func bootstrap(bundle: String, requirement: String, resource: String,
                          arguments: [String], helper: Bool) -> String {
        let args = arguments.map(shellQuoted).joined(separator: " ")
        return """
        set -euo pipefail
        export PATH=/usr/bin:/bin:/usr/sbin:/sbin
        umask 077
        stage=$(/usr/bin/mktemp -d /private/tmp/alwaysconnect-root.XXXXXXXX)
        trap '/bin/rm -rf "$stage"' EXIT
        /bin/chmod 700 "$stage"
        app="$stage/AlwaysConnect.app"
        /usr/bin/ditto \(shellQuoted(bundle)) "$app"
        # Refuse links escaping the snapshot, including mutable external scripts.
        while IFS= read -r -d '' link; do
            target=$(/usr/bin/readlink "$link")
            case "$target" in
                /*|..|../*|*/../*|*/..) echo 'App 包含不安全的外部链接，已停止' >&2; exit 1 ;;
            esac
        done < <(/usr/bin/find "$app" -type l -print0)
        /usr/sbin/chown -R root:wheel "$app"
        /bin/chmod -R go-w "$app"
        /usr/bin/codesign --verify --strict --deep -R=\(shellQuoted(requirement)) "$app" 2>/dev/null || {
            echo 'App 副本签名校验失败或签名证书不符，已停止。请重新下载可信版本。' >&2
            exit 1
        }
        /bin/bash "$app/Contents/Resources/\(resource)" \(args)\(helper ? " \"$app/Contents/Library/LaunchDaemons/AlwaysConnectHelper\"" : "")
        """
    }

    static func run(resource: String, arguments: [String], helper: Bool = false, prompt: String,
                    completion: @escaping (AdminScript.Result) -> Void) {
        guard let source = source(resource: resource, arguments: arguments, helper: helper, prompt: prompt) else {
            completion(AdminScript.Result(output: "", errorNumber: 1, errorMessage: unsignedMessage))
            return
        }
        AdminScript.run(source, completion: completion)
    }
}
