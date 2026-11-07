import Foundation

/// The panel's "恢复网络" (DESIGN.md §24.6): the bundled
/// reset-network.sh, run as root behind the standard macOS administrator
/// password dialog, after the App has ended its own VPN session. It works
/// offline and does not need the background service to answer: it is the
/// way back when something we changed has left the Mac without network.
enum NetworkReset {
    enum Outcome {
        case restored(String)
        case failed(String)
        case cancelled
    }

    static func run(completion: @escaping (Outcome) -> Void) {
        PrivilegedBundle.run(resource: "reset-network.sh", arguments: ["--from-app"],
                             prompt: "AlwaysConnect 要把网络恢复到直连：断开 VPN，清除它改过的路由、DNS 和防火墙设置。") { result in
            if let code = result.errorNumber {
                if code == -128 {
                    completion(.cancelled)
                } else {
                    completion(.failed(lastLine(result.errorMessage ?? "") ?? "恢复没有完成"))
                }
            } else {
                completion(.restored(lastLine(result.output) ?? "网络已恢复"))
            }
        }
    }

    /// The script's verdict is its last "== ..." line.
    private static func lastLine(_ text: String) -> String? {
        text.split(whereSeparator: \.isNewline)
            .last { $0.hasPrefix("== ") }
            .map { String($0.dropFirst(3)) }
    }
}
