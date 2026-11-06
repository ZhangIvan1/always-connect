import Darwin
import Foundation

/// Scratch paths for the session harness (scripts/session-test.sh).
///
/// `ALWAYSCONNECT_TEST_ROOT` replaces the system locations the
/// background service touches — its support directory, pfctl and
/// openconnect — and turns route/DNS changes off. It is honoured only
/// when not running as root, so the installed daemon can never be
/// pointed elsewhere by its environment.
enum TestSeam {
    static let root: URL? = {
        guard getuid() != 0,
              let path = ProcessInfo.processInfo.environment["ALWAYSCONNECT_TEST_ROOT"],
              !path.isEmpty
        else { return nil }
        return URL(fileURLWithPath: path)
    }()

    static var isActive: Bool { root != nil }

    /// <root>/support in place of /Library/Application Support/AlwaysConnect.
    static var supportDir: URL? { root?.appendingPathComponent("support") }

    /// An executable stand-in under the test root (pfctl, openconnect).
    static func tool(_ name: String) -> String? {
        guard let path = root?.appendingPathComponent(name).path,
              FileManager.default.isExecutableFile(atPath: path)
        else { return nil }
        return path
    }
}

/// Timing knobs for the engine harness (scripts/local-checks.sh): read
/// only when not running as root, so the installed daemon's timings can
/// never be changed by its environment.
enum TestKnobs {
    static func value(_ name: String) -> TimeInterval? {
        guard getuid() != 0, let text = ProcessInfo.processInfo.environment[name] else { return nil }
        return TimeInterval(text)
    }
}
