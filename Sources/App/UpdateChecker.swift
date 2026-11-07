import AppKit
import Foundation

@_silgen_name("ac_update_decide")
func ac_update_decide(_ current: UnsafePointer<CChar>, _ releases: UnsafePointer<CChar>,
                      _ skipped: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

/// Update check (DESIGN.md §三十三, user 2026-11-06: "联动到 github 的
/// release 版本上，如果有新版就提示用户更新，手动即可").
///
/// A thin shell: one GET of the GitHub releases list, handed to the Rust
/// core (`ac_update_decide`) together with this App's version; the core
/// parses, compares and picks. No timer: the App asks `checkIfDue()` 30 s
/// after launch and on every panel open, which sends a request at most
/// once a day (once an hour after a failed one). Nothing is downloaded
/// until the user clicks "更新" (DESIGN.md §35.4): then install.sh, the
/// same script as the one-line install, does the download, the checks
/// and the swap, and this App quits the normal way.
///
/// What it found lives in the App's own preferences, so the settings
/// process (its "检查更新" button runs the same code) and the menu-bar App
/// see the same result; uninstall removes them with the rest (§31).
final class UpdateChecker: ObservableObject {
    static let shared = UpdateChecker()

    struct Available: Equatable {
        var version: String
        var tag: String
        var url: URL
        var prerelease: Bool
    }

    enum Outcome: Equatable {
        case newer(Available)
        case skipped(String)
        case current
        /// The reply was no release list: the repository is private or
        /// gone, GitHub's rate limit, a login page in front of the network.
        case unreadable
        /// No reply at all (offline, drop protection holding the network).
        case failed
    }

    /// The newest release above this App that the user has not skipped.
    @Published private(set) var available: Available?
    @Published private(set) var checking = false
    /// Downloading and checking the new version (before the App quits).
    @Published private(set) var installing = false
    /// Why the last "更新" stopped; nil when it did not fail.
    @Published private(set) var installError: String?

    /// Settable for the harness (scripts/update-check-test.sh) only.
    static var currentVersion: String =
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0"

    /// The releases list. `AlwaysConnectReleasesAPI` in Info.plist, so a
    /// fork points at its own; ALWAYSCONNECT_UPDATE_URL overrides it for
    /// the local harness.
    static var feedURL: URL? {
        if let override = ProcessInfo.processInfo.environment["ALWAYSCONNECT_UPDATE_URL"], !override.isEmpty {
            return URL(string: override)
        }
        return (Bundle.main.object(forInfoDictionaryKey: "AlwaysConnectReleasesAPI") as? String)
            .flatMap(URL.init(string:))
    }

    /// The one-line install, which also updates (README, install.sh).
    static let installCommand =
        "curl -fsSL https://raw.githubusercontent.com/weiazm/always-connect/main/install.sh | bash"

    private enum Key {
        static let lastAttempt = "updateLastAttempt"
        static let lastSuccess = "updateLastSuccess"
        static let lastFailed = "updateLastFailed"
        static let found = "updateFound"          // [tag, url, prerelease] of the last newer one
        static let skipped = "updateSkippedVersion"
    }

    static let dayInterval: TimeInterval = 24 * 3600
    static let retryInterval: TimeInterval = 3600

    /// The App's own preferences; the harness swaps in a scratch suite.
    static var store: UserDefaults = .standard
    private var defaults: UserDefaults { Self.store }

    private init() {
        reload()
    }

    var lastSuccess: Date? {
        let t = defaults.double(forKey: Key.lastSuccess)
        return t > 0 ? Date(timeIntervalSince1970: t) : nil
    }

    /// Checks when the last check is old enough; otherwise only re-reads
    /// what the settings process may have found meanwhile.
    func checkIfDue() {
        reload()
        let now = Date().timeIntervalSince1970
        let attempt = defaults.double(forKey: Key.lastAttempt)
        let wait = defaults.bool(forKey: Key.lastFailed) ? Self.retryInterval : Self.dayInterval
        if now - attempt >= wait { check { _ in } }
    }

    /// One request now (the "检查更新" button, or a due check).
    func check(done: @escaping (Outcome) -> Void) {
        guard !checking else { return }
        guard let url = Self.feedURL else {
            done(.unreadable)
            return
        }
        checking = true
        defaults.set(Date().timeIntervalSince1970, forKey: Key.lastAttempt)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("AlwaysConnect/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")
        // Ephemeral and torn down after the one answer (§32.1): no
        // cache, cookies or connection pool stays behind.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration)
        session.dataTask(with: request) { [weak self] data, response, _ in
            session.finishTasksAndInvalidate()
            let outcome: Outcome
            if let data, response != nil {
                outcome = Self.decide(body: String(decoding: data, as: UTF8.self))
            } else {
                outcome = .failed
            }
            DispatchQueue.main.async {
                self?.finish(outcome)
                done(outcome)
            }
        }.resume()
    }

    /// Dismisses this version; a later one shows again.
    func skip(_ update: Available) {
        defaults.set(update.version, forKey: Key.skipped)
        reload()
    }

    func openReleasePage(_ update: Available) {
        NSWorkspace.shared.open(update.url)
    }

    static func copyInstallCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(installCommand, forType: .string)
    }

    // MARK: - One-click update (DESIGN.md §35.4)

    /// The bundled install.sh; settable for a harness.
    static var installScript: String? = Bundle.main.path(forResource: "install", ofType: "sh")

    /// Where the detached second half writes what it did (overwritten
    /// each time, so it stays small; uninstall removes the folder).
    /// Settable for the harness, as are the two below.
    static var updateLog: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/AlwaysConnect/update.log")
    /// The App to replace; nil = this one.
    static var installTarget: String?
    /// The normal quit (VPN off, network direct, §21.5).
    static var quitApp: () -> Void = { AppQuit.request() }  // never from a main-queue block (§37)

    /// Installs the newer version found: install.sh downloads it into a
    /// scratch directory and checks it while this App keeps running (a
    /// failure leaves everything as it was and shows why); then a copy of
    /// the script, detached so that it is no child of this App (quit ends
    /// every child, §23.11), waits for this process to end, swaps the
    /// bundle and opens the new one, and the App quits the normal way:
    /// VPN off and the network back to direct, never a kill.
    func installAvailable() {
        reload()
        guard let update = available else { return }
        install(update)
    }

    func install(_ update: Available) {
        guard !installing else { return }
        guard let script = Self.installScript else {
            installError = "这份 App 里缺少更新脚本，请打开发布页手动下载"
            return
        }
        installing = true
        installError = nil
        // A quarantined App opened from Downloads runs from a read-only
        // translocated copy: install to "应用程序" then.
        let here = Self.installTarget ?? Bundle.main.bundlePath
        let appPath = here.contains("/AppTranslocation/") ? "/Applications/AlwaysConnect.app" : here
        // In the App's caches folder, which uninstall removes (§31); a
        // finished update removes it itself, a failed one right here.
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let stage = caches.appendingPathComponent("com.alwaysconnect.app/update-\(UUID().uuidString)").path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let (status, output) = Self.run(script, ["--version", update.tag, "--app", appPath, "--stage", stage])
            let lines = output.split(separator: "\n").map(String.init)
            guard status == 0, let staged = lines.last(where: { $0.hasPrefix("STAGED ") })?.dropFirst(7) else {
                try? FileManager.default.removeItem(atPath: stage)
                let reason = lines.last(where: { $0.hasPrefix("错误：") }).map { String($0.dropFirst(3)) }
                DispatchQueue.main.async {
                    self?.installing = false
                    self?.installError = reason ?? "下载或校验没有完成"
                }
                return
            }
            let started = Self.detach(script, ["--from", String(staged), "--app", appPath,
                                               "--wait-pid", String(getpid()), "--yes"])
            DispatchQueue.main.async {
                guard started else {
                    try? FileManager.default.removeItem(atPath: stage)
                    self?.installing = false
                    self?.installError = "无法启动更新"
                    return
                }
                Self.quitApp()
            }
        }
    }

    /// The environment for install.sh: this App's releases list, so a
    /// fork's App updates from the fork.
    private static var scriptEnvironment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        if let feed = feedURL?.absoluteString { env["ALWAYSCONNECT_RELEASES_API"] = feed }
        return env
    }

    /// Runs the script to the end; its output is a few lines.
    private static func run(_ script: String, _ arguments: [String]) -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script] + arguments
        process.environment = scriptEnvironment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        process.standardInput = FileHandle.nullDevice
        do { try process.run() } catch { return (-1, "") }
        try? pipe.fileHandleForWriting.close()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// Starts the script in the background through a shell that exits at
    /// once, so the script is re-parented to launchd and outlives the App.
    private static func detach(_ script: String, _ arguments: [String]) -> Bool {
        let log = updateLog
        try? FileManager.default.createDirectory(at: log.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        var env = scriptEnvironment
        env["AC_UPDATE_LOG"] = log.path
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", "nohup /bin/bash \"$0\" \"$@\" >\"$AC_UPDATE_LOG\" 2>&1 </dev/null &", script] + arguments
        process.environment = env
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    // MARK: - Internals

    private func finish(_ outcome: Outcome) {
        checking = false
        defaults.set(outcome == .failed || outcome == .unreadable, forKey: Key.lastFailed)
        switch outcome {
        case .newer(let update):
            defaults.set(Date().timeIntervalSince1970, forKey: Key.lastSuccess)
            defaults.set([update.tag, update.url.absoluteString, update.prerelease ? "1" : "0"], forKey: Key.found)
        case .skipped, .current:
            defaults.set(Date().timeIntervalSince1970, forKey: Key.lastSuccess)
            defaults.removeObject(forKey: Key.found)
        case .unreadable, .failed:
            break  // keep what an earlier check found; retry in an hour
        }
        reload()
    }

    /// The stored find, run through the core again with this App's
    /// version and the skip: after the user installed it, or skipped it
    /// (in either process), it no longer shows.
    private func reload() {
        var shown: Available?
        if let found = defaults.stringArray(forKey: Key.found), found.count == 3 {
            let release: [String: Any] = ["tag_name": found[0], "html_url": found[1],
                                          "draft": false, "prerelease": found[2] == "1"]
            if let data = try? JSONSerialization.data(withJSONObject: [release]),
               case .newer(let update) = Self.decide(body: String(decoding: data, as: UTF8.self)) {
                shown = update
            }
        }
        if available != shown { available = shown }
    }

    private static func decide(body: String) -> Outcome {
        let skipped = store.string(forKey: Key.skipped)
        let raw: UnsafeMutablePointer<CChar>? = currentVersion.withCString { current in
            body.withCString { releases in
                if let skipped {
                    return skipped.withCString { ac_update_decide(current, releases, $0) }
                }
                return ac_update_decide(current, releases, nil)
            }
        }
        guard let raw else { return .unreadable }
        defer { ac_string_free(raw) }
        guard let object = try? JSONSerialization.jsonObject(with: Data(String(cString: raw).utf8)) as? [String: Any],
              let status = object["status"] as? String else { return .unreadable }
        switch status {
        case "newer":
            guard let version = object["version"] as? String, let tag = object["tag"] as? String,
                  let url = (object["url"] as? String).flatMap(URL.init(string:)) else { return .unreadable }
            return .newer(Available(version: version, tag: tag, url: url,
                                    prerelease: (object["prerelease"] as? Bool) ?? false))
        case "skipped": return .skipped((object["version"] as? String) ?? "")
        case "current": return .current
        default: return .unreadable
        }
    }
}
