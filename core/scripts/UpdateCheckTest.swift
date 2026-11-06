import Foundation

// Harness for the update check (DESIGN.md §三十三): the App's
// UpdateChecker against a local HTTP server standing in for GitHub's
// releases list. Run by scripts/update-check-test.sh.

@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)

@main
struct UpdateCheckTest {
    static var failures = 0

    static func expect(_ ok: Bool, _ name: String) {
        print(ok ? "PASS \(name)" : "FAIL \(name)")
        if !ok { failures += 1 }
    }

    /// One check against `path` on the local server, waited for on the main run loop.
    static func check(_ base: String, _ path: String) -> UpdateChecker.Outcome {
        setenv("ALWAYSCONNECT_UPDATE_URL", base + path, 1)
        var result: UpdateChecker.Outcome?
        UpdateChecker.shared.check { result = $0 }
        let deadline = Date().addingTimeInterval(20)
        while result == nil && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        return result ?? .failed
    }

    static func main() {
        let args = CommandLine.arguments
        let base = args[1]          // http://127.0.0.1:<port>/
        let closed = args[2]        // a URL nothing listens on
        let suite = "com.alwaysconnect.update-check-test"
        UserDefaults().removePersistentDomain(forName: suite)
        UpdateChecker.store = UserDefaults(suiteName: suite)!
        UpdateChecker.currentVersion = "0.1.0"

        // A newer pre-release counts (user, 2026-11-06); a draft does not.
        if case .newer(let u) = check(base, "releases.json") {
            expect(u.version == "0.2.0-beta.1" && u.prerelease
                   && u.url.absoluteString == "https://github.com/o/r/releases/tag/v0.2.0-beta.1", "newer-prerelease")
        } else { expect(false, "newer-prerelease") }
        expect(UpdateChecker.shared.available?.version == "0.2.0-beta.1", "banner-shown")

        // Checked a moment ago: due checks send nothing for a day.
        UpdateChecker.shared.checkIfDue()
        expect(!UpdateChecker.shared.checking, "not-due-within-a-day")

        // The private repository's 404 and a missing server keep the last find.
        expect(check(base, "missing.json") == .unreadable, "not-found-unreadable")
        expect(check(base, "notfound.json") == .unreadable, "error-object-unreadable")
        expect(check(closed, "") == .failed, "offline-failed")
        expect(UpdateChecker.shared.available?.version == "0.2.0-beta.1", "find-kept-after-failures")
        // A failed check retries after an hour, not a day.
        let attempt = UpdateChecker.store.double(forKey: "updateLastAttempt")
        UpdateChecker.store.set(attempt - 3700, forKey: "updateLastAttempt")
        setenv("ALWAYSCONNECT_UPDATE_URL", base + "releases.json", 1)
        UpdateChecker.shared.checkIfDue()
        expect(UpdateChecker.shared.checking, "retry-after-an-hour")
        let deadline = Date().addingTimeInterval(20)
        while UpdateChecker.shared.checking && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }

        // Skipping hides it; the same release stays skipped; a later one shows.
        if let u = UpdateChecker.shared.available { UpdateChecker.shared.skip(u) }
        expect(UpdateChecker.shared.available == nil, "skip-hides")
        expect(check(base, "releases.json") == .skipped("0.2.0-beta.1"), "skipped-stays-hidden")
        if case .newer(let u) = check(base, "later.json") {
            expect(u.version == "0.3.0" && !u.prerelease, "later-release-shows")
        } else { expect(false, "later-release-shows") }

        // Once this version is installed, the stored find no longer shows.
        UpdateChecker.currentVersion = "0.3.0"
        UpdateChecker.shared.checkIfDue()
        expect(UpdateChecker.shared.available == nil, "installed-version-hides")
        expect(check(base, "later.json") == .current, "current")

        UserDefaults().removePersistentDomain(forName: suite)
        print(failures == 0 ? "update-check: all passed" : "update-check: \(failures) failed")
        exit(failures == 0 ? 0 : 1)
    }
}
