import Foundation

// Harness for the one-click update (DESIGN.md §35.4): the App's
// UpdateChecker finds a release on a local server and runs install.sh
// against a scratch App, never /Applications. Run by
// scripts/install-test.sh with: <base-url> <install.sh> <target .app>
// <update.log> ok|fail.

@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)

@main
struct UpdateInstallTest {
    static func spin(until done: () -> Bool, seconds: TimeInterval) {
        let deadline = Date().addingTimeInterval(seconds)
        while !done() && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
    }

    static func main() {
        let args = CommandLine.arguments
        let (base, script, target, log, mode) = (args[1], args[2], args[3], args[4], args[5])
        let suite = "com.alwaysconnect.update-install-test"
        UserDefaults().removePersistentDomain(forName: suite)
        UpdateChecker.store = UserDefaults(suiteName: suite)!
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        UpdateChecker.currentVersion = "0.1.0"
        UpdateChecker.installScript = script
        UpdateChecker.installTarget = target
        UpdateChecker.updateLog = URL(fileURLWithPath: log)
        var quit = false
        UpdateChecker.quitApp = { quit = true }

        setenv("ALWAYSCONNECT_UPDATE_URL", base + (mode == "ok" ? "app-ok.json" : "app-bad.json"), 1)
        var outcome: UpdateChecker.Outcome?
        UpdateChecker.shared.check { outcome = $0 }
        spin(until: { outcome != nil }, seconds: 20)
        guard case .newer(let update) = outcome else {
            print("FAIL app-found-update \(String(describing: outcome))")
            exit(1)
        }
        UpdateChecker.shared.install(update)
        print(UpdateChecker.shared.installing ? "PASS app-installing-shown" : "FAIL app-installing-shown")
        spin(until: { quit || !UpdateChecker.shared.installing }, seconds: 60)
        if mode == "ok" {
            // Downloaded and checked; the detached half waits for this
            // process to end before it swaps the App.
            print(quit ? "PASS app-quits-after-staging" : "FAIL app-quits-after-staging \(UpdateChecker.shared.installError ?? "")")
            exit(quit ? 0 : 1)
        }
        let error = UpdateChecker.shared.installError ?? ""
        let ok = !quit && !UpdateChecker.shared.installing && error.contains("校验不一致")
        print(ok ? "PASS app-failure-shown" : "FAIL app-failure-shown quit=\(quit) error=\(error)")
        exit(ok ? 0 : 1)
    }
}
