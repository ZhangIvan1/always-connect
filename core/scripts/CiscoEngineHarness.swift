import AppKit
import Foundation

// Harness for Sources/App/CiscoEngine.swift against core/scripts/
// fake-cisco-vpn.sh (DESIGN.md §21.4). Compiled with the engine by
// scripts/cisco-engine-test.sh; prints one EVENT line per callback.

final class HelperClient {
    enum State: Int {
        case disconnected = 0, connecting, authenticating, awaitingApproval, connected, reconnecting
    }
}

enum CiscoProfiles {
    // No real lookup in the harness: the entry name stays unresolved.
    static func resolve(_ server: String) -> String { "" }
    static func hostEntries() -> [String: String] { [:] }
}

@main
struct Harness {
    static func main() {
        let dir = ProcessInfo.processInfo.environment["FAKE_CISCO_DIR"]!
        var available = true
        CiscoEngine.physicalAvailability = { available }
        CiscoEngine.cliPath = CommandLine.arguments[1]
        CiscoEngine.approvalTimeoutMinimum = 0.5
        // The fake CLI changes no routes: the fallback check finds drops.
        CiscoEngine.monitorInterval = 4
        var password = "good"
        let engine = CiscoEngine()
        let start = Date()
        func log(_ s: String) {
            print(String(format: "%5.1f ", Date().timeIntervalSince(start)) + s)
            fflush(stdout)
        }
        engine.credentialsProvider = { .init(entry: "VPN-A", username: "u", password: password) }
        engine.onState = { state, detail in log("EVENT state=\(state) \(detail)") }
        engine.onTerminal = { log("EVENT terminal=\($0)") }
        engine.onKillSwitch = { mode, _, gws in log("EVENT killswitch=\(mode) gw=\(gws.joined(separator: ","))") }
        func setState(_ s: String) {
            try? s.write(toFile: dir + "/state", atomically: true, encoding: .utf8)
        }
        func wait(_ seconds: Double) {
            RunLoop.main.run(until: Date().addingTimeInterval(seconds))
        }
        log("STEP connect")
        engine.connect(); wait(4)
        log("STEP drop")
        setState("Disconnected"); wait(9)
        log("STEP manual-disconnect")
        let done = DispatchSemaphore(value: 0)
        engine.disconnect { done.signal() }; wait(2)
        log("STEP rejected")
        password = "bad"
        engine.connect(); wait(5)
        log("STEP transient-then-good")
        password = "flaky"
        engine.connect(); wait(2)
        password = "good"; wait(5)
        engine.disconnect {}; wait(1)
        log("STEP approval-expired")
        password = "noapprove"
        engine.connect(); wait(3)
        engine.disconnect {}; wait(1)
        log("STEP quick-login-failed")
        password = "quickfail"
        engine.connect(); wait(2)
        log("STEP pushed-failure")
        engine.disconnect {}; wait(1)
        password = "pushfail"
        engine.connect(); wait(3)
        engine.disconnect {}; wait(1)
        password = "good"
        log("STEP adopt-on-refresh")
        setState("Disconnected")
        engine.connect(); wait(3)
        let second = CiscoEngine()
        second.credentialsProvider = engine.credentialsProvider
        second.onState = { state, detail in log("EVENT2 state=\(state) \(detail)") }
        second.onKillSwitch = { mode, _, _ in log("EVENT2 killswitch=\(mode)") }
        second.refresh(); wait(3)
        log("STEP no-adopt-foreign")
        // A Cisco session the user started in Cisco's own window
        // (DESIGN.md §25.4): never adopted, never armed.
        UserDefaults.standard.set(false, forKey: CiscoEngine.ownedKey)
        let third = CiscoEngine()
        third.credentialsProvider = engine.credentialsProvider
        third.onState = { state, detail in log("EVENT3 state=\(state) \(detail)") }
        third.onKillSwitch = { mode, _, _ in log("EVENT3 killswitch=\(mode)") }
        third.refresh(); wait(3)
        log("EVENT3 managing=\(third.isManaging)")
        engine.disconnect {}; second.disconnect {}; wait(2)
        func cancellationCount() -> Int {
            (try? String(contentsOfFile: dir + "/cancellations", encoding: .utf8))?.split(separator: "\n").count ?? 0
        }
        log("STEP offline-cancel")
        let beforeCancel = cancellationCount()
        password = "slow"
        engine.connect(); wait(1)
        available = false
        engine.networkChanged(); wait(3)
        log("offline owned=\(engine.isManaging)")
        log("offline cancel-issued=\(cancellationCount() > beforeCancel)")
        let stoppedState = (try? String(contentsOfFile: dir + "/state", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "unknown"
        log("offline daemon-state=\(stoppedState)")
        log("STEP offline-resume")
        password = "good"
        available = true
        engine.networkChanged(); wait(3)
        engine.disconnect {}; wait(1)
        log("STEP offline-manual-stop")
        password = "slow"
        engine.connect(); wait(1)
        available = false
        engine.networkChanged(); wait(3)
        engine.disconnect {}; wait(1)
        log("STEP restored-after-manual")
        available = true
        engine.networkChanged(); wait(2)
        log("STEP stop-active-login")
        let beforeActiveStop = cancellationCount()
        password = "slow"
        engine.connect(); wait(1)
        engine.disconnect {}; wait(3)
        log("cancelled owned=\(engine.isManaging)")
        log("active cancel-issued=\(cancellationCount() > beforeActiveStop)")
        log("DONE")
    }
}

// Declared by CertificateRelay.swift in the App; the harness links only
// the engine's shell.
@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)
