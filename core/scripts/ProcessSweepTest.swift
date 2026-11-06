import Foundation

// scripts/process-sweep-test.sh: Sources/Shared/ProcessSweep.swift
// against real child processes (DESIGN.md §23.11). One child exits on
// SIGTERM, one ignores it (needs SIGKILL), one has a grandchild.
@main
struct ProcessSweepTest {
    static func spawn(_ script: String) -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = ["-c", script]
        try! p.run()
        return p
    }

    static func main() {
        var failures = 0
        func check(_ ok: Bool, _ what: String) {
            print((ok ? "ok   " : "FAIL ") + what)
            if !ok { failures += 1 }
        }
        let marker = "ac-sweep-marker-\(getpid())"
        let polite = spawn("exec sleep 300 # \(marker)")
        let stubborn = spawn("trap '' TERM; while :; do sleep 0.2; done # \(marker)")
        let parent = spawn("sleep 300 & wait")
        Thread.sleep(forTimeInterval: 0.5)

        let found = ProcessSweep.descendants()
        check(found.contains(polite.processIdentifier), "polite child listed")
        check(found.contains(stubborn.processIdentifier), "stubborn child listed")
        check(found.contains(parent.processIdentifier), "parent child listed")
        let grandchildren = ProcessSweep.children(of: parent.processIdentifier)
        check(grandchildren.count == 1, "grandchild listed (\(grandchildren.count))")
        check(grandchildren.allSatisfy(found.contains), "descendants include grandchild")

        let byMarker = ProcessSweep.pids(commandContaining: marker)
        // `exec sleep` replaced the polite shell, so its command line no
        // longer carries the marker; the stubborn shell's still does.
        check(byMarker == [stubborn.processIdentifier],
              "command-line search finds exactly the marked process (\(byMarker))")

        let start = Date()
        let killed = ProcessSweep.terminateDescendants(grace: 1)
        let took = Date().timeIntervalSince(start)
        check(killed == [stubborn.processIdentifier] || killed.contains(stubborn.processIdentifier),
              "only the stubborn one needed SIGKILL (\(killed))")
        check(!killed.contains(polite.processIdentifier), "polite child went on SIGTERM")
        check(took < 3, "bounded by the grace period (\(String(format: "%.1f", took)) s)")
        Thread.sleep(forTimeInterval: 0.3)
        let left = found.filter(ProcessSweep.isAlive)
        check(left.isEmpty, "nothing left running (\(left))")
        check(ProcessSweep.descendants().isEmpty, "no descendants after the sweep")
        check(ProcessSweep.terminateDescendants(grace: 1).isEmpty, "a second sweep is a no-op")
        exit(failures == 0 ? 0 : 1)
    }
}
