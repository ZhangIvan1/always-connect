// The own connection's self-check rule (DESIGN.md §26.11), compiled with
// Sources/App/ConnectionCheck.swift by scripts/connection-check-test.sh.
import Foundation

@main
struct ConnectionCheckTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        // rounds: (answered, elapsed seconds)
        func run(_ rounds: [(Bool, Double)]) -> [ConnectionVerdict.Outcome] {
            var v = ConnectionVerdict()
            return rounds.map { v.record(answered: $0.0, at: $0.1) }
        }

        let dead = run((1...8).map { (false, Double($0) * 5) })
        check("nothing answers: gives up after 30 s, not before",
              dead.firstIndex(of: .giveUp) == 5 && !dead.prefix(5).contains(.giveUp))

        // Today's second run (§26.9): answers for ~25 s, then a stall.
        let stall = run([(true, 5), (true, 10), (true, 20), (false, 25), (false, 30), (false, 40),
                         (false, 50)])
        check("answers, then 30 s of silence: gives up", stall.last == .giveUp
              && !stall.dropLast().contains(.giveUp))

        let flaky = run([(false, 5), (false, 10), (true, 15), (false, 20), (false, 25), (true, 30),
                         (false, 40), (false, 50), (true, 60)])
        check("intermittent answers never give up", !flaky.contains(.giveUp))

        let slow = run([(false, 35)])
        check("one slow failed round alone does not give up", slow == [.keepChecking])

        let healthy = run([(true, 5), (true, 60), (true, 121)])
        check("a working session is trusted after two minutes", healthy.last == .healthy)

        let late = run([(true, 100), (false, 125)])
        check("the window ends the check even on a failed round", late.last == .healthy)

        print("connection-check FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
