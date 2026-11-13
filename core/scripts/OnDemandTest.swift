import Foundation

// Preserve the original integration scenarios while Rust owns the decisions.
// Their pure event equivalents live in on_demand/runtime.rs.

@main struct OnDemandTest {
    static var count = 0
    static func check(_ condition: @autoclosure () -> Bool, _ label: String) {
        precondition(condition(), "FAIL \(label)"); count += 1; print("PASS \(label)")
    }
    static func main() {
        let c = OnDemandController()
        var facts = OnDemandFacts(network: "wifi", ssid: "Office-WiFi")
        var reads = 0, stops = 0, starts = 0, probes = 0
        var live = true
        var delayed: ((Bool) -> Void)?
        c.active = { live }; c.autoConnect = { false }
        c.collect = { ssid, done in reads += 1; done(facts) }
        c.disconnect = { stops += 1; live = false }
        c.connect = { c.automatic { starts += 1; live = true } }
        c.probe = { _, _, done in probes += 1; delayed = done }
        var r = OnDemandRule(); r.id = "office"; r.name = "Office"; r.ssids = ["Office-WiFi"]
        c.configure(enabled: false, rules: [r])
        c.automatic { starts += 1 }
        check(reads == 0 && probes == 0, "disabled performs no reads or probes")
        c.configure(enabled: true, rules: [r])
        check(c.state.paused && stops == 1, "active session disconnected on matching rule")
        let baseline = starts
        for _ in 0..<5 { c.automatic { starts += 1 } }
        check(starts == baseline, "all automatic entries blocked while paused")
        c.manualConnect(); c.automatic { starts += 1; live = true }
        check(!c.state.paused && starts == baseline + 1, "manual connect overrides pause")
        c.networkChanged()
        check(!c.state.paused, "tunnel-only path event preserves manual override")
        facts.ssid = "Lab"; c.networkChanged()
        facts.ssid = "Office-WiFi"; c.networkChanged()
        check(c.state.paused && stops == 2, "next physical network reevaluates manual override")
        facts.ssid = "Home"; c.networkChanged()
        check(!c.state.paused && starts == baseline + 2, "leaving matched network restores previously active session")
        live = false; facts.ssid = "Office-WiFi"; c.networkChanged()
        facts.ssid = "Home"; c.networkChanged()
        check(starts == baseline + 3, "leaving a policy pause resumes with launch auto-connect off")
        r.probe = OnDemandProbe(kind: "dns", target: "intranet.example.com")
        c.configure(enabled: true, rules: [r])
        check(probes == 0, "unmatched offline condition does not probe")
        facts.ssid = "Office-WiFi"; c.networkChanged()
        check(probes == 1, "matched offline facts request one probe")
        c.manualConnect(); let oldStop = stops; delayed?(true)
        check(stops == oldStop && !c.state.paused, "stale probe cannot undo manual connection")
        facts.ssid = "Home"; c.networkChanged(); facts.ssid = "Office-WiFi"; c.networkChanged()
        delayed?(false)
        check(!c.state.paused, "probe timeout or failure keeps connection")
        c.configure(enabled: true, rules: [r]); delayed?(true)
        check(c.state.paused, "successful probe disconnects")
        var ignore = r; ignore.probe = nil; ignore.action = "ignore"
        c.configure(enabled: true, rules: [ignore])
        check(c.state.paused, "ignore retains prior pause")
        let before = reads
        c.configure(enabled: false, rules: [r]); c.networkChanged()
        check(reads == before && !c.state.paused, "disabling clears pause without collecting facts")

        c.configure(enabled: true, rules: [r])
        let late = delayed
        let stopsBeforeChange = stops
        c.networkWillChange()
        late?(true)
        check(stops == stopsBeforeChange, "network event immediately invalidates old probe before debounce")
        var earlyStarts = 0
        c.automatic { earlyStarts += 1 }
        check(earlyStarts == 0, "automatic entry waits during network debounce")
        facts.ssid = "Home"; c.networkChanged()
        check(!c.state.paused, "new network settles before policy takes effect")

        // Startup automatic entry waits for initial facts; repeated recovery
        // calls coalesce instead of starting several sessions at once.
        let startup = OnDemandController(); var collected: ((OnDemandFacts) -> Void)?
        startup.collect = { _, done in collected = done }
        startup.configure(enabled: true, rules: [r])
        var startupStarts = 0
        startup.automatic { startupStarts += 1 }; startup.automatic { startupStarts += 1 }
        check(startupStarts == 0, "launch waits for initial physical facts")
        collected?(OnDemandFacts(network: "wired"))
        check(startupStarts == 1, "pending automatic connections coalesced")
        print("\(count) on-demand assertions passed")
    }
}
