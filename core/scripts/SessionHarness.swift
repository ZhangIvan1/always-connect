import Foundation

// scripts/session-test.sh: drives the background service's session
// object (HelperSession, KillSwitch, the openconnect engine) directly,
// with a logging pfctl stand-in and fake-openconnect under
// ALWAYSCONNECT_TEST_ROOT (Sources/Helper/TestSeam.swift). No real pf,
// routes or VPN are touched. One scenario per process.
@main
struct SessionHarness {
    static let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ALWAYSCONNECT_TEST_ROOT"]!)
    static var failures = 0

    static func check(_ ok: Bool, _ what: String) {
        print((ok ? "ok   " : "FAIL ") + what)
        if !ok { failures += 1 }
    }

    static func pfLog() -> [String] {
        let text = (try? String(contentsOf: root.appendingPathComponent("pfctl.log"), encoding: .utf8)) ?? ""
        return text.split(separator: "\n").map(String.init)
    }

    static func waitFor(_ seconds: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            usleep(100_000)
        }
        return condition()
    }

    static func sync<T>(_ body: (@escaping (T) -> Void) -> Void) -> T? {
        let done = DispatchSemaphore(value: 0)
        var value: T?
        body { value = $0; done.signal() }
        return done.wait(timeout: .now() + 10) == .timedOut ? nil : value
    }

    static func connect(_ s: HelperSession) -> Bool? {
        sync { reply in s.connect(server: "vpn.example.test", group: "", username: "u", password: "p", withReply: reply) }
    }

    static func disconnect(_ s: HelperSession) -> Bool {
        sync { (reply: @escaping (Bool) -> Void) in s.disconnect { reply(true) } } ?? false
    }

    static func arm(_ s: HelperSession, _ mode: Int) -> Bool {
        let r: (Bool, String)? = sync { reply in
            s.setKillSwitch(mode, tunnelIf: "utun99", gatewayIps: ["198.51.100.7"]) { reply(($0, $1)) }
        }
        return r?.0 ?? false
    }

    static func status(_ s: HelperSession) -> Int {
        sync { reply in s.getStatus { state, _ in reply(state) } } ?? -1
    }

    static func loads() -> Int { pfLog().filter { $0.contains(" -f ") }.count }

    /// The released end state: our anchor flushed after its last load,
    /// every pf enable reference given back, nothing left on disk that
    /// says "held", the Cisco kill switch off, and it stays that way.
    static func assertReleased(_ label: String, adoptedReferences: Int = 0) {
        usleep(300_000)
        let log = pfLog()
        let lastLoad = log.lastIndex { $0.contains(" -f ") } ?? -1
        let lastFlush = log.lastIndex { $0.contains("-F rules") } ?? -1
        check(lastFlush > lastLoad, "\(label): anchor flushed after its last load")
        let enables = log.filter { $0 == "-E" }.count
        let releases = log.filter { $0.hasPrefix("-X ") }.count
        check(enables + adoptedReferences == releases,
              "\(label): pf enable references given back (\(enables) -E + \(adoptedReferences) adopted, \(releases) -X)")
        check(KillSwitch.shared.isOff, "\(label): Cisco kill switch off")
        check(!CLIOrchestrator.localNetworkHeld(), "\(label): no held state on disk")
        let count = loads()
        sleep(3) // past the kill switch watchdog's 2 s tick
        check(loads() == count, "\(label): nothing loads pf again afterwards")
    }

    static var guardFile: URL { root.appendingPathComponent("support/guard.json") }

    static func lastRelease() -> String { NetworkGuard.shared.lastRelease?.reason ?? "" }

    static func relaunches() -> Int {
        let text = (try? String(contentsOf: root.appendingPathComponent("relaunch.log"), encoding: .utf8)) ?? ""
        return text.split(separator: "\n").count
    }

    static func writeGuard(boot: String, token: String, connected: Bool) {
        let record = NetworkGuard.Record(
            bootSession: boot, token: token, holder: NetworkGuard.ciscoHolder, connected: connected,
            inputs: .init(tunnelIf: "utun99", gatewayIps: ["198.51.100.7"], physicalIf: "en0",
                          allowNetworks: ["192.168.0.0/16"], allowDNS: true))
        try? FileManager.default.createDirectory(at: guardFile.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try! JSONEncoder().encode(record).write(to: guardFile)
    }

    static func lastRules() -> String {
        let text = (try? String(contentsOf: root.appendingPathComponent("pf-rules.log"), encoding: .utf8)) ?? ""
        return text.components(separatedBy: "=== load").last ?? ""
    }

    static func prepareRelay(_ s: HelperSession, gateway: String) -> Bool {
        let pin = "pin-sha256:" + Data(repeating: 7, count: 32).base64EncodedString()
        let pem: String? = sync { reply in s.prepareRelay(gatewayIp: gateway, serverPin: pin, withReply: reply) }
        return !(pem ?? "").isEmpty
    }

    /// A record as a session of an earlier service run left it: an own
    /// engine's split set, holding gateway .7.
    static func writeOwnRecord(connected: Bool) {
        let record = NetworkGuard.Record(
            bootSession: BootSession.id ?? "", token: "10055", holder: "own:9", connected: connected,
            inputs: .init(tunnelIf: "utun99", gatewayIps: ["198.51.100.7"], physicalIf: "en0",
                          allowNetworks: ["192.168.1.0/24"], allowDNS: false,
                          localDNSServers: ["192.168.1.1"], directTable: true))
        try? FileManager.default.createDirectory(at: guardFile.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try! JSONEncoder().encode(record).write(to: guardFile)
    }

    static func main() {
        let scenario = CommandLine.arguments.dropFirst().first ?? ""
        let session = HelperSession()
        NetworkGuard.shared.onGraceExpired = {
            session.releaseEverything(reason: NetworkGuard.Reason.appGone)
        }
        let app = "/Applications/AlwaysConnect-test.app"
        if !["restart-same-boot", "restart-other-boot", "legacy-pf-state", "direct-adopt", "old-record"]
            .contains(scenario) {
            session.harnessOwner(attached: true, appPath: app)
        }
        switch scenario {
        case "cisco-disconnect":
            check(arm(session, 1), "kill switch armed (connected)")
            check(loads() == 1, "connected set loaded")
            check(disconnect(session), "disconnect replied")
            assertReleased("cisco-disconnect")
        case "protection-off":
            check(arm(session, 1), "kill switch armed (connected)")
            check(arm(session, 0), "kill switch set off")
            assertReleased("protection-off")
        case "own-then-cisco":
            // F1: one service lifetime, own connection first, then Cisco.
            check(connect(session) == true, "own connection accepted")
            check(waitFor(10) { loads() >= 1 }, "own tunnel up, pf loaded")
            check(disconnect(session), "own disconnect replied")
            let stopped = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            check(stopped, "own engine stopped")
            assertReleased("own disconnect")
            check(arm(session, 1), "Cisco kill switch armed (connected)")
            check(disconnect(session), "Cisco disconnect replied")
            assertReleased("own-then-cisco")
        case "own-disconnect":
            check(connect(session) == true, "own connection accepted")
            check(waitFor(10) { loads() >= 1 }, "own tunnel up, pf loaded")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            assertReleased("own-disconnect")
        case "own-protection-off":
            // 断线保护关 (DESIGN.md §26.19): the own connection loads no pf
            // set, and a drop (the stand-in exits after 2 s up) leaves
            // nothing held while the engine reconnects.
            setenv("FAKE_UP_SECONDS", "2", 1)
            check(sync { reply in session.setDropProtection(false, withReply: reply) } == true,
                  "drop protection set off")
            check(connect(session) == true, "own connection accepted")
            check(waitFor(10) { status(session) == 4 }, "own tunnel up")
            var sawDrop = false
            check(waitFor(20) {
                let state = status(session)
                if state == 5 { sawDrop = true }
                return sawDrop && state == 4
            }, "dropped and reconnected")
            check(loads() == 0, "no pf set loaded, connected or dropped (\(loads()) loads)")
            check(!NetworkGuard.shared.isHolding, "nothing held")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            check(!CLIOrchestrator.localNetworkHeld(), "own-protection-off: no held state on disk")
            check(KillSwitch.shared.isOff, "own-protection-off: Cisco kill switch off")
        case "own-protection-toggle":
            // The switch flipped in a running own connection: off lets go
            // of the set at once, on loads it again (§26.19).
            check(connect(session) == true, "own connection accepted")
            check(waitFor(10) { loads() >= 1 && NetworkGuard.shared.isHolding }, "own tunnel up, pf loaded")
            check(sync { reply in session.setDropProtection(false, withReply: reply) } == true,
                  "drop protection set off")
            check(waitFor(5) { !NetworkGuard.shared.isHolding }, "set released when switched off")
            let before = loads()
            check(sync { reply in session.setDropProtection(true, withReply: reply) } == true,
                  "drop protection set on")
            check(waitFor(5) { loads() > before && NetworkGuard.shared.isHolding }, "set loaded again when switched on")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            assertReleased("own-protection-toggle")
        case "grace-expiry":
            // App crashed while holding: relaunch tried, hold ends after
            // the grace period, reason kept for the App.
            check(arm(session, 1), "kill switch armed (connected)")
            session.harnessOwner(attached: false)
            check(relaunches() == 1, "App relaunch attempted once")
            check(NetworkGuard.shared.isHolding, "still holding within the grace period")
            check(waitFor(5) { !NetworkGuard.shared.isHolding }, "released after the grace period")
            check(lastRelease() == NetworkGuard.Reason.appGone, "release reason recorded: app-gone (\(lastRelease()))")
            assertReleased("grace-expiry")
        case "grace-cancelled":
            check(arm(session, 1), "kill switch armed (connected)")
            session.harnessOwner(attached: false)
            usleep(500_000)
            session.harnessOwner(attached: true, appPath: app)
            sleep(3)
            check(NetworkGuard.shared.isHolding, "App back within the grace period: still holding")
            check(lastRelease().isEmpty, "no release recorded")
            check(disconnect(session), "disconnect replied")
            assertReleased("grace-cancelled")
        case "quit-no-relaunch":
            // A quit releases first: the App leaving is not a crash.
            check(arm(session, 1), "kill switch armed (connected)")
            check(disconnect(session), "quit's disconnect replied")
            session.harnessOwner(attached: false)
            check(relaunches() == 0, "no relaunch after a quit")
            assertReleased("quit-no-relaunch")
        case "restart-same-boot":
            // A service restart in this boot: adopt, block, give back the
            // adopted pf reference when the grace period ends.
            writeGuard(boot: BootSession.id ?? "", token: "10042", connected: true)
            NetworkGuard.shared.adoptAtStart()
            check(NetworkGuard.shared.isHolding, "adopted the hold")
            check(loads() == 1, "blocking set loaded in place of the connected set")
            check(waitFor(5) { !NetworkGuard.shared.isHolding }, "released after the grace period with no App")
            check(pfLog().contains("-X 10042"), "adopted pf reference given back")
            check(lastRelease() == NetworkGuard.Reason.appGone, "release reason: app-gone")
            assertReleased("restart-same-boot", adoptedReferences: 1)
        case "restart-other-boot":
            writeGuard(boot: "00000000-0000-0000-0000-000000000000", token: "10042", connected: false)
            NetworkGuard.shared.adoptAtStart()
            check(!NetworkGuard.shared.isHolding, "record from another boot not adopted")
            check(loads() == 0, "nothing loaded at boot")
            check(!FileManager.default.fileExists(atPath: guardFile.path), "record removed")
            check(lastRelease() == NetworkGuard.Reason.reboot, "release reason: reboot")
        case "legacy-pf-state":
            let legacy = root.appendingPathComponent("support/pf-state.json")
            try? FileManager.default.createDirectory(at: legacy.deletingLastPathComponent(),
                                                     withIntermediateDirectories: true)
            try! Data("{}".utf8).write(to: legacy)
            NetworkGuard.shared.adoptAtStart()
            check(!FileManager.default.fileExists(atPath: legacy.path), "older build's pf-state removed")
            check(!NetworkGuard.shared.isHolding && loads() == 0, "nothing held or loaded")
        case "own-replace":
            // F4: a replaced engine must not release its successor's set.
            check(connect(session) == true, "first own connection accepted")
            check(waitFor(10) { loads() >= 1 }, "first tunnel up")
            let r: Bool? = sync { reply in
                session.connect(server: "vpn2.example.test", group: "", username: "u", password: "p",
                                withReply: reply)
            }
            check(r == true, "second connection replaces the first")
            check(waitFor(10) { loads() >= 2 }, "second tunnel up")
            sleep(3)
            check(NetworkGuard.shared.isHolding, "still holding after the old engine wound down")
            // The handover makes the first engine stale before the second
            // exists (§30.1), so the newest holder is own:3, not own:2.
            check(NetworkGuard.shared.holder == "own:3", "the new engine holds (\(NetworkGuard.shared.holder ?? "-"))")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            assertReleased("own-replace")
        case "orphan-sweep":
            // F6: a crashed run's openconnect / routing core is ended at start.
            // One process each (no child that could outlive it and hold
            // the output pipe): perl scripts named like the real tools,
            // carrying the real arguments.
            func standIn(_ name: String, _ args: [String]) -> Process {
                let path = root.appendingPathComponent(name).path
                try? "#!/usr/bin/perl\nsleep 600;\n".write(toFile: path, atomically: true, encoding: .utf8)
                chmod(path, 0o755)
                let p = Process()
                p.executableURL = URL(fileURLWithPath: path)
                p.arguments = args
                p.standardOutput = FileHandle.nullDevice
                p.standardError = FileHandle.nullDevice
                try! p.run()
                return p
            }
            let markers = HelperDaemon.leftoverMarkers
            let oc = standIn("openconnect", ["--server=x", markers[0].1])
            let tail = standIn("tail", ["-f", markers[0].1])
            usleep(300_000)
            check(ProcessSweep.isAlive(oc.processIdentifier), "stand-in leftover running")
            HelperDaemon.endOwnProcesses(includeChildren: false)
            usleep(300_000)
            check(!ProcessSweep.isAlive(oc.processIdentifier), "leftover openconnect ended by the start sweep")
            check(ProcessSweep.isAlive(tail.processIdentifier), "an unrelated process with the path is left alone")
            tail.terminate()
        case "journal-at-start":
            // §26.3: a dead session's route journal is undone at daemon
            // start when it is from this boot, dropped when it is not.
            let support = TestSeam.supportDir!
            try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            let journal = CLIOrchestrator.routeStateURL(support)
            let stub = root.appendingPathComponent("restore-stub.sh")
            try! "#!/bin/sh\necho \"$1\" >> \"$(dirname \"$0\")/restore.log\"\nrm -f \"$ALWAYSCONNECT_ROUTE_STATE_PATH\"\n"
                .write(to: stub, atomically: true, encoding: .utf8)
            chmod(stub.path, 0o755)
            check(CLIOrchestrator.undoJournalAtStart(scriptPath: stub.path, supportDir: support) == "none",
                  "nothing to do without a journal")
            try! "AC_BOOT=\(BootSession.id ?? "")\nAC_TUN=utun7\nAC_TUNS=\"utun7\"\n"
                .write(to: journal, atomically: true, encoding: .utf8)
            check(CLIOrchestrator.undoJournalAtStart(scriptPath: stub.path, supportDir: support) == "restored",
                  "journal from this boot undone")
            let log = (try? String(contentsOf: root.appendingPathComponent("restore.log"), encoding: .utf8)) ?? ""
            check(log.contains("restore"), "the script's restore ran")
            check(!FileManager.default.fileExists(atPath: journal.path), "journal gone after the restore")
            try! "AC_BOOT=00000000-0000-0000-0000-000000000000\nAC_TUN=utun7\n"
                .write(to: journal, atomically: true, encoding: .utf8)
            check(CLIOrchestrator.undoJournalAtStart(scriptPath: stub.path, supportDir: support) == "dropped",
                  "journal from another boot dropped, not replayed")
            check(!FileManager.default.fileExists(atPath: journal.path), "stale journal removed")
            let runs = ((try? String(contentsOf: root.appendingPathComponent("restore.log"), encoding: .utf8)) ?? "")
                .split(separator: "\n").count
            check(runs == 1, "restore ran only for this boot's journal")
        case "direct-routes-journal":
            // §26.5: every direct host route is journalled before it is
            // added and taken out on stop, at start or by the reset.
            let support = TestSeam.supportDir!
            try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            let journal = support.appendingPathComponent("direct-routes")
            let routes = DirectRoutes(supportDir: support, noRoutes: true)
            routes.add(["203.0.113.5", "203.0.113.6", "not-an-ip"], via: "192.168.1.1")
            routes.add(["203.0.113.5"], via: "192.168.1.1")
            let text = (try? String(contentsOf: journal, encoding: .utf8)) ?? ""
            let lines = text.split(separator: "\n")
            check(lines.first == Substring("boot " + (BootSession.id ?? "")), "journal records the boot")
            check(lines.count == 3, "two routes journalled once each, junk ignored")
            routes.removeAll()
            check(!FileManager.default.fileExists(atPath: journal.path), "journal gone after stop")
            routes.add(["203.0.113.7"], via: "192.168.1.1")
            check(DirectRoutes.undoAtStart(supportDir: support, noRoutes: true) == "removed 1",
                  "a dead session's routes from this boot are undone at start")
            try! "boot 00000000-0000-0000-0000-000000000000\n203.0.113.8 192.168.1.1\n"
                .write(to: journal, atomically: true, encoding: .utf8)
            check(DirectRoutes.undoAtStart(supportDir: support, noRoutes: true) == "dropped",
                  "another boot's journal is only dropped")
            check(DirectRoutes.undoAtStart(supportDir: support, noRoutes: true) == "none", "then nothing left")
            // §26.13: the list's networks share the journal.
            routes.add(["10.20.0.0/16", "10.20.0.0/40", "203.0.113.9"], via: "192.168.1.1")
            let mixed = ((try? String(contentsOf: journal, encoding: .utf8)) ?? "").split(separator: "\n")
            check(mixed.contains("10.20.0.0/16 192.168.1.1") && mixed.count == 3,
                  "a network journalled like an address, a bad prefix ignored")
            routes.remove(["10.20.0.0/16"])
            check(!routes.addresses.contains("10.20.0.0/16") && routes.addresses.contains("203.0.113.9"),
                  "a removed network is no longer routed")
            check(DirectRoutes.undoAtStart(supportDir: support, noRoutes: true) == "removed 2",
                  "networks and addresses are both undone")
            // §28.5: a wider network around the LAN is routed, the LAN itself and its parts are not.
            let lan = IPv4.range("192.168.50.0/24")
            check(DirectRoutes.networksToRoute(["192.168.0.0/16", "192.168.50.0/24", "192.168.50.128/25", "10.9.0.0/16"],
                                               attached: [lan!]) == ["192.168.0.0/16", "10.9.0.0/16"],
                  "the LAN's supernet is routed, the LAN and its subnets are not")
            // §30.2: every attached network counts (Wi-Fi beside Ethernet).
            check(DirectRoutes.networksToRoute(["192.168.20.0/22", "192.168.30.0/23", "172.16.0.0/12"],
                                               attached: [IPv4.range("192.168.20.0/22")!,
                                                          IPv4.range("192.168.30.0/23")!]) == ["172.16.0.0/12"],
                  "no attached network is routed via another interface's router")
        case "direct-table":
            // Plan v2 (§25.8): local DNS servers and the direct table.
            let holder = NetworkGuard.shared.newOwnHolder()
            let inputs = NetworkGuard.Inputs(
                tunnelIf: "utun99", gatewayIps: ["198.51.100.7"], physicalIf: "en0",
                allowNetworks: ["192.168.0.0/16"], allowDNS: false,
                localDNSServers: ["192.168.1.1"], directTable: true)
            check(NetworkGuard.shared.apply(holder: holder, connected: false, inputs: inputs) == nil,
                  "split set loaded")
            let tableOps = { pfLog().filter { $0.contains("-t ac_direct -T") } }
            check(NetworkGuard.shared.addDirect(["203.0.113.20", "2001:db8::5"]), "addresses added")
            check(tableOps().last == "-a com.apple/300.AlwaysConnect -t ac_direct -T add 203.0.113.20 2001:db8::5",
                  "pf table add issued (\(tableOps().last ?? "-"))")
            let before = tableOps().count
            check(NetworkGuard.shared.addDirect(["203.0.113.20"]), "re-adding a known address succeeds")
            check(tableOps().count == before, "...without another pfctl call")
            check(!NetworkGuard.shared.addDirect(["203.0.113.21", "not-an-ip"]), "an invalid entry fails the call")
            check(!NetworkGuard.shared.directAddresses.contains("203.0.113.21"), "...and adds nothing")
            NetworkGuard.shared.removeDirect(["203.0.113.20"])
            check(tableOps().last == "-a com.apple/300.AlwaysConnect -t ac_direct -T delete 203.0.113.20",
                  "pf table delete issued")
            check(NetworkGuard.shared.directAddresses == ["2001:db8::5"], "table contents tracked")
            // A rules reload (new DNS servers) empties the table in pf: re-added.
            var moved = inputs
            moved.localDNSServers = ["10.0.0.1"]
            check(NetworkGuard.shared.apply(holder: holder, connected: false, inputs: moved) == nil, "reloaded")
            let log = pfLog()
            let lastLoad = log.lastIndex { $0.contains(" -f ") } ?? -1
            let readd = log.lastIndex { $0 == "-a com.apple/300.AlwaysConnect -t ac_direct -T add 2001:db8::5" } ?? -1
            check(readd > lastLoad, "table re-added after the reload")
            let saved = (try? String(contentsOf: guardFile, encoding: .utf8)) ?? ""
            check(saved.contains("2001:db8::5") && saved.contains("10.0.0.1"), "table and DNS servers in guard.json")
            NetworkGuard.shared.release(holder: nil, reason: NetworkGuard.Reason.user)
            check(pfLog().contains("-a com.apple/300.AlwaysConnect -F Tables"), "release empties the anchor's tables")
            check(NetworkGuard.shared.directAddresses.isEmpty, "table forgotten on release")
            assertReleased("direct-table")
        case "direct-before-hold":
            // Added while nothing is held: kept, loaded with the next set.
            check(NetworkGuard.shared.addDirect(["203.0.113.40"]), "accepted while not holding")
            check(!pfLog().contains { $0.contains("-T add") }, "no pf call while no table is loaded")
            let holder = NetworkGuard.shared.newOwnHolder()
            var inputs = NetworkGuard.Inputs(
                tunnelIf: "utun99", gatewayIps: ["198.51.100.7"], physicalIf: "en0",
                allowNetworks: [], allowDNS: false)
            inputs.directTable = true
            _ = NetworkGuard.shared.apply(holder: holder, connected: false, inputs: inputs)
            check(pfLog().contains("-a com.apple/300.AlwaysConnect -t ac_direct -T add 203.0.113.40"),
                  "loaded with the first set that declares the table")
            check(disconnect(session), "disconnect replied")
            assertReleased("direct-before-hold")
        case "direct-adopt":
            // A restart in this boot re-adds the table's contents.
            var record = NetworkGuard.Record(
                bootSession: BootSession.id ?? "", token: "10077", holder: "own:9", connected: false,
                inputs: .init(tunnelIf: "utun99", gatewayIps: ["198.51.100.7"], physicalIf: "en0",
                              allowNetworks: [], allowDNS: false, localDNSServers: ["192.168.1.1"],
                              directTable: true))
            record.direct = ["203.0.113.30"]
            try? FileManager.default.createDirectory(at: guardFile.deletingLastPathComponent(),
                                                     withIntermediateDirectories: true)
            try! JSONEncoder().encode(record).write(to: guardFile)
            NetworkGuard.shared.adoptAtStart()
            check(NetworkGuard.shared.isHolding, "adopted")
            check(pfLog().contains("-a com.apple/300.AlwaysConnect -t ac_direct -T add 203.0.113.30"),
                  "direct table re-added after the restart")
            check(NetworkGuard.shared.directAddresses == ["203.0.113.30"], "contents known again")
            check(waitFor(5) { !NetworkGuard.shared.isHolding }, "released after the grace period")
            assertReleased("direct-adopt", adoptedReferences: 1)
        case "old-record":
            // A guard.json from before plan v2 (no localDNSServers,
            // directTable, direct) still decodes and is adopted.
            let old = """
            {"bootSession":"\(BootSession.id ?? "")","token":"10088","holder":"cisco","connected":false,
             "inputs":{"tunnelIf":"utun99","gatewayIps":["198.51.100.7"],"physicalIf":"en0",
                       "allowNetworks":[],"allowDNS":true}}
            """
            try? FileManager.default.createDirectory(at: guardFile.deletingLastPathComponent(),
                                                     withIntermediateDirectories: true)
            try! Data(old.utf8).write(to: guardFile)
            NetworkGuard.shared.adoptAtStart()
            check(NetworkGuard.shared.isHolding, "older record adopted")
            check(waitFor(5) { !NetworkGuard.shared.isHolding }, "released after the grace period")
            assertReleased("old-record", adoptedReferences: 1)
        case "takeover-adopted":
            // §30.1, user 2026-11-06: the service restarted under a live
            // session; the App reconnects and its relay resolved the
            // gateway's OTHER address. The new engine takes the adopted
            // set over before its login, letting the new address through.
            writeOwnRecord(connected: true)
            NetworkGuard.shared.adoptAtStart()
            check(NetworkGuard.shared.holder == "own:9", "adopted the old engine's set")
            check(lastRules().contains("198.51.100.7"), "adopted set passes the old gateway")
            check(prepareRelay(session, gateway: "198.51.100.9"), "relay prepared with another gateway address")
            setenv("FAKE_CONNECT_DELAY", "3", 1)
            check(connect(session) == true, "reconnect accepted")
            check(waitFor(2) { NetworkGuard.shared.holder == "own:1" }, "new engine holds the set before its login")
            let rules = lastRules()
            check(rules.contains("198.51.100.9") && !rules.contains("198.51.100.7"),
                  "the held set now passes the new gateway address only")
            check(rules.contains("192.168.1.0/24"), "the LAN stays allowed")
            check(!pfLog().contains("-a com.apple/300.AlwaysConnect -F rules"), "never released in between")
            check(waitFor(2) { status(session) == SessionDriverClient.State.reconnecting.rawValue },
                  "shown as a drop being recovered, not a fresh login (\(status(session)))")
            check(waitFor(10) { status(session) == SessionDriverClient.State.connected.rawValue }, "tunnel up")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            assertReleased("takeover-adopted", adoptedReferences: 1)
        case "takeover-replace":
            // §30.1: a new relay of the same App (reopened, or another
            // gateway address) replaces the engine without opening the
            // network in between, and without logging the session off.
            let signals = root.appendingPathComponent("signals.log")
            setenv("FAKE_SIGNAL_LOG", signals.path, 1)
            check(prepareRelay(session, gateway: "198.51.100.7"), "first relay")
            check(connect(session) == true, "first connection accepted")
            check(waitFor(10) { status(session) == SessionDriverClient.State.connected.rawValue }, "first tunnel up")
            let flushesBefore = pfLog().filter { $0.contains("-F rules") }.count
            check(prepareRelay(session, gateway: "198.51.100.9"), "second relay, other gateway address")
            setenv("FAKE_CONNECT_DELAY", "3", 1)
            check(connect(session) == true, "replacement accepted")
            check(waitFor(8) { lastRules().contains("198.51.100.9") }, "new engine took the set over")
            check(pfLog().filter { $0.contains("-F rules") }.count == flushesBefore,
                  "the set was never released during the handover")
            check(((try? String(contentsOf: signals, encoding: .utf8)) ?? "").contains("HUP"),
                  "old openconnect left without logging off (SIGHUP)")
            check(waitFor(10) { status(session) == SessionDriverClient.State.connected.rawValue }, "second tunnel up")
            check(disconnect(session), "disconnect replied")
            _ = waitFor(15) {
                (sync { reply in session.getSessionInfo { reason, _ in reply(reason) } } ?? 0) == 1
            }
            assertReleased("takeover-replace")
        case "protection-off-adopted":
            // §30.1: 断线保护 switched off with no engine running lets go
            // of a set the restarted service adopted.
            writeOwnRecord(connected: false)
            NetworkGuard.shared.adoptAtStart()
            check(NetworkGuard.shared.isHolding, "adopted")
            let r: Bool? = sync { reply in session.setDropProtection(false, withReply: reply) }
            check(r == true, "switch-off replied")
            check(!NetworkGuard.shared.isHolding, "the adopted set is gone")
            assertReleased("protection-off-adopted", adoptedReferences: 1)
        case "held-allow-update":
            // §30.1: held with no engine, the App's new LAN gets through.
            writeOwnRecord(connected: false)
            NetworkGuard.shared.adoptAtStart()
            let r: Bool? = sync { reply in session.updateAllowNetworks(["172.31.0.0/16"], withReply: reply) }
            check(r == true, "update accepted with no engine")
            check(lastRules().contains("172.31.0.0/16") && !lastRules().contains("192.168.1.0/24"),
                  "the held set passes the new LAN instead of the old one")
            check(NetworkGuard.shared.isHolding, "still held")
            check(disconnect(session), "disconnect replied")
            assertReleased("held-allow-update", adoptedReferences: 1)
        default:
            print("unknown scenario \(scenario)")
            failures += 1
        }
        ProcessSweep.terminateDescendants(grace: 1)
        exit(failures == 0 ? 0 : 1)
    }
}
