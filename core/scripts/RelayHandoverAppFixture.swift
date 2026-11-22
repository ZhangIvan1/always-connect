// Compiled by relay-handover-test.py with production App handover methods
// inserted below. Only UI/keychain selection, DNS and the XPC transport are
// adapters. HelperSession, Rust, Network.framework and the destination CLI
// are real. TestSeam prevents system route/PF changes.
import Foundation
import Security

enum HelperInstaller { static let installedHelperMatchesBundle = true }
struct FixtureDemand { func permitsConnection() -> Bool { true } }

final class FixtureClient {
    let helper: HelperSession
    let identity: SecIdentity
    let anchor: SecCertificate
    let relayHandover = RelayHandover()
    let onDemand = FixtureDemand()
    var usesCisco = false
    var relay: CertificateRelay?
    var relayGeneration = 0
    var relayConnectionContext: RelayConnectionContext?
    var relayAttempt = 0
    var relayPin: String?
    var relayPhase: String?
    var relayRetryAfter: Date?
    var lastError = ""
    var detail = ""
    var redirects = 0
    var pinnedTargets: [String] = []

    init(helper: HelperSession, identity: SecIdentity, anchor: SecCertificate) {
        self.helper = helper; self.identity = identity; self.anchor = anchor
    }
    func ensureConnection(_ body: (HelperSession) -> Void) { body(helper) }
    func resolveGatewayIPv4(_ host: String, completion: @escaping ([String]?) -> Void) {
        completion(["127.0.0.1"]) // fixed loopback fixture, no system DNS
    }
    func prepareRelay(server: String, preservingHandover: Bool = false,
                      sessionId: String, attempt: Int, resolved: [String]? = nil,
                      completion: @escaping (String?) -> Void) {
        relayGeneration += 1
        let generation = relayGeneration
        guard let address = GatewayAddress(server) else { completion("bad fixture target"); return }
        let next = CertificateRelay(host: address.host, port: address.port, identity: identity,
            upstreamPort: address.host == "localhost" ? 4474 : 4476, anchor: anchor,
            sessionId: sessionId, attempt: attempt)
        DispatchQueue.global().async {
            do {
                let prepared = try next.prepare(resolved: ["127.0.0.1"])
                self.helper.prepareRelay(gatewayIp: prepared.gatewayIp, serverPin: prepared.serverPin) { pem in
                    let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
                    guard let der = Data(base64Encoded: body) else {
                        DispatchQueue.main.async { completion("bad fixture relay certificate") }; return
                    }
                    next.onRedirect = { [weak self] event in
                        DispatchQueue.main.async {
                            guard let self else { return }
                            self.redirects += 1
                            self.handleRelayRedirect(event, source: server, pin: prepared.serverPin, generation: generation)
                        }
                    }
                    next.onFatalIssue = { [weak self] issue in
                        DispatchQueue.main.async {
                            self?.failRelayHandover(session: sessionId, message: issue.message, reason: issue.rawValue)
                        }
                    }
                    next.start(clientCertificate: der) { error in
                        DispatchQueue.main.async {
                            guard generation == self.relayGeneration else { next.stop(); return }
                            guard error == nil else { completion(error!.localizedDescription); return }
                            self.relay = next
                            self.relayPin = prepared.serverPin
                            self.pinnedTargets.append(server)
                            completion(nil)
                        }
                    }
                }
            } catch { DispatchQueue.main.async { completion(error.localizedDescription) } }
        }
    }

    // PRODUCTION_HANDOVER_METHODS
}

@main
enum HandoverAppFixture {
    static func main() {
        guard #available(macOS 15.0, *), let root = TestSeam.root, getuid() != 0 else {
            fputs("FAIL loopback fixture requires non-root macOS 15\n", stderr); exit(1)
        }
        let pki = URL(fileURLWithPath: CommandLine.arguments[1])
        let data = try! Data(contentsOf: pki.appendingPathComponent("company.p12"))
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: "test",
                       kSecImportToMemoryOnly as String: true] as CFDictionary
        guard SecPKCS12Import(data as CFData, options, &items) == errSecSuccess,
              let value = (items as? [[String: Any]])?.first?[kSecImportItemIdentity as String],
              let ca = SecCertificateCreateWithData(nil, try! Data(contentsOf: pki.appendingPathComponent("ca.der")) as CFData)
        else { fputs("FAIL fixture PKI\n", stderr); exit(1) }
        let helper = HelperSession()
        helper.harnessOwner(attached: true, appPath: "/Applications/AlwaysConnect-test.app")
        let record = NetworkGuard.Record(bootSession: BootSession.id ?? "", token: "10055",
            holder: "own:9", connected: false,
            inputs: .init(tunnelIf: "utun99", gatewayIps: ["127.0.0.1"], physicalIf: "en0",
                          allowNetworks: ["192.168.1.0/24"], allowDNS: false,
                          localDNSServers: ["192.168.1.1"], directTable: true))
        let file = root.appendingPathComponent("support/guard.json")
        try! FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! JSONEncoder().encode(record).write(to: file)
        NetworkGuard.shared.adoptAtStart()
        let app = FixtureClient(helper: helper, identity: value as! SecIdentity, anchor: ca)
        let a = "https://localhost:4473/"
        let b = "https://127.0.0.1:4473/"
        let session = UUID().uuidString
        app.prepareRelay(server: a, sessionId: session, attempt: 0) { error in
            guard error == nil, let pin = app.relayPin else { app.lastError = error ?? "no pin"; return }
            let context = RelayConnectionContext(session: session, target: a, pin: pin, allowed: [a, b])
            app.relayConnectionContext = context
            guard app.relayHandover.command(["op": "register", "session": session,
                  "target": a, "pin": pin, "allowed": [a, b]])?.0.ok == true else {
                app.lastError = "fixture App registration failed"; return
            }
            let text = String(data: try! JSONEncoder().encode(context), encoding: .utf8)!
            helper.connectRelayed(server: a, group: "", username: "testuser", password: "testpass", context: text) {
                if !$0 { DispatchQueue.main.async { app.lastError = "fixture initial intent rejected" } }
            }
        }
        var authenticated = false
        let deadline = Date().addingTimeInterval(35)
        while !authenticated && app.lastError.isEmpty && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.03))
            // Cookie capture comes from the production engine's real destination
            // OpenConnect; no fixture fabricates an authenticated result.
            if let raw = try? Data(contentsOf: CookieStore.defaultFileURL),
               let cookie = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] {
                authenticated = cookie["gateway"] as? String == b && cookie["cookie"] as? String == "mockcookie123"
            }
        }
        let pfLog = root.appendingPathComponent("pfctl.log")
        let calls = (try? String(contentsOf: pfLog, encoding: .utf8)) ?? ""
        var failures = 0
        func check(_ ok: Bool, _ label: String) {
            print("\(ok ? "PASS" : "FAIL") \(label)")
            if !ok { failures += 1 }
        }
        check(app.lastError.isEmpty, "production App handover accepted: \(app.lastError)")
        check(authenticated, "destination OpenConnect authenticated through its fresh relay pin")
        check(app.redirects == 1 && app.relayAttempt == 1 && app.pinnedTargets == [a, b],
              "fragmented redirect caused exactly one same-port target replacement")
        check(NetworkGuard.shared.isHolding && !calls.split(separator: "\n").contains { $0.hasPrefix("-X ") },
              "protected handover did not release the adopted firewall reference")
        check(helper.harnessEngineHolder() == NetworkGuard.shared.holder,
              "current destination engine owns retained protection")
        var stopped = false
        helper.disconnect { DispatchQueue.main.async { stopped = true } }
        let stopDeadline = Date().addingTimeInterval(12)
        while !stopped && Date() < stopDeadline { RunLoop.main.run(until: Date().addingTimeInterval(0.03)) }
        app.relay?.stop()
        check(stopped && !NetworkGuard.shared.isHolding, "explicit disconnect restores the fixture network")
        exit(failures == 0 ? 0 : 1)
    }
}
