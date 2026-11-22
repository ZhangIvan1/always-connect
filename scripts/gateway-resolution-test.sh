#!/bin/bash
# Actual Swift method bodies with deterministic XPC/clock/keychain substitutes.
# No service connection, DNS query, certificate or network change.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 - "$ROOT" "$WORK/Test.swift" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
def method(path,signature):
    s=(root/path).read_text();start=s.index(signature);at=s.index('{',start);depth=1;end=at+1
    while depth:
        depth+=(s[end]=='{')-(s[end]=='}');end+=1
    return s[start:end]
resolve=method('Sources/App/HelperClient.swift','private func resolveGatewayIPv4(').replace('private func','func',1)
resolve=resolve.replace('DispatchQueue.main.asyncAfter(deadline: .now() + 3)','Clock.after(3)').replace('DispatchQueue.main.async','Clock.enqueue')
prepare=method('Sources/App/CertificateRelay.swift','func prepare(prefer:')
daemon=method('Sources/Helper/HelperDaemon.swift','func resolveGatewayIPv4(').replace('DispatchQueue.global(qos: .utility).async','Clock.enqueue')
source=(root/'Sources/App/HelperClient.swift').read_text()
assert 'known: memory.addresses, resolved: addresses)' in source
assert 'connection.setCodeSigningRequirement(requirement)' in (root/'Sources/Helper/HelperDaemon.swift').read_text()
text='''import Foundation
@_silgen_name("ac_gateway_system_bootstrap") func ac_gateway_system_bootstrap(_ held: Int32) -> Bool
@_silgen_name("ac_gateway_literal") func ac_gateway_literal(_ host: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free") func ac_string_free(_ pointer: UnsafeMutablePointer<CChar>)
final class Proxy {
    var calls = 0
    var reply: (([String]) -> Void)?
    func resolveGatewayIPv4(_ host: String, withReply: @escaping ([String]) -> Void) { calls += 1; reply = withReply }
}
enum HelperInstaller { static var installedHelperMatchesBundle = true }
enum Clock {
    static var timers: [() -> Void] = []
    static func after(_ seconds: Int, execute: @escaping () -> Void) { precondition(seconds == 3); timers.append(execute) }
    static func enqueue(execute: @escaping () -> Void) { execute() }
    static func fire() { let pending = timers; timers = []; pending.forEach { $0() } }
}
final class Client {
    let proxy = Proxy()
    var held: Bool? = nil
    func fetchNetworkHeld(completion: @escaping (Bool?) -> Void) { completion(held) }
    func ensureConnection(_ body: (Proxy) -> Void) { body(proxy) }
'''+resolve+'''
}
enum RelayLog {
    static var lines: [String] = []
    static func write(_ line: String) { lines.append(line) }
}
final class Relay {
    let sessionId = "fixture-session"
    enum RelayError: Error { case unsupportedSystem, unresolved }
    struct Prepared { let gatewayIp: String; let serverPin: String; let addresses: [String] }
    let host = "gw.example"
    let upstreamPort: UInt16 = 443
    let queue = DispatchQueue(label: "fixture")
    var listenerIdentity: Int?
    var gatewayIp: String?
    static var dnsCalls = 0
    static func makeListenerIdentity() throws -> (Int, String) { (1, "fixture-pin") }
    static func resolveAllIPv4(_ host: String, port: UInt16) -> [String] { dnsCalls += 1; return ["203.0.113.66"] }
    static func pick(_ ips: [String], prefer: String?, avoid: String?) -> String? { ips.first }
'''+prepare+'''
}
final class GatewayLookupLease { let handle = 1; init?() {} }
enum PhysicalNetwork {
    static func current(preferring interface: String) -> (gateway: String, interface: String)? {
        ("192.168.7.1", interface == "en7" ? "en7" : "en0")
    }
}
enum LocalDNS { static func servers(for interface: String) -> [String] { ["192.168.1.1"] } }
enum NetworkGuard {
    struct Inputs { var physicalIf: String; var localDNSServers: [String] }
    static let shared = Inputs(physicalIf: "en7", localDNSServers: ["192.168.7.1"])
    static func take(_ value: UnsafeMutablePointer<CChar>?) -> String? {
        guard let value else { return nil }; defer { free(value) }; return String(cString: value)
    }
}
extension NetworkGuard.Inputs { var gatewayBootstrapContext: Self? { self } }
var observedInterface = ""; var observedServers = ""
func ac_gateway_active(_ handle: Int) -> Bool { true }
func ac_resolve_gateway(_ handle: Int, _ host: String, _ servers: String, _ interface: String) -> UnsafeMutablePointer<CChar>? {
    observedInterface = interface; observedServers = servers; return strdup("198.51.100.1")
}
final class Daemon {
'''+daemon+'''
}
@main enum Test {
    static func main() throws {
        let daemon = Daemon(); var daemonResult: [String] = []
        daemon.resolveGatewayIPv4("gw.example") { daemonResult = $0 }
        precondition(daemonResult == ["198.51.100.1"] && observedInterface == "en7" && observedServers == "192.168.7.1")
        let c = Client(); var answers: [[String]?] = []
        c.resolveGatewayIPv4("gw.example") { answers.append($0) }
        c.proxy.reply?(["198.51.100.1"]); Clock.fire(); c.proxy.reply?(["198.51.100.2"])
        precondition(answers == [["198.51.100.1"]])
        answers = []; c.resolveGatewayIPv4("gw.example") { answers.append($0) }
        Clock.fire(); c.proxy.reply?(["198.51.100.2"])
        precondition(answers == [[]])
        HelperInstaller.installedHelperMatchesBundle = false
        let before = c.proxy.calls; answers = []
        c.resolveGatewayIPv4("gw.example") { answers.append($0) }
        precondition(c.proxy.calls == before && answers == [[]])
        c.held = false; answers = []
        c.resolveGatewayIPv4("gw.example") { answers.append($0) }
        precondition(answers.count == 1 && answers[0] == nil, "unprotected legacy bootstrap must permit system DNS")
        c.held = true; answers = []
        c.resolveGatewayIPv4("gw.example") { answers.append($0) }
        precondition(answers == [[]], "protected legacy bootstrap must never permit system DNS")
        answers = []
        c.resolveGatewayIPv4("198.51.100.8") { answers.append($0) }
        precondition(answers == [["198.51.100.8"]], "numeric gateway needs no DNS or new service method")
        if #available(macOS 15.0, *) {
            let relay = Relay()
            let known = try relay.prepare(known: ["198.51.100.9"], resolved: [])
            precondition(known.gatewayIp == "198.51.100.9" && Relay.dnsCalls == 0)
            let fresh = try relay.prepare(resolved: ["198.51.100.8"])
            precondition(fresh.gatewayIp == "198.51.100.8" && Relay.dnsCalls == 0)
            do { _ = try relay.prepare(resolved: []); fatalError("empty bootstrap cannot use system DNS") }
            catch Relay.RelayError.unresolved { }
            precondition(Relay.dnsCalls == 0)
            precondition(RelayLog.lines.count == 2)
            precondition(RelayLog.lines[0].contains("session=fixture-session stage=dns source=cache candidates=0 port=443"))
            precondition(RelayLog.lines[1].contains("source=resolved candidates=1"))
            precondition(!RelayLog.lines.contains { $0.contains("198.51.100.") || $0.contains("gw.example") })
        }
        print("PASS gateway XPC match gate, 3-second timeout, duplicate/late reply and fresh-unheld-only system bootstrap, protected/unknown no fallback (substituted wiring)")
    }
}
'''
Path(sys.argv[2]).write_text(text)
PY
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$WORK/Test.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test"
"$WORK/test"
