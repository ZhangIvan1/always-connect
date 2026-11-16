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
source=(root/'Sources/App/HelperClient.swift').read_text()
assert 'known: memory.addresses, resolved: addresses)' in source
assert 'connection.setCodeSigningRequirement(requirement)' in (root/'Sources/Helper/HelperDaemon.swift').read_text()
text='''import Foundation
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
    func ensureConnection(_ body: (Proxy) -> Void) { body(proxy) }
'''+resolve+'''
}
final class Relay {
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
@main enum Test {
    static func main() throws {
        let c = Client(); var answers: [[String]] = []
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
        if #available(macOS 15.0, *) {
            let relay = Relay()
            let known = try relay.prepare(known: ["198.51.100.9"], resolved: [])
            precondition(known.gatewayIp == "198.51.100.9" && Relay.dnsCalls == 0)
            let fresh = try relay.prepare(resolved: ["198.51.100.8"])
            precondition(fresh.gatewayIp == "198.51.100.8" && Relay.dnsCalls == 0)
            do { _ = try relay.prepare(resolved: []); fatalError("empty bootstrap cannot use system DNS") }
            catch Relay.RelayError.unresolved { }
            precondition(Relay.dnsCalls == 0)
        }
        print("PASS gateway XPC match gate, 3-second timeout, duplicate/late reply and no system DNS fallback (substituted wiring)")
    }
}
'''
Path(sys.argv[2]).write_text(text)
PY
swiftc -O -parse-as-library "$WORK/Test.swift" -o "$WORK/test"
"$WORK/test"
