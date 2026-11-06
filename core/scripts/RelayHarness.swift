// Harness for the App's certificate relay (DESIGN.md §二十三), driven by
// scripts/relay-test.sh. Compiled together with
// Sources/App/CertificateRelay.swift and Sources/Shared/GatewayAddress.swift.
//
//   RelayHarness framing
//       CSTP packet reassembly and CONNECT detection, no network.
//   RelayHarness relay <identity.p12> <pass> <ca.der> <listen> <upstream> <client.pem>
//       Runs the relay with a test "company" identity (memory-only
//       import), trusting only the mock gateway's CA, and accepting
//       only client.pem. Prints "READY <gateway ip> <pin>".
import Foundation
import Security

@main
struct RelayHarness {
    static func main() {
        let args = CommandLine.arguments
        if args.count == 2, args[1] == "framing" {
            framing()
        } else if args.count == 8, args[1] == "relay" {
            relay(Array(args.dropFirst(2)))
        } else {
            fputs("usage: RelayHarness framing | relay <p12> <pass> <ca.der> <listen> <upstream> <client.pem>\n", stderr)
            exit(2)
        }
    }

    static func framing() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        // §30.6: which gateway address the relay uses.
        let two = ["198.51.100.7", "198.51.100.9"]
        check("the last session's address is kept while the name still has it",
              CertificateRelay.pick(two, prefer: "198.51.100.9", avoid: nil) == "198.51.100.9")
        check("a silent address is skipped while another exists",
              CertificateRelay.pick(two, prefer: "198.51.100.7", avoid: "198.51.100.7") == "198.51.100.9")
        check("with one address only, it is used even if it was silent",
              CertificateRelay.pick(["198.51.100.7"], prefer: nil, avoid: "198.51.100.7") == "198.51.100.7")
        check("a preferred address the name no longer has is not used",
              CertificateRelay.pick(two, prefer: "203.0.113.1", avoid: nil) == "198.51.100.7")
        check("nothing known, nothing picked", CertificateRelay.pick([], prefer: "198.51.100.7", avoid: nil) == nil)

        check("gateway address with port and path", GatewayAddress("https://gw.example:8443/group")
              == GatewayAddress("gw.example:8443/other") && GatewayAddress("gw.example:8443")?.port == 8443)
        check("gateway address defaults to 443", GatewayAddress("gw.example")?.port == 443)
        check("non-https address is refused", GatewayAddress("http://gw.example") == nil)
        print("framing FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }

    static func relay(_ a: [String]) {
        guard #available(macOS 15.0, *) else {
            print("SKIP memory-only import needs macOS 15")
            exit(77)
        }
        guard let p12 = FileManager.default.contents(atPath: a[0]),
              let caData = FileManager.default.contents(atPath: a[2]),
              let ca = SecCertificateCreateWithData(nil, caData as CFData),
              let listen = UInt16(a[3]), let upstream = UInt16(a[4]),
              let pem = try? String(contentsOfFile: a[5], encoding: .utf8)
        else { fputs("bad arguments\n", stderr); exit(2) }
        let der = Data(base64Encoded: pem.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }.joined())
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: a[1],
                       kSecImportToMemoryOnly as String: true] as CFDictionary
        guard let der, SecPKCS12Import(p12 as CFData, options, &items) == errSecSuccess,
              let value = (items as? [[String: Any]])?.first?[kSecImportItemIdentity as String]
        else { fputs("identity import failed\n", stderr); exit(2) }
        let relay = CertificateRelay(host: "localhost", port: listen, identity: value as! SecIdentity,
                                     upstreamPort: upstream, anchor: ca)
        let prepared: CertificateRelay.Prepared
        do {
            prepared = try relay.prepare()
        } catch {
            fputs("prepare failed: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
        relay.start(clientCertificate: der) { error in
            if let error {
                fputs("start failed: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
            print("READY \(prepared.gatewayIp) \(prepared.serverPin)")
            fflush(stdout)
        }
        dispatchMain()
    }
}
