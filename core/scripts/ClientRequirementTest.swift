import Foundation
import Security

// Harness for ClientRequirement (DESIGN.md §36.3), driven by
// scripts/helper-client-test.sh:
//   test unit                     string building
//   test req <binary>             print the requirement the background
//                                 service signed as <binary> would use
//                                 ("none" when it has no certificate)
//   test check <binary> <req>     exit 0 when <binary> satisfies <req>

@main
struct ClientRequirementTest {
    static func staticCode(_ path: String) -> SecStaticCode {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { print("FAIL cannot open \(path)"); exit(2) }
        return code
    }

    static func main() {
        let args = CommandLine.arguments
        switch args.count > 1 ? args[1] : "" {
        case "unit":
            var fails = 0
            func check(_ name: String, _ ok: Bool) { print("\(ok ? "PASS" : "FAIL") \(name)"); if !ok { fails += 1 } }
            check("no certificate, no team: nobody", ClientRequirement.make(team: nil, leafDER: nil) == nil)
            check("empty certificate: nobody", ClientRequirement.make(team: "", leafDER: Data()) == nil)
            let leaf = ClientRequirement.make(team: nil, leafDER: Data("abc".utf8))
            check("leaf: identifier + SHA-1 of the certificate",
                  leaf == "identifier \"com.alwaysconnect.app\" and certificate leaf = H\"a9993e364706816aba3e25717850c26c9cd0d89d\"")
            let team = ClientRequirement.make(team: "ABCDE12345", leafDER: Data("abc".utf8))
            check("team: Apple-anchored, same team",
                  team == "identifier \"com.alwaysconnect.app\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\"")
            check("odd team string falls back to the leaf",
                  ClientRequirement.make(team: "AB\" or true", leafDER: Data("abc".utf8)) == leaf)
            for r in [leaf, team].compactMap({ $0 }) {
                var compiled: SecRequirement?
                check("compiles: \(r.prefix(40))…",
                      SecRequirementCreateWithString(r as CFString, [], &compiled) == errSecSuccess)
            }
            exit(fails == 0 ? 0 : 1)
        case "req" where args.count == 3:
            print(ClientRequirement.derived(from: staticCode(args[2])) ?? "none")
        case "check" where args.count == 4:
            exit(ClientRequirement.staticCode(staticCode(args[2]), satisfies: args[3]) ? 0 : 1)
        default:
            print("usage: test unit | req <binary> | check <binary> <requirement>")
            exit(2)
        }
    }
}
