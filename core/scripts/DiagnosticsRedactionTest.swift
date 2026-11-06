import Foundation

// DiagnosticsRedaction (DESIGN.md §36.3): nothing in the shareable
// diagnostics file names the user's VPN. Sample names only.
@main
struct DiagnosticsRedactionTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) { print("\(ok ? "PASS" : "FAIL") \(name)"); if !ok { fails += 1 } }
        let secrets = DiagnosticsRedaction.secrets(
            server: "VPN-A", group: "Staff",
            entries: [("VPN-A", "https://vpn.example.com:443/staff", "VPN-A"),
                      ("备用", "vpn-b.example.net", nil)])
        check("server host extracted", secrets.contains("vpn.example.com"))
        check("full address kept too", secrets.contains("https://vpn.example.com:443/staff"))
        check("longest first", secrets.first == "https://vpn.example.com:443/staff")
        check("short names skipped", !secrets.contains("备用"))
        let detail = "已连接 · VPN-A（经 Cisco），网关 VPN.example.com，组 staff，备用 vpn-b.example.net"
        let out = DiagnosticsRedaction.redact(detail, secrets: secrets)
        check("detail redacted: \(out)",
              !out.lowercased().contains("vpn-a") && !out.lowercased().contains("example")
              && !out.lowercased().contains("staff") && out.contains("经 Cisco"))
        check("nothing to hide: text unchanged",
              DiagnosticsRedaction.redact("断了 7 秒", secrets: DiagnosticsRedaction.secrets(server: "", group: "", entries: [])) == "断了 7 秒")
        check("host of bare name is nil", DiagnosticsRedaction.host(of: "VPN-A") == nil)
        exit(fails == 0 ? 0 : 1)
    }
}
