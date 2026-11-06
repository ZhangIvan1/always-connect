// Other-VPN notices (DESIGN.md §27.2), compiled with
// Sources/App/NetworkNeighbors.swift by scripts/neighbors-test.sh.
import Foundation

@main
struct NeighborsTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        typealias O = NetworkNeighbors.Observation
        let calm = O(defaultInterface: "en0", oursActive: false, ciscoTunnel: false, apps: [],
                     systemProxy: nil, port53Busy: false, splitOn: true)
        check("nothing running: no notice", NetworkNeighbors.notices(calm).isEmpty)

        var tun = calm; tun.defaultInterface = "utun9"; tun.apps = ["ClashX"]
        let t = NetworkNeighbors.notices(tun)
        check("a foreign TUN default route is a warning naming the app",
              t.count == 1 && t[0].level == .warning && t[0].text.contains("ClashX") && t[0].text.contains("utun9"))

        var ours = tun; ours.oursActive = true
        check("our own tunnel as default route is not reported as foreign",
              NetworkNeighbors.notices(ours).allSatisfy { !$0.text.contains("utun9") })
        var cisco = tun; cisco.ciscoTunnel = true; cisco.apps = []
        check("Cisco's tunnel in Cisco mode is expected", NetworkNeighbors.notices(cisco).isEmpty)

        var proxyMode = calm; proxyMode.apps = ["sing-box"]
        let p = NetworkNeighbors.notices(proxyMode)
        check("a proxy app without TUN is only information",
              p.count == 1 && p[0].level == .info && p[0].text.contains("sing-box"))

        var dns = calm; dns.port53Busy = true
        check("port 53 taken matters only with the split on",
              NetworkNeighbors.notices(dns).first?.level == .warning
              && { var d = dns; d.splitOn = false; return NetworkNeighbors.notices(d).isEmpty }())

        var sys = calm; sys.systemProxy = "HTTP 127.0.0.1:7890"
        check("a system proxy alone is information", NetworkNeighbors.notices(sys).first?.level == .info)
        print("neighbors FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
