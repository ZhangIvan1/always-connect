// The split list's rule syntax (DESIGN.md §26.13), compiled with
// Sources/App/ListRules.swift, DirectSites.swift, ProfileStore.swift and
// Sources/Shared by scripts/list-rules-test.sh; data from Sources/App/GeoData.
import Foundation

@main
struct ListRulesTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        check("a web address becomes its domain", ListRule.parse("https://www.Example.com/path") == .domain("www.example.com"))
        check("geosite list by name", ListRule.parse("geosite:GitHub") == .geosite("github", attribute: nil))
        check("geosite with an attribute", ListRule.parse("geosite:google@cn") == .geosite("google", attribute: "cn"))
        check("unknown geosite refused with a reason", ListRule.parse("geosite:nosuchlist") == nil
              && ListRule.problem("geosite:nosuchlist") == "没有叫这个名字的网站清单")
        check("geoip:cn accepted, other countries explained", ListRule.parse("geoip:CN") == .geoip("cn")
              && ListRule.problem("geoip:us") == "目前只支持 geoip:cn")
        check("network and single address", ListRule.parse("10.1.0.0/16") == .network("10.1.0.0/16")
              && ListRule.parse("192.168.1.5") == .network("192.168.1.5/32"))
        check("junk explained", ListRule.problem("not a rule") != nil && ListRule.problem("") == nil)

        let gh = ListRule.geosite("github", attribute: nil).expanded
        check("geosite:github brings its related names", gh.contains("domain:github.com") && gh.contains("domain:ghcr.io"))
        let cn = ListRule.geosite("cn", attribute: nil).expanded
        check("geosite:cn is a large resolved list (\(cn.count))", cn.count > 1000 && cn.allSatisfy {
            $0.hasPrefix("domain:") || $0.hasPrefix("full:") || $0.hasPrefix("keyword:") || $0.hasPrefix("regexp:") })
        let googleCN = ListRule.geosite("google", attribute: "cn").expanded
        let google = ListRule.geosite("google", attribute: nil).expanded
        check("an attribute filters (\(googleCN.count) of \(google.count))", !googleCN.isEmpty && googleCN.count < google.count)
        let ip = ListRule.geoip("cn").expanded
        check("geoip:cn expands to IP ranges (\(ip.count))", ip.count > 1000 && ip.allSatisfy { $0.hasPrefix("ipcidr:") })
        check("networks are not sent to the forwarder", ListRule.network("10.0.0.0/8").expanded.isEmpty)

        // The split page's examples (SplitPage.examples) must all be valid
        // and the attribute example must select something.
        for example in ["example.com", "10.0.0.5", "192.168.50.0/24", "geosite:apple", "geosite:microsoft",
                        "geosite:github", "geosite:apple@cn"] {
            check("example \(example) is valid", ListRule.parse(example) != nil)
        }
        check("geosite:apple@cn selects rules", !ListRule.geosite("apple", attribute: "cn").expanded.isEmpty)

        var legacy = AppSettings()
        legacy.directGroups = ["preset-a"]
        legacy.directCustom = ["example.org"]
        check("old groups are not migrated, own names are",
              DirectSites.sites(legacy) == [DirectSite(name: "example.org", domains: ["example.org"])])

        var settings = AppSettings()
        settings.directSites = [DirectSite(name: "x", domains: ["example.com"]),
                                DirectSite(name: "10.9.0.0/16", domains: ["10.9.0.0/16"]),
                                DirectSite(name: "geosite:github", domains: ["geosite:github"])]
        settings.autoLAN = false
        check("the forwarder gets names and lists, not networks",
              settings.directDomains.contains("example.com") && settings.directDomains.contains("domain:ghcr.io")
              && !settings.directDomains.contains("10.9.0.0/16"))
        check("the allowlist gets the list's networks", settings.effectiveAllowNetworks == ["10.9.0.0/16"])
        settings.autoLAN = nil
        let local = LocalNetwork.current()
        check("local network on by default (\(local.joined(separator: ",")))",
              settings.effectiveAllowNetworks == ["10.9.0.0/16"] + local.filter { $0 != "10.9.0.0/16" })
        check("local networks are real CIDRs no wider than /16", local.allSatisfy { isValidCIDR($0)
              && (Int($0.split(separator: "/")[1]) ?? 0) >= 16 })
        // Adding from the 连接 page (DESIGN.md §四十四).
        check("site of a name", DirectSites.site(of: "www.example.com") == "example.com"
              && DirectSites.site(of: "a.b.example.com.cn") == "example.com.cn"
              && DirectSites.site(of: "files.example.co.uk") == "example.co.uk"
              && DirectSites.site(of: "example.com") == "example.com")
        let menu = DirectSites.choices(host: "a.b.example.com", address: "93.184.215.14")
        check("menu: whole site first, each level, the name, then the address",
              menu.map(\.rule) == ["example.com", "b.example.com", "a.b.example.com", "93.184.215.14/32"]
              && menu.first?.label.contains("整个网站") == true && menu[2].label.contains("只这一个"))
        check("menu for a bare site has no duplicate",
              DirectSites.choices(host: "example.com", address: "93.184.215.14").map(\.rule) == ["example.com", "93.184.215.14/32"])
        check("menu without a name offers only the address",
              DirectSites.choices(host: nil, address: "203.0.113.10").map(\.rule) == ["203.0.113.10/32"])
        check("every menu line is a valid list line", menu.allSatisfy { ListRule.parse($0.rule) != nil })
        let list = [DirectSite(name: "example.com", domains: ["example.com"]),
                    DirectSite(name: "198.51.100.0/24", domains: ["198.51.100.0/24"]),
                    DirectSite(name: "geosite:github", domains: ["geosite:github"])]
        check("a name under a list domain is covered",
              DirectSites.covering(list, host: "mail.example.com", address: "203.0.113.1") == "example.com")
        check("a look-alike name is not covered",
              DirectSites.covering(list, host: "badexample.com", address: "203.0.113.1") == nil)
        check("an address in a list network is covered",
              DirectSites.covering(list, host: nil, address: "198.51.100.77") == "198.51.100.0/24")
        check("site lists are not looked into", DirectSites.covering(list, host: "github.com", address: "203.0.113.1") == nil)
        let added = DirectSites.adding("203.0.113.10/32", to: list)
        check("adding appends once", added.count == 4 && DirectSites.adding("203.0.113.10/32", to: added) == added
              && DirectSites.adding("example.com", to: list) == list)
        check("removing takes out only that line", DirectSites.removing("example.com", from: list) == Array(list.dropFirst()))
        let group = [DirectSite(name: "Old group", domains: ["example.com", "example.org"])]
        check("removing from a migrated group keeps the rest",
              DirectSites.removing("example.org", from: group) == [DirectSite(name: "Old group", domains: ["example.com"])])

        print("list-rules FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
