import Foundation

/// Server entry names from the local Cisco Secure Client profiles
/// (DESIGN.md §20.6). "VPN-A" is a profile entry's HostName, not a
/// host: openconnect cannot resolve it. Cisco keeps the mapping to
/// the real HostAddress in its profile XML on this Mac, so the App
/// looks the name up there at connect time instead of the repository
/// carrying company hostnames. A server that already looks like an
/// address (has a dot or a colon), or a name no profile knows, is
/// passed through unchanged.
enum CiscoProfiles {
    static let directories = [
        "/opt/cisco/secureclient/vpn/profile",
        "/opt/cisco/anyconnect/profile",
    ]

    static func resolve(_ server: String) -> String {
        let name = server.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !name.contains("."), !name.contains(":") else {
            return name
        }
        return hostEntries()[name] ?? name
    }

    /// The user's Cisco "Allow local (LAN) access" preference. Cisco
    /// Secure Client 5 keeps it in the machine-wide preferences file
    /// (/opt/cisco/secureclient/vpn/.anyconnect_global, observed
    /// 2026-11-03 with the box ticked); older AnyConnect used
    /// ~/.anyconnect. The first file that mentions it wins. nil = no
    /// preferences file mentions it yet (the profile default, off).
    static func localLanAccessEnabled() -> Bool? {
        let candidates = [
            "/opt/cisco/secureclient/vpn/.anyconnect_global",
            FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".anyconnect").path,
            "/opt/cisco/anyconnect/.anyconnect_global",
        ]
        for path in candidates {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  text.contains("<LocalLanAccess")
            else { continue }
            return localLanAccess(in: text)
        }
        return nil
    }

    private static func localLanAccess(in text: String) -> Bool {
        guard let open = text.range(of: "<LocalLanAccess"),
              let close = text.range(of: "</LocalLanAccess>", range: open.upperBound..<text.endIndex),
              let gt = text.range(of: ">", range: open.upperBound..<close.lowerBound)
        else { return false }
        return text[gt.upperBound..<close.lowerBound]
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "true"
    }

    /// HostName -> HostAddress across every profile; the first
    /// profile (by file name) to define a name wins.
    static func hostEntries() -> [String: String] {
        var entries: [String: String] = [:]
        let fm = FileManager.default
        for dir in directories {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files.sorted() where file.hasSuffix(".xml") {
                let url = URL(fileURLWithPath: dir).appendingPathComponent(file)
                guard let parser = XMLParser(contentsOf: url) else { continue }
                let collector = HostEntryCollector()
                parser.delegate = collector
                parser.parse()
                for (name, address) in collector.entries where entries[name] == nil {
                    entries[name] = address
                }
            }
        }
        return entries
    }
}

private final class HostEntryCollector: NSObject, XMLParserDelegate {
    var entries: [(String, String)] = []
    private var inHostEntry = false
    private var name = ""
    private var address = ""
    private var text = ""

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes: [String: String] = [:]) {
        if elementName == "HostEntry" {
            inHostEntry = true
            name = ""
            address = ""
        }
        text = ""
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        text += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName: String?) {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch elementName {
        case "HostName" where inHostEntry: name = value
        case "HostAddress" where inHostEntry: address = value
        case "HostEntry":
            if !name.isEmpty, !address.isEmpty { entries.append((name, address)) }
            inHostEntry = false
        default: break
        }
        text = ""
    }
}
