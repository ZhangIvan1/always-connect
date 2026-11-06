import Foundation

/// Cisco owns these session counters; the Helper's openconnect engine
/// has no interface in Cisco mode (DESIGN.md §21.18).
enum CiscoTrafficStats {
    static func parse(_ output: String) -> (bytesIn: Int64, bytesOut: Int64)? {
        var fields: [String: String] = [:]
        for line in output.split(separator: "\n") {
            let pair = line.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { continue }
            fields[pair[0].trimmingCharacters(in: .whitespacesAndNewlines)] =
                pair[1].trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // A disconnected CLI can retain counters from the last session.
        guard fields["Connection State"] == "Connected",
              let received = fields["Bytes Received"], let bytesIn = Int64(received), bytesIn >= 0,
              let sent = fields["Bytes Sent"], let bytesOut = Int64(sent), bytesOut >= 0
        else { return nil }
        return (bytesIn, bytesOut)
    }
}
