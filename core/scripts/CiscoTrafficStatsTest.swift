import Foundation

@main
struct CiscoTrafficStatsTest {
    static func main() {
        let connected = """
        \r  >> state: Unknown
        \r  >> state: Connected
            Connection State:            Connected
            Management Connection State: Disconnected (user tunnel active)
        [ Bytes ]
            Bytes Sent:                  5000000001
            Bytes Received:              9000000002
        """
        let stats = CiscoTrafficStats.parse(connected)
        precondition(stats?.bytesIn == 9_000_000_002 && stats?.bytesOut == 5_000_000_001)
        precondition(CiscoTrafficStats.parse(connected.replacingOccurrences(of: "5000000001", with: "0"))?.bytesOut == 0)
        for invalid in [
            "", connected.replacingOccurrences(of: "State:            Connected", with: "State:            Disconnected"),
            connected.replacingOccurrences(of: "Bytes Received:", with: "Other:"),
            connected.replacingOccurrences(of: "5000000001", with: "-1"),
            connected.replacingOccurrences(of: "9000000002", with: "unknown"),
            connected.replacingOccurrences(of: "5000000001", with: "99999999999999999999")
        ] {
            precondition(CiscoTrafficStats.parse(invalid) == nil, "Must reject missing, stale or invalid counters")
        }
        print("PASS Cisco traffic: receive/send, 64-bit, zero, disconnected and invalid output")
    }
}
