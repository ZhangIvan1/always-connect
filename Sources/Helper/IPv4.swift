import Darwin

/// Dotted-quad helpers for the Swift orchestration that still parses
/// addresses itself (DirectRoutes, Connections). The DNS forwarder's own
/// matching is in Rust (core/src/dns_forwarder.rs, DESIGN.md §32.6).
enum IPv4 {
    static func value(_ s: String) -> UInt32? {
        var a = in_addr()
        guard inet_pton(AF_INET, s, &a) == 1 else { return nil }
        return UInt32(bigEndian: a.s_addr)
    }

    /// "a.b.c.d/n" as (first, last).
    static func range(_ cidr: String) -> (UInt32, UInt32)? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let base = value(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits)
        else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
        return (base & mask, (base & mask) | ~mask)
    }
}
