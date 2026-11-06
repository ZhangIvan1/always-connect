import Foundation

/// Swift wrapper over ac_pf_generate (core/src/pf.rs via ffi.rs).
/// Returns the anchor text, or nil when the Rust side rejects the input
/// (bad interface, empty gateway list, invalid network/IP).
/// allowDirectEgress selects the pf set (DESIGN.md §17.5): false =
/// blocking set (fail-closed default), true = connected set
/// (physical outbound passes, so pumped direct traffic can egress).
/// allowDNS lets port 53 out to any address (DESIGN.md §二十一);
/// localDNSServers lets it out to those only, and directTable declares
/// and passes <ac_direct> (plan v2, §25.8). The blocking set covers
/// every interface, not just the physical one (§25.3).
enum PfAnchor {
    static func generate(
        physicalIf: String,
        tunnelIf: String,
        gatewayIps: [String],
        allowNetworks: [String],
        allowDirectEgress: Bool = false,
        allowDNS: Bool = false,
        localDNSServers: [String] = [],
        directTable: Bool = false
    ) -> String? {
        physicalIf.withCString { phys in
            tunnelIf.withCString { tun in
                gatewayIps.joined(separator: ",").withCString { gw in
                    allowNetworks.joined(separator: ",").withCString { allow in
                        localDNSServers.joined(separator: ",").withCString { dns in
                            let flags: Int32 = (allowDirectEgress ? 1 : 0) | (allowDNS ? 2 : 0)
                                | (directTable ? 4 : 0)
                            guard let raw = ac_pf_generate(phys, tun, gw, allow, dns, flags) else {
                                return nil
                            }
                            defer { ac_string_free(raw) }
                            return String(cString: raw)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - C ABI imports (alwaysconnect-core, core/src/ffi.rs)

@_silgen_name("ac_pf_generate")
func ac_pf_generate(
    _ physicalIf: UnsafePointer<CChar>,
    _ tunnelIf: UnsafePointer<CChar>,
    _ gatewayIpsCsv: UnsafePointer<CChar>,
    _ allowNetworksCsv: UnsafePointer<CChar>,
    _ dnsServersCsv: UnsafePointer<CChar>,
    _ flags: Int32
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)
