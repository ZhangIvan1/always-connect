import Foundation

/// Rule tester evaluation inside the Helper (DESIGN.md §十八).
///
/// The App cannot evaluate rules itself: the App target does not link
/// the Rust staticlib (only the Helper does). So the App sends
/// its rules as JSON with the request, and the Helper builds a throwaway
/// engine, feeds the rules in, and answers with direction + reason
/// code from ac_engine_resolve_detail. The engine lives only for this
/// call; it never touches the live session.
enum RuleEvaluator {
    /// Returns (direction, reason): direction 0 = VPN, 1 = direct,
    /// -1 = bad input (undecodable rules or bad mode).
    static func evaluate(
        app: String,
        domain: String,
        ip: String,
        rulesJSON: String,
        defaultMode: Int
    ) -> (Int, String) {
        guard let data = rulesJSON.data(using: .utf8),
              let rules = try? JSONDecoder().decode([Rule].self, from: data),
              let handle = ac_engine_new(Int32(defaultMode))
        else {
            return (-1, "bad-input")
        }
        defer { ac_engine_free(handle) }
        for rule in rules {
            let typeCode: Int32
            switch rule.type {
            case .app: typeCode = 0
            case .domain: typeCode = 1
            case .network: typeCode = 2
            }
            let direction: Int32 = rule.direction == .viaVPN ? 0 : 1
            guard rule.target.withCString({ target in
                ac_engine_add_rule(handle, typeCode, target, direction, rule.isEnabled) == 0
            }) else {
                return (-1, "bad-input")
            }
        }
        var reasonBuffer = [CChar](repeating: 0, count: 64)
        let direction = app.withCString { appC in
            domain.withCString { domainC in
                ip.withCString { ipC in
                    ac_engine_resolve_detail(
                        handle, appC, domainC, ipC,
                        &reasonBuffer, reasonBuffer.count)
                }
            }
        }
        guard direction >= 0 else {
            return (-1, "bad-input")
        }
        let reason = String(cString: reasonBuffer)
        return (Int(direction), reason)
    }
}

// MARK: - C ABI imports (alwaysconnect-core, core/src/ffi.rs)

@_silgen_name("ac_engine_new")
func ac_engine_new(_ defaultMode: Int32) -> UnsafeMutableRawPointer?

@_silgen_name("ac_engine_add_rule")
func ac_engine_add_rule(
    _ engine: UnsafeMutableRawPointer?,
    _ ruleType: Int32,
    _ target: UnsafePointer<CChar>,
    _ direction: Int32,
    _ enabled: Bool
) -> Int32

@_silgen_name("ac_engine_resolve_detail")
func ac_engine_resolve_detail(
    _ engine: UnsafeMutableRawPointer?,
    _ app: UnsafePointer<CChar>,
    _ domain: UnsafePointer<CChar>,
    _ ip: UnsafePointer<CChar>,
    _ outReason: UnsafeMutablePointer<CChar>,
    _ bufLen: Int
) -> Int32

@_silgen_name("ac_engine_free")
func ac_engine_free(_ engine: UnsafeMutableRawPointer?)
