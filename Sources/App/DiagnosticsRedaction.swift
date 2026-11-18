import Foundation

/// Export-only Rust projections. Never return redacted free-form text: an
/// unregistered server, account or address must not bypass the public bundle.
enum DiagnosticsRedaction {
    static let placeholder = "<已隐去>"
    enum Kind: String {
        case state, detail, outcome, engine, rule, version, timeline
        case durationSeconds, isSleepRecord, sleepDropCount
    }

    static func classify(_ kind: Kind, _ value: String) -> String {
        guard let raw = ac_diagnostics_classify(kind.rawValue, value) else { return "已省略" }
        defer { diagnostics_string_free(raw) }
        return String(cString: raw)
    }
}

@_silgen_name("ac_diagnostics_classify")
private func ac_diagnostics_classify(
    _ kind: UnsafePointer<CChar>, _ value: UnsafePointer<CChar>
) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func diagnostics_string_free(_ value: UnsafeMutablePointer<CChar>?)
