import Foundation

@main
struct DiagnosticsRedactionTest {
    static func main() {
        var failures = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        let payload = "RAW_CANARY_7 USER_CANARY_7 203.0.113.73 backup-canary.example GROUP_CANARY_7"
        for kind: DiagnosticsRedaction.Kind in [
            .state, .detail, .outcome, .engine, .rule, .version, .timeline,
            .durationSeconds, .isSleepRecord, .sleepDropCount,
        ] {
            let text = DiagnosticsRedaction.classify(kind, payload)
            check("unknown \(kind.rawValue) cannot echo input", payload.split(separator: " ").allSatisfy { !text.contains($0) })
        }
        check("known error is a fixed category", DiagnosticsRedaction.classify(.detail, "Login error USER_CANARY_7") == "登录被拒绝")
        check("version is canonical numeric metadata", DiagnosticsRedaction.classify(.version, "000.02.007") == "0.2.7")
        check("IP cannot be a version", DiagnosticsRedaction.classify(.version, "203.0.113.73") == "未提供")
        check("subsecond duration survives FFI", DiagnosticsRedaction.classify(.durationSeconds, "0.375") == "实际掉线 0.375 秒")
        check("nonfinite duration is omitted", DiagnosticsRedaction.classify(.durationSeconds, "inf").isEmpty)
        check("excessive drop count is omitted", DiagnosticsRedaction.classify(.sleepDropCount, String(Int.max)).isEmpty)
        check("sleep flag uses fixed labels", DiagnosticsRedaction.classify(.isSleepRecord, "true") == "睡眠记录 true")
        exit(failures == 0 ? 0 : 1)
    }
}
