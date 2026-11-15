import AppKit
import UniformTypeIdentifiers

/// One-click diagnostics export (UI-DESIGN.md §五诊断页, Cisco DART
/// equivalent): Helper state, profile, rules, drop history, app and
/// system versions. Deliberately excludes all secrets: no password,
/// and no username either, even though the username alone is not
/// classified secret elsewhere. It is meant to be shareable (public
/// issues), so nothing names the user's VPN either: server, Cisco
/// entries and group are hidden everywhere and split-list entries are
/// counted, not listed (DiagnosticsRedaction, DESIGN.md §36.3).
/// Every exported textual category is reconstructed in Rust; raw status and
/// history summaries are never copied (§48.5). The live panel is unchanged.
enum DiagnosticsExporter {
    static func export(manager: HelperClient, profile: Profile) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = diagnosticsFileName()
        panel.allowedContentTypes = [.plainText]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            manager.ciscoTimelineForDiagnostics { timeline in
                try? diagnosticsText(manager: manager, profile: profile, ciscoTimeline: timeline)
                    .write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private static func diagnosticsFileName() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "AlwaysConnect-Diagnostics-\(formatter.string(from: Date())).txt"
    }

    private static func diagnosticsText(
        manager: HelperClient, profile: Profile, ciscoTimeline: String
    ) -> String {
        let version = DiagnosticsRedaction.classify(
            .version, Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let state = DiagnosticsRedaction.classify(.state, String(manager.state.rawValue))
        let detail = DiagnosticsRedaction.classify(.detail, manager.detail)
        let rules = ProfileStore.loadRules()
        var lines = [
            "AlwaysConnect 诊断包（服务器、Group 与名单内容已隐去，可以公开）",
            "导出时间：\(ISO8601DateFormatter().string(from: Date()))",
            "App 版本：\(version)",
            "系统：macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            "",
            "Helper 状态：\(state)（\(detail)）",
            "Helper 可用：\(manager.helperAvailable ? "是" : "否")",
            "服务器：\(profile.server.isEmpty ? "未设置" : DiagnosticsRedaction.placeholder)（共 \(profile.servers.count) 个）",
            "Group：\(profile.group.isEmpty ? "未设置" : DiagnosticsRedaction.placeholder)",
            "默认模式：\(profile.defaultMode == .secure ? "全部走 VPN" : "仅名单走 VPN")",
            "启动自动连接：\(profile.autoConnectOnLaunch ? "开" : "关")",
            "",
            "规则（\(rules.count) 条，内容不导出）：",
        ]
        for rule in rules {
            lines.append("- [\(DiagnosticsRedaction.classify(.rule, rule.type.rawValue))] \(DiagnosticsRedaction.placeholder) → \(rule.direction == .viaVPN ? "走 VPN" : "直连")\(rule.isEnabled ? "" : "（停用）")")
        }
        lines.append("")
        lines.append("掉线历史（\(manager.dropHistory.count) 次）：")
        let timeFormatter = DateFormatter()
        timeFormatter.locale = Locale(identifier: "en_US_POSIX")
        timeFormatter.calendar = Calendar(identifier: .gregorian)
        timeFormatter.dateFormat = "yyyy-MM-dd HH:mm"
        for drop in manager.dropHistory {
            let outcome = DiagnosticsRedaction.classify(.outcome, drop.outcome?.rawValue ?? "legacy")
            let engine = DiagnosticsRedaction.classify(.engine, drop.engine ?? "")
            let reason = DiagnosticsRedaction.classify(.detail, drop.failureReason ?? "")
            let retries = drop.retries.map { String($0) } ?? "未知"
            let approvals = drop.approvals.map { String($0) } ?? "未知"
            let metadata = [
                DiagnosticsRedaction.classify(.durationSeconds, String(drop.durationSeconds)),
                DiagnosticsRedaction.classify(.isSleepRecord, String(drop.isSleepRecord)),
                DiagnosticsRedaction.classify(.sleepDropCount, String(drop.sleepDropCount)),
            ].filter { !$0.isEmpty }.joined(separator: "，")
            lines.append("- \(timeFormatter.string(from: drop.droppedAt)) → \(timeFormatter.string(from: drop.recoveredAt))：\(outcome)，\(engine)，重试 \(retries) 次，等待批准 \(approvals) 次；原因：\(reason)")
            if !metadata.isEmpty { lines[lines.count - 1] += "；\(metadata)" }
        }
        lines.append("")
        lines.append("Cisco 引擎时间线：")
        lines.append(DiagnosticsRedaction.classify(.timeline, ciscoTimeline))
        return lines.joined(separator: "\n") + "\n"
    }
}
