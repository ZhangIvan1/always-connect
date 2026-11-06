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
enum DiagnosticsExporter {
    static func export(manager: HelperClient, profile: Profile) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = diagnosticsFileName()
        panel.allowedContentTypes = [.plainText]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? diagnosticsText(manager: manager, profile: profile)
                .write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private static func diagnosticsFileName() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "AlwaysConnect-Diagnostics-\(formatter.string(from: Date())).txt"
    }

    private static func diagnosticsText(manager: HelperClient, profile: Profile) -> String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        let secrets = DiagnosticsRedaction.secrets(
            server: profile.server, group: profile.group,
            entries: profile.servers.map { ($0.name, $0.address, $0.ciscoName) })
        let hide = { (text: String) in DiagnosticsRedaction.redact(text, secrets: secrets) }
        let rules = ProfileStore.loadRules()
        var lines = [
            "AlwaysConnect 诊断包（服务器、Group 与名单内容已隐去，可以公开）",
            "导出时间：\(Date())",
            "App 版本：\(version)",
            "系统：\(os)",
            "",
            "Helper 状态：\(manager.state)（\(hide(manager.detail))）",
            "Helper 可用：\(manager.helperAvailable ? "是" : "否")",
            "服务器：\(profile.server.isEmpty ? "未设置" : DiagnosticsRedaction.placeholder)（共 \(profile.servers.count) 个）",
            "Group：\(profile.group.isEmpty ? "未设置" : DiagnosticsRedaction.placeholder)",
            "默认模式：\(profile.defaultMode == .secure ? "全部走 VPN" : "仅名单走 VPN")",
            "启动自动连接：\(profile.autoConnectOnLaunch ? "开" : "关")",
            "",
            "规则（\(rules.count) 条，内容不导出）：",
        ]
        for rule in rules {
            lines.append("- [\(rule.type)] \(DiagnosticsRedaction.placeholder) → \(rule.direction == .viaVPN ? "走 VPN" : "直连")\(rule.isEnabled ? "" : "（停用）")")
        }
        lines.append("")
        lines.append("掉线历史（\(manager.dropHistory.count) 次）：")
        let timeFormatter = DateFormatter()
        timeFormatter.dateFormat = "yyyy-MM-dd HH:mm"
        for drop in manager.dropHistory {
            let engine = drop.engineLabel.map { "，\($0)" } ?? ""
            lines.append(hide("- \(timeFormatter.string(from: drop.droppedAt)) → \(timeFormatter.string(from: drop.recoveredAt))：\(drop.outcomeLabel)，\(drop.summary)\(engine)"))
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
