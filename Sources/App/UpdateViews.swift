import SwiftUI

/// The update notice in the menu-bar panel (UI-DESIGN.md §四, DESIGN.md
/// §三十三): only while a newer release is known; nothing otherwise.
struct UpdateBanner: View {
    @ObservedObject var updates = UpdateChecker.shared
    /// Close the panel (the browser takes the focus anyway).
    var onOpen: () -> Void = {}
    @State private var confirming = false

    var body: some View {
        if let update = updates.available {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Label("有新版本 \(update.version)\(update.prerelease ? "（预发布）" : "")",
                          systemImage: "arrow.down.circle")
                        .font(.caption)
                        .foregroundStyle(Color.accentColor)
                    Spacer()
                    if !updates.installing {
                        Button("跳过") { updates.skip(update) }
                            .buttonStyle(.borderless)
                            .font(.caption)
                            .help("这个版本不再提示，更新的版本出来时照常提示")
                        Button("查看") {
                            updates.openReleasePage(update)
                            onOpen()
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("在浏览器里打开这个版本的发布页")
                        if !confirming {
                            Button("更新") { confirming = true }
                                .font(.caption)
                                .help("下载、校验并换上新版，然后自动重新打开")
                        }
                    }
                }
                UpdateProgress(update: update, confirming: $confirming) {
                    updates.install(update)
                }
            }
        }
    }
}

/// The line under "有新版本": the confirmation, the download, or why it
/// stopped. Shared by the panel and Settings.
struct UpdateProgress: View {
    @ObservedObject var updates = UpdateChecker.shared
    let update: UpdateChecker.Available
    @Binding var confirming: Bool
    let start: () -> Void

    var body: some View {
        if updates.installing {
            VStack(alignment: .leading, spacing: 4) {
                if case .downloading(let done, let total) = updates.installStep, total > 0 {
                    ProgressView(value: Double(min(done, total)), total: Double(total))
                        .progressViewStyle(.linear)
                        .controlSize(.small)
                }
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(Self.stepText(updates.installStep, version: update.version))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } else if confirming {
            VStack(alignment: .leading, spacing: 4) {
                Text(UpdateSteps.confirm)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Spacer()
                    Button("取消") { confirming = false }
                        .font(.caption)
                    Button("继续更新") {
                        confirming = false
                        start()
                    }
                    .font(.caption)
                    .keyboardShortcut(.defaultAction)
                }
            }
        } else if let error = updates.installError {
            Text("更新没有完成：\(error)。原来的版本没有改动，可以再试一次或打开发布页手动下载。")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

extension UpdateProgress {
    /// One line per step of a running update (DESIGN.md §38.5).
    static func stepText(_ step: UpdateChecker.InstallStep?, version: String) -> String {
        func mb(_ bytes: Int64) -> String { String(format: "%.1f", Double(bytes) / 1_000_000) }
        switch step {
        case .downloading(let done, let total) where total > 0:
            return "正在下载 \(version)：\(mb(min(done, total))) / \(mb(total)) MB（VPN 照常可用）"
        case .downloading(let done, _):
            return "正在下载 \(version)：已下载 \(mb(done)) MB（VPN 照常可用）"
        case .checking:
            return "正在校验新版…"
        case .restarting:
            return "校验通过，正在退出并换上新版，几秒后自动打开…"
        case .finding, .none:
            return "正在查找 \(version) 的安装包…"
        }
    }
}

enum UpdateSteps {
    static let confirm = "更新会退出并重新打开 AlwaysConnect：VPN 断开一下后自动重新连接，可能要在手机上再确认一次登录。"
        + "后台服务也要更新时，新版打开后会请你输一次电脑密码。"
    static let full = "点\u{201C}立即更新\u{201D}会下载并校验新版，然后自动退出、换上新版并重新打开。"
        + "也可以在终端执行下面的命令，效果相同（以后装新版也用它）。"
}

/// Settings → General → 版本 (UI-DESIGN.md §六): this version, a button
/// that checks now, and what it found.
struct UpdateSection: View {
    @ObservedObject private var updates = UpdateChecker.shared
    @State private var message: String?
    @State private var copied = false
    @State private var confirming = false
    @State private var startedFromSettings = false

    var body: some View {
        Section {
            LabeledContent("当前版本") {
                HStack(spacing: 8) {
                    Text(UpdateChecker.currentVersion)
                        .foregroundStyle(.secondary)
                    Button(updates.checking ? "正在检查…" : "检查更新") { checkNow() }
                        .disabled(updates.checking)
                }
            }
            if let update = updates.available {
                LabeledContent("有新版本 \(update.version)\(update.prerelease ? "（预发布）" : "")") {
                    HStack(spacing: 8) {
                        Button("跳过这个版本") {
                            updates.skip(update)
                            message = "已跳过 \(update.version)，更新的版本出来时会再提示"
                        }
                        Button("打开发布页") { updates.openReleasePage(update) }
                        Button("立即更新") { confirming = true }
                            .disabled(confirming || updates.installing || startedFromSettings)
                    }
                    .disabled(updates.installing)
                }
                if startedFromSettings {
                    Text("已开始更新：新版下载并校验好后，AlwaysConnect 会自动退出并打开新版；出了问题会在菜单栏面板里说明。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    UpdateProgress(update: update, confirming: $confirming) {
                        // The menu-bar App does it: it is the one that quits
                        // and its panel shows a failure (§32.15).
                        if AppRole.isSettings {
                            SettingsLink.shared.send("installUpdate")
                            startedFromSettings = true
                        } else {
                            updates.install(update)
                        }
                    }
                }
                Text(UpdateSteps.full)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                LabeledContent {
                    Button(copied ? "已复制" : "复制") {
                        UpdateChecker.copyInstallCommand()
                        copied = true
                    }
                } label: {
                    Text(UpdateChecker.installCommand)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }
            if let message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            Text("版本")
        } footer: {
            Text(footer)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var footer: String {
        var text = "每天自动查一次 GitHub 上的发布（含预发布），有新版只在菜单栏面板里提示，你点\u{201C}更新\u{201D}才会下载安装。"
        if let last = updates.lastSuccess {
            let f = DateFormatter()
            f.locale = Locale(identifier: "zh_CN")
            f.dateFormat = "M月d日 HH:mm"
            text += "上次检查：\(f.string(from: last))。"
        }
        return text
    }

    private func checkNow() {
        message = nil
        updates.check { outcome in
            switch outcome {
            case .newer(let update): message = "有新版本 \(update.version)"
            case .skipped(let version): message = "最新的是 \(version)，你之前选了跳过它"
            case .current: message = "已是最新版本"
            case .unreadable: message = "暂时无法检查：发布页不可访问（仓库未公开或访问次数受限），过一会儿再试"
            case .failed: message = "检查失败：连不上 GitHub，请检查网络后再试"
            }
        }
    }
}
