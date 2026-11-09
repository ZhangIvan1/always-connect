import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

// MARK: - First-run wizard

/// Four-step first-run wizard (UI-DESIGN.md §六). Shown when no
/// username is stored. Credential and mode steps are skippable only
/// in the sense that closing the window leaves them for next launch:
/// there is no Next past them without valid input.
struct WizardView: View {
    var onDone: () -> Void
    @ObservedObject private var helper = HelperClient.shared
    @State private var step = 0
    @State private var mode = ProfileStore.loadProfile().defaultMode
    @State private var installMessage: String?
    @State private var installOK = HelperInstaller.status == .enabled
    @State private var credentialsOK = false

    private static let titles = ["欢迎", "后台服务", "账号", "家里局域网"]

    var body: some View {
        VStack(spacing: 0) {
            Group {
                if step == 0 {
                    welcome
                } else if step == 1 {
                    serviceStep
                } else if step == 2 {
                    CredentialForm(onSaved: { refreshCredentialsOK() })
                } else {
                    Form {
                        Section {
                            LocalLanStatus()
                        } footer: {
                            Text("可以跳过，以后在「设置 → 网络」里也能看。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .formStyle(.grouped)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack(spacing: 12) {
                // Step dots: where you are, how much is left.
                HStack(spacing: 6) {
                    ForEach(0..<Self.titles.count, id: \.self) { i in
                        Circle()
                            .fill(i == step ? Color.accentColor : Color.secondary.opacity(0.35))
                            .frame(width: 7, height: 7)
                    }
                    Text(Self.titles[step])
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 4)
                }
                Spacer()
                if step > 0 {
                    Button("上一步") { step -= 1 }
                }
                if step < 3 {
                    Button("下一步") { step += 1 }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canNext)
                } else {
                    Button("完成并连接") {
                        // Split mode is not offered while inactive
                        // (DESIGN.md §20.10): everything takes the VPN.
                        var profile = ProfileStore.loadProfile()
                        profile.defaultMode = .secure
                        ProfileStore.saveProfile(profile)
                        _ = HelperClient.shared.connectWithStoredCredentials(manual: true)
                        onDone()
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(width: 560, height: 480)
        .toggleStyle(.always)
        .onAppear { refreshCredentialsOK() }
        // Approval happens in System Settings: re-read the daemon's
        // status when the user comes back.
        .onReceive(NotificationCenter.default.publisher(
            for: NSApplication.didBecomeActiveNotification)) { _ in
            if !installOK, HelperInstaller.status == .enabled {
                installOK = true
                installMessage = "后台服务已安装"
            }
            HelperClient.shared.refreshStatus()
        }
        // A service installed from the terminal (dev install) tells
        // nobody: ask it every 2 s while this step waits, so the step
        // turns green by itself instead of looking stuck.
        .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in
            if step == 1, !installOK, !helper.helperAvailable {
                HelperClient.shared.refreshStatus()
            }
        }
    }

    private var welcome: some View {
        VStack(spacing: 18) {
            Image(nsImage: GlobeIcon.image(.lock, size: 84))
            VStack(spacing: 6) {
                Text("欢迎使用 AlwaysConnect")
                    .font(.largeTitle.weight(.semibold))
                Text("让单位的 VPN 一直在线的菜单栏助手")
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 12) {
                feature("person.badge.key.fill", "记住账号，打开就自动登录")
                feature("arrow.triangle.2.circlepath", "断线后自动重连，断线期间不走本地网络")
                feature("house.fill", "连着 VPN 也能访问家里的路由器和设备")
            }
            .padding(.top, 6)
            // Responsible use (DESIGN.md §34.4): said once, before the
            // first connection, in plain words.
            Text("请只连接你所在单位授权你使用的 VPN，并遵守单位的 IT 规定。AlwaysConnect 不提供任何代理或线路，是独立的个人项目，与 Cisco 没有关联。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 420)
        }
        .padding(30)
    }

    private func feature(_ symbol: String, _ text: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
            Text(text)
        }
    }

    private var serviceStep: some View {
        Form {
            Section {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: helper.helperAvailable ? "checkmark.circle.fill" : "lock.shield")
                        .font(.title)
                        .foregroundStyle(helper.helperAvailable ? Color.green : Color.accentColor)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(helper.helperAvailable ? "后台服务已在运行" : "安装后台服务")
                            .font(.headline)
                        Text("断线时由它暂停上网、你手动断开时恢复。安装时系统会要一次电脑开机密码。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                    if !helper.helperAvailable {
                        Button("安装") {
                            HelperInstaller.install { result in
                                switch result {
                                case .success:
                                    installOK = true
                                    installMessage = nil
                                    HelperClient.shared.refreshStatus()
                                case .failure(let error):
                                    installMessage = HelperInstaller.failureText(error)
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .padding(.vertical, 4)
                if let installMessage, !helper.helperAvailable {
                    Text(installMessage).foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
    }

    private var canNext: Bool {
        switch step {
        // A Helper that already answers over XPC counts as installed,
        // however it got there (e.g. scripts/dev-helper.sh on a build
        // without a developer team, where SMAppService cannot run).
        case 1: return installOK || helper.helperAvailable
        case 2: return credentialsOK
        default: return true
        }
    }

    private func refreshCredentialsOK() {
        credentialsOK = HelperClient.shared.hasCredentials
    }
}
