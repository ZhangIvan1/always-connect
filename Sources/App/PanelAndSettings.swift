import SwiftUI

/// Menu-bar popover: a big coloured status header, ONE labelled action
/// button, server line, last error. The old small switch read the same
/// on and off inside a popover (user, 2026-11-03), so the state is now
/// spelled out and the button says what it will do (UI-DESIGN.md §四).
/// Disconnecting a working connection goes through an inline confirm
/// row; from a red state (dropped, held) the button restores the
/// direct network at once, so the user is never trapped.
/// The panel is lazily created and released on close to keep the App's
/// footprint minimal.
struct PanelView: View {
    @ObservedObject var manager: HelperClient
    var profile: Profile
    var onStart: () -> Void
    var onStop: () -> Void
    /// Close the popover, then open Settings (optionally on a tab).
    var onOpenSettings: (String?) -> Void = { SettingsWindow.shared.show(tab: $0) }
    /// Close the panel (a link opened in the browser).
    var onClose: () -> Void = {}
    @State private var showConfirmDisconnect = false
    @State private var servers = ProfileStore.loadServers()
    @State private var selectedServer = ProfileStore.loadProfile().server
    @State private var protectionOn = ProfileStore.loadAppSettings().isDropProtectionOn
    @State private var showConfirmQuit = false
    /// The split switch flipped while connected: reconnect first (§26.12).
    @State private var confirmSplit: Bool?
    @State private var siteCount = DirectSites.sites(ProfileStore.loadAppSettings()).count
    /// Other VPNs / proxies seen at panel open (§27.2).
    @State private var neighbors: [NeighborNotice] = []
    private let activityTimer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    @State private var showConfirmReset = false
    @State private var resettingNetwork = false
    @State private var resetMessage: String?
    /// Read once per panel open (it compares two binaries).
    @State private var helperOutdated = HelperInstaller.installedHelperOutdated
    @State private var installMessage: String?
    @ObservedObject private var speed = MenuBarSpeed.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            let look = StatusLook.of(manager.state, held: manager.networkHeld,
                                     hasCredentials: manager.hasCredentials)
            HStack(spacing: 12) {
                Image(nsImage: GlobeIcon.image(
                    GlobeIcon.badge(for: manager.state, held: manager.networkHeld), size: 36))
                    .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(look.headline)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(Color(nsColor: look.color))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
            }
            primaryButton
            quickSettings
            if let on = confirmSplit {
                VStack(alignment: .leading, spacing: 6) {
                    Text(on ? "开启分流要用证书重新连接一次，手机需要再批准。"
                            : "关闭分流会改回经 Cisco 重新连接一次，可能需要再批准。")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Spacer()
                        Button("取消") { confirmSplit = nil }
                        Button("重新连接") {
                            confirmSplit = nil
                            manager.setSplit(on: on)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
            ForEach(neighbors.filter { $0.level == .warning || manager.state == .disconnected }, id: \.text) { notice in
                Label(notice.text, systemImage: notice.level == .warning ? "exclamationmark.triangle.fill" : "info.circle")
                    .font(.caption)
                    .foregroundStyle(notice.level == .warning ? Color.orange : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if speed.isOn, let t = speed.totals {
                // §四十五: the menu bar shows the total, here its parts.
                Label("走 VPN ↓\(MenuBarSpeed.rate(t.vpn[0]))/s ↑\(MenuBarSpeed.rate(t.vpn[1]))/s · 直连 ↓\(MenuBarSpeed.rate(t.direct[0]))/s ↑\(MenuBarSpeed.rate(t.direct[1]))/s",
                      systemImage: "speedometer")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            if let drop = manager.lastDrop {
                Label("上次掉线 \(dropTime(drop.latestDropAt))，\(drop.panelSummary)",
                      systemImage: "clock.arrow.circlepath")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if showConfirmDisconnect {
                HStack {
                    Text("断开后网络恢复直连")
                        .font(.callout)
                    Spacer()
                    Button("确认断开") {
                        showConfirmDisconnect = false
                        onStop()
                    }
                    Button("取消") {
                        showConfirmDisconnect = false
                    }
                }
            }
            if let error = manager.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if let notice = manager.autoStopNotice, manager.state == .disconnected {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if manager.helperUnresponsive {
                // The restore got no answer (DESIGN.md §25.5): the way
                // out that needs no background service at all.
                VStack(alignment: .leading, spacing: 6) {
                    Text("后台服务没有响应，网络可能仍被暂停")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Button("强制恢复网络（需电脑密码）") {
                        manager.prepareForForcedRestore()
                        HelperInstaller.forceRecover { result in
                            switch result {
                            case .success:
                                installMessage = "网络已恢复直连"
                                manager.forcedRestoreDone()
                            case .failure(HelperInstaller.InstallError.cancelled):
                                installMessage = "已取消：需要输入电脑密码才能强制恢复"
                                manager.forcedRestoreAbandoned()
                            case .failure(let error):
                                installMessage = "强制恢复失败：\(error.localizedDescription)"
                                manager.forcedRestoreAbandoned()
                            }
                        }
                    }
                    if let installMessage {
                        Text(installMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if let warning = manager.pfWarning, manager.state != .disconnected {
                Text(warning)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if !manager.helperAvailable {
                // "Helper" is our word, not the user's: say what it is
                // for (UI-DESIGN.md §四).
                HStack {
                    Text("后台服务未运行：断线时无法封网")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Spacer()
                    Button("安装后台服务") {
                        HelperInstaller.install { result in
                            switch result {
                            case .success:
                                installMessage = "后台服务已安装"
                                manager.refreshStatus()
                            case .failure(let error):
                                installMessage = HelperInstaller.failureText(error)
                            }
                        }
                    }
                }
                if let installMessage {
                    Text(installMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if manager.helperAvailable, helperOutdated {
                // A rebuilt local App carries a newer service than the
                // one installed (DESIGN.md §21.8).
                HStack {
                    Text(manager.helperUpdateWaiting ? "等这次登录完成后再更新…"
                         : manager.helperUpdatePending ? "正在更新后台服务…"
                         : manager.switchIsOn && !manager.usesCisco ? "后台服务有新版本（更新时连接会断几秒，自动接上）" : "后台服务有新版本")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("更新") {
                        manager.installHelper { result in
                            switch result {
                            case .success:
                                helperOutdated = false
                                installMessage = "后台服务已更新"
                            case .failure(let error):
                                installMessage = HelperInstaller.failureText(error)
                            }
                        }
                    }
                    .disabled(manager.helperUpdatePending)
                }
                if let installMessage {
                    Text(installMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            UpdateBanner(onOpen: onClose)
            networkResetRow
            Divider()
            // One quiet toolbar row: Settings (server, account, network),
            // diagnostics, quit.
            HStack(spacing: 4) {
                PanelToolButton(title: "设置", symbol: "gearshape") {
                    onOpenSettings(nil)
                }
                .help("服务器地址、账号、断线保护等")
                PanelToolButton(title: "诊断包", symbol: "square.and.arrow.down") {
                    DiagnosticsExporter.export(manager: manager, profile: profile)
                }
                .help("导出诊断信息（不含密码与账号）")
                Spacer()
                // Quit = VPN off, direct network, nothing of ours left
                // running (DESIGN.md §21.5); confirm only when that
                // actually ends a connection.
                PanelToolButton(title: "退出", symbol: "power") {
                    if manager.switchIsOn {
                        showConfirmQuit = true
                    } else {
                        AppQuit.request()
                    }
                }
                .help("断开 VPN、恢复直连网络，并退出 AlwaysConnect")
            }
            if showConfirmQuit {
                HStack {
                    Text("退出会断开 VPN，网络恢复直连")
                        .font(.callout)
                    Spacer()
                    Button("断开并退出") {
                        showConfirmQuit = false
                        AppQuit.request()
                    }
                    Button("取消") { showConfirmQuit = false }
                }
            }
        }
        .padding(16)
        .frame(width: 300)
        .toggleStyle(.always)
        .onAppear {
            manager.refreshSplitActivity()
            let active = manager.state != .disconnected
            let cisco = manager.usesCisco
            let split = manager.ownConnection
            DispatchQueue.global(qos: .userInitiated).async {
                let found = NetworkNeighbors.notices(NetworkNeighbors.observe(
                    oursActive: active && !cisco, ciscoTunnel: active && cisco, splitOn: split))
                DispatchQueue.main.async { neighbors = found }
            }
        }
        .onReceive(activityTimer) { _ in manager.refreshSplitActivity() }
    }

    /// 按网站分流 in the panel (§26.12): the switch, and in one line what
    /// it is doing right now.
    private var splitRow: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Toggle(isOn: Binding(
                    get: { manager.ownConnection },
                    set: { on in
                        if manager.switchIsOn { confirmSplit = on } else { manager.setSplit(on: on) }
                    })) {
                    Label("按网站分流", systemImage: "arrow.triangle.branch")
                }
                .disabled(manager.splitSwitchPending)
            }
            HStack(spacing: 4) {
                Text(splitCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                Button("名单") { onOpenSettings("split") }
                    .buttonStyle(.link)
                    .font(.caption)
            }
        }
        .padding(.vertical, 6)
    }

    private var splitCaption: String {
        if manager.splitSwitchPending { return "正在切换，稍候会重新连接…" }
        guard manager.ownConnection else { return "关：全部走 VPN（经 Cisco）" }
        if siteCount == 0 { return "开：名单还是空的，点「名单」添加" }
        guard manager.state == .connected else { return "开：名单里 \(siteCount) 条不走 VPN" }
        guard let activity = manager.splitActivity else { return "开：名单里 \(siteCount) 条不走 VPN" }
        if activity.entries.isEmpty { return "生效中：还没打开名单里的网站" }
        let names = activity.entries.prefix(2).joined(separator: "、")
        let more = activity.entries.count > 2 ? " 等 \(activity.entries.count) 个网站" : ""
        return "生效中：\(names)\(more)直连（\(activity.addresses) 个地址）"
    }

    /// The way back when the Mac has no network because of us (DESIGN.md
    /// §24.6): always there, works offline, asks once for the Mac password.
    @ViewBuilder private var networkResetRow: some View {
        HStack {
            Text("上不了网、被 AlwaysConnect 卡住时")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button(resettingNetwork ? "恢复中…" : "恢复网络") { showConfirmReset = true }
                .controlSize(.small)
                .disabled(resettingNetwork)
                .help("断开 VPN，清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连")
        }
        if showConfirmReset {
            VStack(alignment: .leading, spacing: 6) {
                Text("会断开 VPN，并清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连。需要输入一次开机密码。")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("取消") { showConfirmReset = false }
                    Button("恢复网络") {
                        showConfirmReset = false
                        resettingNetwork = true
                        resetMessage = nil
                        manager.prepareForNetworkReset()
                        NetworkReset.run { outcome in
                            resettingNetwork = false
                            manager.networkResetFinished()
                            switch outcome {
                            case .restored(let text): resetMessage = text
                            case .failed(let text): resetMessage = "没有完全恢复：\(text)"
                            case .cancelled: resetMessage = nil
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        if let resetMessage {
            Text(resetMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The everyday switches, right in the panel (owner's request,
    /// DESIGN.md §21.13): which server, and drop protection.
    private var quickSettings: some View {
        VStack(spacing: 0) {
            HStack {
                Label("服务器", systemImage: "server.rack")
                Spacer()
                Menu {
                    ForEach(servers) { entry in
                        Button {
                            selectedServer = entry.target
                            manager.switchServer(to: entry.target)
                        } label: {
                            if entry.target == selectedServer {
                                Label(entry.name, systemImage: "checkmark")
                            } else {
                                Text(entry.name)
                            }
                        }
                    }
                    Divider()
                    Button("管理服务器…") { onOpenSettings("credentials") }
                } label: {
                    Text(servers.first { $0.target == selectedServer }?.name ?? selectedServer)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            .padding(.vertical, 7)
            Divider()
            splitRow
            // Both connection ways (DESIGN.md §26.19): off = a drop uses
            // the local network instead of pausing it.
            Divider()
            Toggle(isOn: Binding(
                get: { protectionOn },
                set: { on in
                    protectionOn = on
                    var settings = ProfileStore.loadAppSettings()
                    settings.dropProtection = on
                    ProfileStore.saveAppSettings(settings)
                    manager.dropProtectionChanged()
                })) {
                Label("断线保护", systemImage: protectionOn ? "lock.shield" : "lock.open")
            }
            .padding(.vertical, 6)
        }
        .font(.callout)
        .padding(.horizontal, 10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.06)))
    }

    /// The engine's own words under the headline (retry count, last
    /// notice); for a plain disconnect, what "未连接" means.
    private var subtitle: String {
        if !manager.hasCredentials {
            // Servers usually come from the Mac's Cisco (§三十八).
            return ProfileStore.loadProfile().servers.isEmpty ? "先填服务器、账号和密码" : "先填账号和密码"
        }
        if manager.state == .disconnected, !manager.networkHeld { return "VPN 已关，正在用本地网络上网" }
        if manager.state == .reconnecting { return manager.stateLine }
        return manager.detail.isEmpty ? manager.stateLine : manager.detail
    }

    /// One button, labelled with what it does next.
    @ViewBuilder private var primaryButton: some View {
        let red = manager.state == .reconnecting || manager.networkHeld
        if !manager.hasCredentials {
            Button(ProfileStore.loadProfile().servers.isEmpty ? "填写服务器与账号" : "填写账号与密码") {
                onOpenSettings("credentials")
            }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
        } else if manager.state == .disconnected, !manager.networkHeld {
            Button { showConfirmDisconnect = false; onStart() } label: {
                Text("连接 VPN").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        } else if red {
            // Never trapped behind drop protection: one click, no
            // confirm, back to the direct network.
            Button { showConfirmDisconnect = false; onStop() } label: {
                Text("断开 VPN，恢复直连网络").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .controlSize(.large)
        } else {
            Button { showConfirmDisconnect = true } label: {
                Text(manager.state == .connected ? "断开 VPN" : "取消连接").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
    }

    private func dropTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        if Calendar.current.isDateInToday(date) {
            formatter.dateFormat = "今天 HH:mm"
        } else {
            formatter.dateFormat = "MM-dd HH:mm"
        }
        return formatter.string(from: date)
    }
}

/// The menu-bar panel's window (DESIGN.md §32.16): a borderless panel
/// with the popover material under the icon, not an NSPopover. Measured
/// with the same SwiftUI content: an NSPopover costs ~130 MB of graphics
/// memory for as long as it shows (animated or not), this ~7 MB.
final class MenuPanel: NSPanel {
    init() {
        super.init(contentRect: NSRect(x: 0, y: 0, width: 332, height: 200),
                   styleMask: [.borderless], backing: .buffered, defer: true)
        isFloatingPanel = true
        level = .statusBar
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
        backgroundColor = .clear
        isOpaque = false
        hasShadow = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        animationBehavior = .utilityWindow
    }

    // Key, so native controls draw active (an inactive window draws them
    // grey, which read as "off", §21.14).
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func cancelOperation(_ sender: Any?) { close() }
}

/// Tells the panel when its SwiftUI content wants another size (a
/// confirm row appeared), so the window follows with its top fixed.
final class PanelHostingView<Content: View>: NSHostingView<Content> {
    var onResize: (() -> Void)?
    private var pending = false

    override func invalidateIntrinsicContentSize() {
        super.invalidateIntrinsicContentSize()
        guard !pending else { return }
        pending = true
        DispatchQueue.main.async { [weak self] in
            self?.pending = false
            self?.onResize?()
        }
    }
}

final class PanelController: NSObject, NSWindowDelegate {
    private var panel: MenuPanel?
    private weak var anchor: NSStatusBarButton?
    private var outsideClicks: Any?
    private let manager: HelperClient

    init(manager: HelperClient) {
        self.manager = manager
    }

    var isShown: Bool { panel?.isVisible ?? false }

    func toggle(relativeTo button: NSStatusBarButton) {
        if isShown {
            panel?.close()
            return
        }
        // Fresh profile on every open: Settings may have changed it
        // since launch, and the panel must not show stale values.
        // Re-attach too: re-registers for pushes after a Helper
        // restart and corrects availability.
        manager.refreshStatus()
        UpdateChecker.shared.checkIfDue()
        let view = PanelView(
            manager: manager,
            profile: ProfileStore.loadProfile(),
            onStart: { [weak self] in self?.startTapped() },
            onStop: { [weak self] in self?.manager.disconnect() },
            onOpenSettings: { [weak self] tab in
                self?.panel?.close()
                SettingsWindow.shared.show(tab: tab)
            },
            onClose: { [weak self] in self?.panel?.close() }
        )
        let panel = MenuPanel()
        let effect = NSVisualEffectView()
        effect.material = .popover
        effect.state = .active
        effect.blendingMode = .behindWindow
        effect.wantsLayer = true
        effect.layer?.cornerRadius = 12
        effect.layer?.masksToBounds = true
        let host = PanelHostingView(rootView: view)
        host.onResize = { [weak self, weak host] in
            guard let self, let host, let panel = self.panel else { return }
            let size = host.fittingSize
            if abs(size.height - panel.frame.height) > 0.5 || abs(size.width - panel.frame.width) > 0.5 {
                self.place(panel, size: size)
            }
        }
        host.translatesAutoresizingMaskIntoConstraints = false
        effect.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: effect.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: effect.trailingAnchor),
            host.topAnchor.constraint(equalTo: effect.topAnchor),
            host.bottomAnchor.constraint(equalTo: effect.bottomAnchor),
        ])
        panel.contentView = effect
        panel.delegate = self
        self.panel = panel
        anchor = button
        place(panel, size: host.fittingSize)
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        // A click anywhere else closes it, as a popover's would.
        outsideClicks = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.panel?.close()
        }
    }

    /// Under the menu-bar icon, top edge fixed (the panel grows and
    /// shrinks downwards as rows appear), kept on screen.
    private func place(_ panel: NSPanel, size: NSSize) {
        guard let button = anchor, let window = button.window else { return }
        let icon = window.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = window.screen ?? NSScreen.main
        let bounds = screen?.visibleFrame ?? icon
        var x = icon.midX - size.width / 2
        x = min(max(x, bounds.minX + 6), bounds.maxX - size.width - 6)
        let top = icon.minY - 4
        panel.setFrame(NSRect(x: x.rounded(), y: (top - size.height).rounded(),
                              width: size.width, height: size.height), display: true)
    }

    func windowDidResignKey(_ notification: Notification) {
        // A menu or sheet of the panel itself takes key briefly; anything
        // else (another app, the desktop) closes it.
        DispatchQueue.main.async { [weak self] in
            guard let self, let panel = self.panel, panel.isVisible, !panel.isKeyWindow else { return }
            if NSApp.keyWindow == nil || NSApp.keyWindow?.parent === panel { return }
            panel.close()
        }
    }

    /// Closed = gone (DESIGN.md §32.1): its SwiftUI tree, timers and
    /// polls go with it; the next open builds a fresh one.
    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? MenuPanel, closing === panel else { return }
        if let outsideClicks { NSEvent.removeMonitor(outsideClicks) }
        outsideClicks = nil
        closing.delegate = nil
        DispatchQueue.main.async { [weak self] in
            closing.contentView = nil
            if self?.panel === closing { self?.panel = nil }
        }
    }

    private func startTapped() {
        // Credentials come from the Keychain; without them the panel
        // switch is disabled, so this guard is a second line only.
        _ = manager.connectWithStoredCredentials()
    }
}

/// Small icon + label button for the panel's bottom row.
private struct PanelToolButton: View {
    var title: String
    var symbol: String
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.callout)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
    }
}
