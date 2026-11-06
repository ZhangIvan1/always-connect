import AppKit
import Combine
import SwiftUI

/// The approval reminder (DESIGN.md §29, UI-DESIGN.md "等批准"): while
/// a login waits on the phone, a small bubble drops out of the menu-bar
/// icon, says what to do and how long it has waited, and goes back
/// into the icon by itself once connected. A reminder, not a blocker
/// (user, 2026-11-06): small, no sound, nothing to click away first.
///
/// - Never takes keyboard focus (non-activating panel): typing in
///   another app goes on undisturbed.
/// - On every Space and over full-screen apps; when the icon is not on
///   screen (full-screen menu bar hidden, crowded notch) it sits at the
///   top centre of the screen instead, without the arrow.
/// - Click it to open the panel; × hides it for this wait, it comes
///   back on the next request.
/// - Off in Settings (通用 → 等手机批准时在菜单栏下提醒): only the
///   system notification, as before.
final class ApprovalPrompt {
    static let shared = ApprovalPrompt()

    /// Own connection: how long "logging in" must last before the
    /// bubble shows, so a quick cookie resume never flashes it.
    static let ownLoginDelay: TimeInterval = 3
    /// How long the green "已连接" stays before the bubble goes.
    static let successLinger: TimeInterval = 1.6

    /// The menu-bar icon the bubble points at (set by AppDelegate).
    var anchor: () -> NSStatusBarButton? = { nil }
    /// Opens the menu-bar panel (set by AppDelegate).
    var openPanel: () -> Void = {}

    private var tracker = ApprovalPromptTracker()
    private let model = ApprovalCardModel()
    private var panel: ApprovalCardPanel?
    private var cancellable: AnyCancellable?
    private var ownLoginItem: DispatchWorkItem?
    private var lingerItem: DispatchWorkItem?

    private init() {}

    /// The reminder is on (Settings) and will be put on screen. The
    /// notifier skips its approval banner then, unless the screen is
    /// locked (nobody sees the bubble there).
    var takesOverApprovalNotice: Bool {
        ProfileStore.loadAppSettings().isApprovalCardOn && !Self.screenIsLocked
    }

    /// The panel opened from the icon: it says the same, so the bubble
    /// steps aside for this wait.
    func panelOpened() {
        guard tracker.isVisible else { return }
        userHid()
    }

    func start() {
        guard cancellable == nil else { return }
        cancellable = HelperClient.shared.$state
            .removeDuplicates()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in self?.stateChanged(state) }
    }

    /// Settings switched the card off: take it down now.
    func settingsChanged() {
        if AppRole.isSettings { SettingsLink.shared.send("approvalCard"); return }
        if !ProfileStore.loadAppSettings().isApprovalCardOn {
            tracker = ApprovalPromptTracker()
            dismiss(animated: true)
        } else {
            stateChanged(HelperClient.shared.state)
        }
    }

    private func stateChanged(_ state: HelperClient.State) {
        ownLoginItem?.cancel()
        ownLoginItem = nil
        guard ProfileStore.loadAppSettings().isApprovalCardOn else { return }
        switch state {
        case .awaitingApproval:
            apply(.approval)
        case .authenticating where !HelperClient.shared.usesCisco:
            let item = DispatchWorkItem { [weak self] in
                guard HelperClient.shared.state == .authenticating,
                      !HelperClient.shared.usesCisco else { return }
                self?.apply(.ownLogin)
            }
            ownLoginItem = item
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.ownLoginDelay, execute: item)
        case .authenticating:
            apply(.other)
        case .connecting:
            apply(.establishing)
        case .connected:
            apply(.connected)
        case .disconnected:
            apply(.ended)
        case .reconnecting:
            apply(.other)
        }
    }

    private func apply(_ signal: ApprovalPromptTracker.Signal) {
        switch tracker.handle(signal) {
        case .none:
            break
        case .show(let card):
            lingerItem?.cancel()
            model.card = card
            present()
        case .update(let card):
            model.card = card
        case .finish(let card):
            model.card = card
            let item = DispatchWorkItem { [weak self] in self?.dismiss(animated: true) }
            lingerItem = item
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.successLinger, execute: item)
        case .hide:
            dismiss(animated: true)
        }
    }

    private func userHid() {
        tracker.hide()
        dismiss(animated: true)
    }

    // MARK: - Window

    private func present() {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        let place = placement()
        model.arrowX = place.arrowX
        let target = place.frame
        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        if panel.isVisible, panel.alphaValue > 0.9 {
            panel.setFrame(target, display: true)
            return
        }
        panel.setFrame(reduceMotion ? target : target.offsetBy(dx: 0, dy: 10), display: false)
        panel.alphaValue = 0
        panel.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.22
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            panel.animator().setFrame(target, display: true)
            panel.animator().alphaValue = 1
        }
    }

    /// Under the menu-bar icon with the arrow on it, kept on screen;
    /// top centre without an arrow when the icon is not showing.
    private func placement() -> (frame: NSRect, arrowX: CGFloat?) {
        let size = NSSize(width: ApprovalBubbleMetrics.windowWidth,
                          height: ApprovalBubbleMetrics.windowHeight)
        let pad = ApprovalBubbleMetrics.sidePad
        if let button = anchor(), let window = button.window, window.isVisible,
           window.occlusionState.contains(.visible), let screen = window.screen {
            let icon = window.convertToScreen(button.convert(button.bounds, to: nil))
            let bounds = screen.visibleFrame
            var x = icon.midX - size.width / 2
            x = min(max(x, bounds.minX + 4 - pad), bounds.maxX - size.width - 4 + pad)
            let frame = NSRect(x: x.rounded(),
                               y: (icon.minY - size.height - 1 + ApprovalBubbleMetrics.topPad).rounded(),
                               width: size.width, height: size.height)
            return (frame, icon.midX - frame.minX - pad)
        }
        let screen = Self.screenUnderPointer()
        let frame = NSRect(x: (screen.frame.midX - size.width / 2).rounded(),
                           y: (screen.visibleFrame.maxY - size.height - 2 + ApprovalBubbleMetrics.topPad).rounded(),
                           width: size.width, height: size.height)
        return (frame, nil)
    }

    private func dismiss(animated: Bool) {
        lingerItem?.cancel()
        lingerItem = nil
        guard let panel, panel.isVisible else { return }
        guard animated else { release(panel); return }
        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        let frame = panel.frame
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.2
            ctx.timingFunction = CAMediaTimingFunction(name: .easeIn)
            if !reduceMotion { panel.animator().setFrame(frame.offsetBy(dx: 0, dy: 10), display: true) }
            panel.animator().alphaValue = 0
        }, completionHandler: { [weak self] in
            // A new request may have shown it again meanwhile.
            guard let self, !self.tracker.isVisible else { return }
            self.release(panel)
        })
    }

    /// Off screen = gone (DESIGN.md §32.1): the bubble's ripple and
    /// breathing glow repeat forever, and a window merely ordered out
    /// kept drawing them all day (measured: ~7 % CPU, constant redraws,
    /// after a wait the user had hidden). The window and its SwiftUI
    /// tree go with the card; the next request builds them again.
    private func release(_ panel: ApprovalCardPanel) {
        panel.orderOut(nil)
        panel.contentView = nil
        if self.panel === panel { self.panel = nil }
        model.card = nil
    }

    private func makePanel() -> ApprovalCardPanel {
        let panel = ApprovalCardPanel()
        let view = ApprovalCardView(
            model: model,
            onHide: { [weak self] in self?.userHid() },
            onOpen: { [weak self] in
                self?.userHid()
                self?.openPanel()
            })
        let host = FirstClickHostingView(rootView: view)
        host.frame.size = NSSize(width: ApprovalBubbleMetrics.windowWidth,
                                 height: ApprovalBubbleMetrics.windowHeight)
        panel.contentView = host
        return panel
    }

    private static func screenUnderPointer() -> NSScreen {
        let point = NSEvent.mouseLocation
        return NSScreen.screens.first { NSMouseInRect(point, $0.frame, false) }
            ?? NSScreen.main ?? NSScreen.screens[0]
    }

    /// The login window is up (screen locked): the bubble would sit
    /// behind it, so the notification stays the way to tell.
    static var screenIsLocked: Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return (session["CGSSessionScreenIsLocked"] as? Bool) ?? false
    }
}
