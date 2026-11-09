import UserNotifications

/// System notifications for the UI-DESIGN.md §二 classes the App can
/// observe from Helper state transitions: drop, restore,
/// awaiting-approval, plus terminal failures (DESIGN.md §十九):
/// credentials rejected and attempts exhausted now carry a reason
/// code from getSessionInfo, so they are posted reliably instead of
/// being guessed from detail text. The panel error row remains the
/// rejection surface for users who miss the notification.
///
/// Aggregation (AppSettings.notificationAggregation, default on):
/// on = drop/restore notifications are posted; off = only
/// action-required approval and terminal notifications are posted.
///
/// Never a silent dead end (DESIGN.md §25.5): every notice about a
/// paused network says so plainly and carries a 「恢复直连」 action that
/// does what the panel's red button does.
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()

    private var authRequested = false
    static let heldCategory = "network-held"
    static let restoreAction = "restore-direct"

    private override init() { super.init() }

    func handleTransition(from old: HelperClient.State, to new: HelperClient.State,
                          blocking: Bool = true) {
        let aggregation = ProfileStore.loadAppSettings().notificationAggregation
        switch (old, new) {
        case (.connected, .reconnecting):
            if blocking {
                // Action-required: the network is paused, always say so.
                post(title: "AlwaysConnect：网络已暂停",
                     body: "VPN 断了，正在重连；为防止流量绕过 VPN，网络暂时被拦截。点「恢复直连」可立即恢复。",
                     held: true)
            } else if aggregation {
                post(title: "AlwaysConnect", body: "VPN 断了，正在重连（断线保护已关，流量走本地网络）")
            }
        case (.reconnecting, .connected):
            if aggregation {
                post(title: "AlwaysConnect", body: "已恢复")
            }
        case (_, .awaitingApproval):
            // Action-required: posted every time, regardless of
            // aggregation — unless the approval card says it on screen
            // (DESIGN.md §29); a locked screen still gets the banner.
            if !ApprovalPrompt.shared.takesOverApprovalNotice {
                post(title: "AlwaysConnect", body: "等你在手机上确认登录")
            }
        default:
            break
        }
    }

    /// Terminal failure notification (DESIGN.md §十九), fired once
    /// per terminal transition after getSessionInfo returns.
    /// Action-required like approval: always posted, regardless of
    /// aggregation. Manual stops (1) and ongoing sessions (0) never
    /// notify; an old Helper (timeout) never reaches this method.
    func notifyTerminal(reasonCode: Int) {
        switch reasonCode {
        case 2:
            post(title: "AlwaysConnect：登录被拒，已停止重连",
                 body: "可能是密码错误，或没有在手机上点批准。网络如仍暂停，点「恢复直连」恢复。",
                 held: true)
        case 5:
            post(title: "AlwaysConnect：手机上的登录确认没有通过，已停止重连",
                 body: "确认手机能上网后点「重新连接」。网络如仍暂停，点「恢复直连」恢复。",
                 held: true)
        case 3:
            post(title: "AlwaysConnect：多次重连失败",
                 body: "请检查网络或账号。网络如仍暂停，点「恢复直连」恢复。", held: true)
        default:
            break
        }
    }

    /// Asked once at launch: asking only when the first notification
    /// is due races the authorization prompt, and that first one (a
    /// drop, an approval wait) is the one that matters.
    func requestAuthorization() {
        guard !authRequested else { return }
        authRequested = true
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let restore = UNNotificationAction(identifier: Self.restoreAction, title: "恢复直连",
                                           options: [])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.heldCategory, actions: [restore],
                                   intentIdentifiers: [], options: []),
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Still paused, as a reminder (HelperClient, every 10 minutes).
    func remindHeld() {
        post(title: "AlwaysConnect：网络仍暂停",
             body: "VPN 还没连上，网络仍被拦截。点「恢复直连」可立即恢复。", held: true)
    }

    /// The gate let go on its own while the App was gone (§25.2).
    func notifyReleasedWhileAway() {
        post(title: "AlwaysConnect 上次意外退出",
             body: "2 分钟内没有回来，网络已自动恢复直连，VPN 未连接。")
    }

    /// The own connection's self-check gave up (§26.11).
    func notifyOwnConnectionUnusable() {
        post(title: "AlwaysConnect：已自动断开自建连接",
             body: "连上后 30 秒都上不了网，已断开 VPN、恢复直连。可在设置里改用「经 Cisco」连接。")
    }

    // MARK: - UNUserNotificationCenterDelegate

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == Self.restoreAction {
            DispatchQueue.main.async { HelperClient.shared.disconnect() }
        }
        completionHandler()
    }

    /// Shown while the App is frontmost too (the panel may be open).
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    private func post(title: String, body: String, held: Bool = false) {
        let center = UNUserNotificationCenter.current()
        requestAuthorization()
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        if held { content.categoryIdentifier = Self.heldCategory }
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false))
        center.add(request, withCompletionHandler: nil)
    }
}
