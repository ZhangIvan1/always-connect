import Foundation

/// What the approval card shows, decided from the connection state
/// alone (DESIGN.md §29.1). Foundation only, so the contract runs in
/// scripts/approval-prompt-test.sh without AppKit or a Helper.
///
/// - approval: the engine knows a login is waiting on the phone (the
///   Cisco engine, right after the password went in).
/// - ownLogin: the own connection is logging in; openconnect gives no
///   approval signal yet (§16.5), so the card says "when the request
///   arrives on the phone" instead of claiming one is pending.
/// - establishing: the login went through, the tunnel is being set up.
/// - connected / ended / other: the wait is over one way or another.
///
/// Every new wait counts as one request in the series that runs until
/// connected or disconnected; a hidden card stays hidden for that wait
/// only, the next request shows it again.
struct ApprovalPromptTracker {
    enum Signal: Equatable {
        case approval, ownLogin, establishing, connected, ended, other
    }

    enum Kind: Equatable { case approval, ownLogin }
    enum Stage: Equatable { case waiting, establishing, connected }

    struct Card: Equatable {
        var kind: Kind
        /// 1 for the first request since the last connect/disconnect.
        var request: Int
        var since: Date
        var stage: Stage = .waiting
    }

    enum Effect: Equatable {
        case none
        /// Show (or replace) the card.
        case show(Card)
        /// Same wait, new stage: update the card in place.
        case update(Card)
        /// Connected: show the success state briefly, then go.
        case finish(Card)
        case hide
    }

    private(set) var card: Card?
    private(set) var hidden = false
    private var requests = 0

    var isVisible: Bool { card != nil && !hidden }

    mutating func handle(_ signal: Signal, now: Date = Date()) -> Effect {
        switch signal {
        case .approval, .ownLogin:
            let kind: Kind = signal == .approval ? .approval : .ownLogin
            if let card, card.kind == kind, card.stage == .waiting {
                return .none  // the same state pushed again
            }
            // Only phone requests count: "logging in" turning into a
            // real approval wait is still the first request.
            if kind == .approval { requests += 1 }
            let wasHidden = card?.kind == .ownLogin && hidden
            let next = Card(kind: kind, request: max(requests, 1), since: now)
            card = next
            // Hidden while logging in = hidden for this login's approval too.
            hidden = wasHidden
            return wasHidden ? .none : .show(next)
        case .establishing:
            guard var current = card, current.stage == .waiting else { return .none }
            current.stage = .establishing
            card = current
            return hidden ? .none : .update(current)
        case .connected:
            requests = 0
            return close(success: true)
        case .ended:
            requests = 0
            return close(success: false)
        case .other:
            return close(success: false)
        }
    }

    /// The user hid the card: it stays away for this wait only.
    mutating func hide() {
        hidden = true
    }

    private mutating func close(success: Bool) -> Effect {
        defer { card = nil; hidden = false }
        guard var current = card else { return .none }
        if hidden { return .hide }
        if success {
            current.stage = .connected
            return .finish(current)
        }
        return .hide
    }
}

extension ApprovalPromptTracker.Card {
    var title: String {
        switch (stage, kind) {
        case (.connected, _): return "已连接"
        case (.establishing, .approval): return "已批准，正在连接…"
        case (.establishing, .ownLogin): return "正在建立连接…"
        case (.waiting, .approval): return "请在手机上批准 VPN 登录"
        case (.waiting, .ownLogin): return "正在登录 VPN"
        }
    }

    /// The line under the title, with the time waited so far.
    func subtitle(now: Date) -> String {
        switch stage {
        case .connected: return "可以继续工作了"
        case .establishing: return "马上就好"
        case .waiting:
            let waited = "已等 " + Self.clock(now.timeIntervalSince(since))
            switch kind {
            case .approval:
                return request > 1 ? "第 \(request) 次请求 · \(waited)" : "登录请求已发到手机 · \(waited)"
            case .ownLogin:
                return "手机收到批准请求时请点批准 · \(waited)"
            }
        }
    }

    /// m:ss, never negative.
    static func clock(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        return String(format: "%d:%02d", s / 60, s % 60)
    }
}
