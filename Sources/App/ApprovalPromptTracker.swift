import Foundation

/// What the approval card shows, decided from the connection state
/// alone (DESIGN.md §29.1). Foundation only, so the contract runs in
/// scripts/approval-prompt-test.sh without AppKit or a Helper.
///
/// - approval: the existing explicit approval presentation (Cisco adapter).
/// - authResponse: credentials were submitted and the response is outstanding;
///   this does not assert that a phone request was sent or is pending.
/// - establishing: the login went through, the tunnel is being set up.
/// - connected / ended / other: the wait is over one way or another.
///
/// Every new wait counts as one request in the series that runs until
/// connected or disconnected; a hidden card stays hidden for that wait
/// only, the next request shows it again.
struct ApprovalPromptTracker {
    enum Signal: Equatable {
        case approval, authResponse, establishing, connected, ended, other
    }

    enum Kind: Equatable { case approval, authResponse }
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
        case .approval, .authResponse:
            let kind: Kind = signal == .approval ? .approval : .authResponse
            if let card, card.kind == kind, card.stage == .waiting {
                return .none  // the same state pushed again
            }
            // An outstanding response does not establish a phone request.
            // Only the approval adapter advances that request counter.
            if kind == .approval { requests += 1 }
            let wasHidden = card?.kind == .authResponse && hidden
            let next = Card(kind: kind, request: max(requests, 1), since: now)
            card = next
            // Hiding the response wait also hides its following approval card.
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
        case (.establishing, .authResponse): return "正在建立连接…"
        case (.waiting, .approval): return "请在手机上批准 VPN 登录"
        case (.waiting, .authResponse): return "等待认证响应"
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
            case .authResponse:
                return "正在等待网关响应，请留意手机通知 · \(waited)"
            }
        }
    }

    /// m:ss, never negative.
    static func clock(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        return String(format: "%d:%02d", s / 60, s % 60)
    }
}
