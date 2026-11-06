import Foundation

/// One drop episode (DESIGN.md §21.22): from the moment a live tunnel
/// dropped (connected → reconnecting) until it ended — reconnected,
/// stopped retrying, disconnected by the user, or the App quit.
/// Foundation only, so scripts/drop-history-test.sh can compile it alone.
///
/// Fields added in §21.22 are optional: records saved before them
/// decode with nil (synthesized Codable uses decodeIfPresent for
/// optionals) and read as "recovered, no retry details".
struct DropRecord: Codable, Equatable, Identifiable {
    enum Outcome: String, Codable {
        case recovered      // back to connected
        case failed         // stopped retrying (rejected login, attempts used up, gave up)
        case stoppedByUser  // the user disconnected while it was still retrying
        case quit           // the App quit while it was still retrying
    }

    var id: UUID = UUID()
    var droppedAt: Date
    /// When the episode ended (the name predates failed episodes).
    var recoveredAt: Date
    var outcome: Outcome?
    /// Re-logins started during the episode (Cisco engine / Helper
    /// openconnect engine episodeRetries). 0 = the session came back
    /// by itself; nil = old record.
    var retries: Int?
    /// Times the episode waited for approval on the phone.
    var approvals: Int?
    /// "cisco" or "own".
    var engine: String?
    /// Why a failed episode stopped, in the user's words.
    var failureReason: String?

    var durationSeconds: TimeInterval {
        max(0, recoveredAt.timeIntervalSince(droppedAt))
    }

    var resolvedOutcome: Outcome { outcome ?? .recovered }
}

// MARK: - Text (Diagnostics page, panel, diagnostics bundle)

extension DropRecord {
    static func durationText(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds.rounded()))
        if total < 60 { return "\(total) 秒" }
        if total < 3600 {
            let s = total % 60
            return s == 0 ? "\(total / 60) 分钟" : "\(total / 60) 分 \(s) 秒"
        }
        let m = total % 3600 / 60
        return m == 0 ? "\(total / 3600) 小时" : "\(total / 3600) 小时 \(m) 分"
    }

    /// Short result tag at the end of the row.
    var outcomeLabel: String {
        switch resolvedOutcome {
        case .recovered: return "已恢复"
        case .failed: return "没恢复"
        case .stoppedByUser: return "你断开了"
        case .quit: return "退出了 App"
        }
    }

    var engineLabel: String? {
        switch engine {
        case "cisco": return "经 Cisco"
        case "own": return "自建连接"
        default: return nil
        }
    }

    /// One sentence: how long it was down, how many re-logins, how it
    /// ended and why.
    var summary: String {
        let down = "断了 \(Self.durationText(durationSeconds))"
        let relogins: String? = retries.flatMap { $0 > 0 ? "重新登录 \($0) 次" : nil }
        var text: String
        switch resolvedOutcome {
        case .recovered:
            if let retries {
                text = retries == 0 ? "\(down)，连接自己续上了（没有重新登录）"
                    : "\(down)，重新登录 \(retries) 次后恢复"
            } else {
                text = "\(down)后恢复（旧记录，没有重试详情）"
            }
        case .failed:
            text = "\(down)，\(relogins.map { $0 + "后" } ?? "")停止重试"
            if let failureReason { text += "：\(failureReason)" }
        case .stoppedByUser:
            text = "\(down)，\(relogins.map { $0 + "时" } ?? "重连中")你断开了 VPN"
        case .quit:
            text = "\(down)，\(relogins.map { $0 + "时" } ?? "重连中")退出了 App"
        }
        if let approvals, approvals > 0 {
            text += "；其中 \(approvals) 次等你在手机上批准"
        }
        return text
    }

    /// The panel's one line after "上次掉线 <time>，".
    var panelSummary: String {
        let down = Self.durationText(durationSeconds)
        let relogins = retries.flatMap { $0 > 0 ? "，重新登录 \($0) 次" : nil } ?? ""
        switch resolvedOutcome {
        case .recovered: return "断了 \(down)\(relogins)后恢复"
        case .failed: return "断了 \(down)\(relogins)，没恢复"
        case .stoppedByUser: return "断了 \(down)\(relogins)，你断开了"
        case .quit: return "断了 \(down)\(relogins)，退出了 App"
        }
    }

    /// The terminal reason the engine reports after "disconnected"
    /// (DESIGN.md §十九: 1 manual stop, 2 credentials rejected,
    /// 3 attempts exhausted) refines a failed / stopped record.
    func applyingTerminal(_ code: Int) -> DropRecord {
        var record = self
        switch code {
        case 1:
            if record.outcome == .failed { record.outcome = .stoppedByUser }
        case 2:
            record.outcome = .failed
            record.failureReason = "账号或密码被拒绝"
        case 3:
            record.outcome = .failed
            record.failureReason = "重试次数用完"
        default:
            break
        }
        return record
    }
}

// MARK: - Episode tracking

/// Follows the App's state stream and turns each drop episode into a
/// DropRecord. Pure value type: HelperClient feeds it states, retry
/// counts and user actions (DESIGN.md §21.22).
struct DropEpisodeTracker {
    enum Event: Equatable {
        case connected, reconnecting, awaitingApproval, connecting, disconnected
    }

    struct Episode: Equatable {
        var start: Date
        var engine: String
        var retries = 0
        var approvals = 0
        var userStopped = false
    }

    private(set) var episode: Episode?

    /// Feeds one state transition (repeats of the same state are
    /// harmless). Returns the finished record when this ends an episode.
    mutating func handle(_ event: Event, previous: Event, engine: String,
                         retries: Int, now: Date = Date()) -> DropRecord? {
        if episode == nil, event == .reconnecting, previous == .connected {
            episode = Episode(start: now, engine: engine)
        }
        guard var current = episode else { return nil }
        current.retries = max(current.retries, retries)
        if event == .awaitingApproval, previous != .awaitingApproval {
            current.approvals += 1
        }
        episode = current
        switch event {
        case .connected:
            return finish(.recovered, now: now)
        case .disconnected:
            return finish(current.userStopped ? .stoppedByUser : .failed, now: now)
        default:
            return nil
        }
    }

    /// The live retry count arrived (asynchronously for the own connection).
    mutating func noteRetries(_ retries: Int) {
        guard var current = episode else { return }
        current.retries = max(current.retries, retries)
        episode = current
    }

    /// The user pressed disconnect; the coming "disconnected" ends the
    /// episode as theirs, not as a failure.
    mutating func noteUserStop() {
        episode?.userStopped = true
    }

    /// The App is quitting mid-episode: record it now (the
    /// disconnected push may never arrive).
    mutating func finishForQuit(now: Date = Date()) -> DropRecord? {
        guard episode != nil else { return nil }
        return finish(.quit, now: now)
    }

    private mutating func finish(_ outcome: DropRecord.Outcome, now: Date) -> DropRecord? {
        guard let current = episode else { return nil }
        episode = nil
        return DropRecord(
            droppedAt: current.start, recoveredAt: now, outcome: outcome,
            retries: current.retries, approvals: current.approvals,
            engine: current.engine, failureReason: nil)
    }
}
