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
    /// Drops while the Mac slept (DESIGN.md §41): the window's start
    /// (the App's "will sleep"), shared by every drop of one sleep, so
    /// they fold into one record. Nil = an ordinary drop.
    var sleepSince: Date?
    /// Drops folded into this sleep record (1 for the first).
    var sleepDrops: Int?
    /// When the newest folded drop began (droppedAt is the first's).
    var lastDroppedAt: Date?
    /// Time actually down, summed over the folded drops (the span from
    /// the first drop to the last recovery is mostly connected time).
    var downSeconds: TimeInterval?

    var durationSeconds: TimeInterval {
        if let downSeconds { return max(0, downSeconds) }
        return max(0, recoveredAt.timeIntervalSince(droppedAt))
    }

    var isSleepRecord: Bool { sleepSince != nil }
    var sleepDropCount: Int { max(1, sleepDrops ?? 1) }
    /// The newest drop's start (the panel's "上次掉线" time).
    var latestDropAt: Date { lastDroppedAt ?? droppedAt }

    /// Folds `next`, a later drop of the same sleep, into this record:
    /// counts and down time add up, the outcome is the latest one.
    func folding(_ next: DropRecord) -> DropRecord {
        var merged = self
        merged.sleepDrops = sleepDropCount + next.sleepDropCount
        merged.downSeconds = durationSeconds + next.durationSeconds
        merged.lastDroppedAt = next.latestDropAt
        merged.recoveredAt = next.recoveredAt
        merged.outcome = next.outcome
        merged.failureReason = next.failureReason
        merged.retries = (retries ?? 0) + (next.retries ?? 0)
        merged.approvals = (approvals ?? 0) + (next.approvals ?? 0)
        merged.engine = next.engine ?? engine
        return merged
    }

    /// The history with `record` added: a drop of the same sleep as the
    /// newest record folds into it, anything else is a new entry.
    static func appending(_ record: DropRecord, to history: [DropRecord]) -> [DropRecord] {
        if let since = record.sleepSince, let last = history.last, last.sleepSince == since {
            return history.dropLast() + [last.folding(record)]
        }
        return history + [record]
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
        if isSleepRecord { return sleepSummary }
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

    /// A sleep record's sentence: how many drops, the time down in
    /// total, and how the last one ended.
    private var sleepSummary: String {
        let n = sleepDropCount
        let down = Self.durationText(durationSeconds)
        let relogins: String? = retries.flatMap { $0 > 0 ? "重新登录 \($0) 次" : nil }
        var text = n > 1 ? "电脑睡眠时断了 \(n) 次，合计 \(down)" : "电脑睡眠时断了 \(down)"
        switch resolvedOutcome {
        case .recovered:
            if let relogins {
                text += n > 1 ? "，共\(relogins)，都已恢复" : "，\(relogins)后恢复"
            } else {
                text += n > 1 ? "，每次都自己续上了（没有重新登录）" : "，连接自己续上了（没有重新登录）"
            }
        case .failed:
            text += n > 1 ? "，\(relogins.map { "共" + $0 + "，" } ?? "")最后一次停止重试"
                : "，\(relogins.map { $0 + "后" } ?? "")停止重试"
            if let failureReason { text += "：\(failureReason)" }
        case .stoppedByUser:
            text += n > 1 ? "，\(relogins.map { "共" + $0 + "，" } ?? "")最后一次重连中你断开了 VPN"
                : "，\(relogins.map { $0 + "时" } ?? "重连中")你断开了 VPN"
        case .quit:
            text += n > 1 ? "，\(relogins.map { "共" + $0 + "，" } ?? "")最后一次重连中退出了 App"
                : "，\(relogins.map { $0 + "时" } ?? "重连中")退出了 App"
        }
        if let approvals, approvals > 0 {
            text += "；其中 \(approvals) 次等你在手机上批准"
        }
        return text
    }

    /// The panel's one line after "上次掉线 <time>，".
    var panelSummary: String {
        if isSleepRecord {
            let n = sleepDropCount
            let down = Self.durationText(durationSeconds)
            let head = n > 1 ? "睡眠中断了 \(n) 次（合计 \(down)）" : "睡眠中断了 \(down)"
            let relogins = retries.flatMap { $0 > 0 ? "，重新登录 \($0) 次" : nil } ?? ""
            switch resolvedOutcome {
            case .recovered: return n > 1 ? "\(head)\(relogins)，都已恢复" : "\(head)\(relogins)后恢复"
            case .failed: return "\(head)\(relogins)，没恢复"
            case .stoppedByUser: return "\(head)\(relogins)，你断开了"
            case .quit: return "\(head)\(relogins)，退出了 App"
            }
        }
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
    /// 3 attempts exhausted, 5 phone confirmation failed twice, §43) refines a failed / stopped record.
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
        case 5:
            record.outcome = .failed
            record.failureReason = "手机上的登录确认没有通过"
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
        /// The sleep this drop began in (nil = the Mac was awake).
        var sleepSince: Date?
    }

    private(set) var episode: Episode?

    /// The Mac's sleep as the App sees it (DESIGN.md §41): opened by
    /// "will sleep", closed when the screens wake. The brief dark wakes
    /// in between (mail, iCloud; the tunnel reconnects in them) wake no
    /// screen, so one night is one window.
    private(set) var sleepSince: Date?
    private(set) var wokeAt: Date?
    /// A drop found right after opening the lid is still the sleep's.
    static let wakeGrace: TimeInterval = 60

    mutating func noteSleep(now: Date = Date()) {
        // Already asleep (a repeated notice): keep the window's start.
        if sleepSince != nil, wokeAt == nil { return }
        sleepSince = now
        wokeAt = nil
    }

    mutating func noteWake(now: Date = Date()) {
        if sleepSince != nil, wokeAt == nil { wokeAt = now }
    }

    /// The sleep a drop starting at `now` belongs to, if any.
    func sleepWindow(at now: Date) -> Date? {
        guard let since = sleepSince else { return nil }
        if let wokeAt, now.timeIntervalSince(wokeAt) > Self.wakeGrace { return nil }
        return since
    }

    /// Feeds one state transition (repeats of the same state are
    /// harmless). Returns the finished record when this ends an episode.
    mutating func handle(_ event: Event, previous: Event, engine: String,
                         retries: Int, now: Date = Date()) -> DropRecord? {
        if episode == nil, event == .reconnecting, previous == .connected {
            episode = Episode(start: now, engine: engine, sleepSince: sleepWindow(at: now))
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
        var record = DropRecord(
            droppedAt: current.start, recoveredAt: now, outcome: outcome,
            retries: current.retries, approvals: current.approvals,
            engine: current.engine, failureReason: nil)
        if let since = current.sleepSince {
            record.sleepSince = since
            record.sleepDrops = 1
        }
        return record
    }
}
