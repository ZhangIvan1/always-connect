import Foundation

// Drop-history contract (DESIGN.md §21.22): Sources/App/DropHistory.swift
// alone. Episodes from state streams, outcomes, terminal reasons, old
// records, and the text the Diagnostics page and panel show.

var failures = 0
func check(_ ok: Bool, _ name: String) {
    print(ok ? "PASS" : "FAIL", name)
    if !ok { failures += 1 }
}

@main
struct DropHistoryTest {
    static func main() {
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        func at(_ s: TimeInterval) -> Date { t0.addingTimeInterval(s) }

        // 1 recovered after two re-logins, one approval; repeats don't double-count
        var tracker = DropEpisodeTracker()
        check(tracker.handle(.connected, previous: .connecting, engine: "cisco", retries: 0, now: at(0)) == nil,
              "first connect is not a drop")
        _ = tracker.handle(.reconnecting, previous: .connected, engine: "cisco", retries: 0, now: at(10))
        _ = tracker.handle(.reconnecting, previous: .reconnecting, engine: "cisco", retries: 1, now: at(12))
        _ = tracker.handle(.awaitingApproval, previous: .reconnecting, engine: "cisco", retries: 1, now: at(14))
        _ = tracker.handle(.awaitingApproval, previous: .awaitingApproval, engine: "cisco", retries: 1, now: at(15))
        tracker.noteRetries(2)
        let r1 = tracker.handle(.connected, previous: .awaitingApproval, engine: "cisco", retries: 0, now: at(47))
        check(r1?.outcome == .recovered && r1?.retries == 2 && r1?.approvals == 1 && r1?.engine == "cisco",
              "recovered: retries 2, approvals 1 (got \(String(describing: r1)))")
        check(r1?.durationSeconds == 37, "duration from drop to recovery")
        check(r1?.summary == "断了 37 秒，重新登录 2 次后恢复；其中 1 次等你在手机上批准", "summary: \(r1?.summary ?? "")")
        check(r1?.outcomeLabel == "已恢复" && r1?.engineLabel == "经 Cisco", "labels")
        check(tracker.episode == nil, "episode closed")

        // 2 came back by itself
        _ = tracker.handle(.reconnecting, previous: .connected, engine: "own", retries: 0, now: at(100))
        let r2 = tracker.handle(.connected, previous: .reconnecting, engine: "own", retries: 0, now: at(102))
        check(r2?.retries == 0 && r2?.summary == "断了 2 秒，连接自己续上了（没有重新登录）", "self-recovered: \(r2?.summary ?? "")")

        // 3 failed, then the terminal reason refines it
        _ = tracker.handle(.reconnecting, previous: .connected, engine: "own", retries: 0, now: at(200))
        tracker.noteRetries(4)
        let r3 = tracker.handle(.disconnected, previous: .reconnecting, engine: "own", retries: 4, now: at(500))
        check(r3?.outcome == .failed && r3?.retries == 4, "disconnected mid-drop = failed")
        let r3b = r3!.applyingTerminal(2)
        check(r3b.failureReason == "账号或密码被拒绝"
              && r3b.summary == "断了 5 分钟，重新登录 4 次后停止重试：账号或密码被拒绝", "rejected: \(r3b.summary)")
        check(r3b.panelSummary == "断了 5 分钟，重新登录 4 次，没恢复", "panel: \(r3b.panelSummary)")
        check(r3!.applyingTerminal(3).failureReason == "重试次数用完", "attempts exhausted")
        check(r3!.applyingTerminal(1).outcome == .stoppedByUser, "terminal manual stop = the user's")

        // 4 the user disconnects mid-drop
        _ = tracker.handle(.reconnecting, previous: .connected, engine: "cisco", retries: 0, now: at(600))
        tracker.noteUserStop()
        let r4 = tracker.handle(.disconnected, previous: .reconnecting, engine: "cisco", retries: 1, now: at(675))
        check(r4?.outcome == .stoppedByUser && r4!.applyingTerminal(1).outcome == .stoppedByUser,
              "user stop stays the user's")
        check(r4?.summary == "断了 1 分 15 秒，重新登录 1 次时你断开了 VPN", "stopped: \(r4?.summary ?? "")")

        // 5 quit mid-drop; then the late disconnected push records nothing
        _ = tracker.handle(.reconnecting, previous: .connected, engine: "own", retries: 0, now: at(700))
        let r5 = tracker.finishForQuit(now: at(4300))
        check(r5?.outcome == .quit && r5?.summary == "断了 1 小时，重连中退出了 App", "quit: \(r5?.summary ?? "")")
        check(tracker.handle(.disconnected, previous: .reconnecting, engine: "own", retries: 0, now: at(4301)) == nil,
              "no second record after quit")
        check(tracker.finishForQuit() == nil, "quit with no drop records nothing")

        // 6 manual disconnect while connected is not a drop
        tracker.noteUserStop()
        check(tracker.handle(.disconnected, previous: .connected, engine: "own", retries: 0, now: at(5000)) == nil,
              "disconnect while connected is not a drop")

        // 7 records saved before §21.22 still decode and read sensibly
        let old = #"[{"droppedAt":815385760.4,"recoveredAt":815385767.9,"id":"A43E7072-94C8-4420-845B-79A4AA141177"}]"#
        let decoded = try? JSONDecoder().decode([DropRecord].self, from: Data(old.utf8))
        check(decoded?.count == 1 && decoded?.first?.outcome == nil && decoded?.first?.resolvedOutcome == .recovered,
              "old record decodes as recovered")
        check(decoded?.first?.summary == "断了 8 秒后恢复（旧记录，没有重试详情）", "old summary: \(decoded?.first?.summary ?? "")")

        // 8 round trip with the new fields
        let data = try! JSONEncoder().encode([r3b])
        let back = try? JSONDecoder().decode([DropRecord].self, from: data)
        check(back?.first == r3b, "round trip keeps outcome, retries, reason")

        // 9 duration text
        check(DropRecord.durationText(59) == "59 秒" && DropRecord.durationText(60) == "1 分钟"
              && DropRecord.durationText(3725) == "1 小时 2 分", "duration text")

        // 10 drops while the Mac sleeps fold into one record (§41)
        var sleeper = DropEpisodeTracker()
        var history: [DropRecord] = []
        func drop(_ start: TimeInterval, _ end: TimeInterval, retries: Int = 0, approval: Bool = false,
                  failed: Bool = false) {
            _ = sleeper.handle(.reconnecting, previous: .connected, engine: "own", retries: 0, now: at(start))
            if approval {
                _ = sleeper.handle(.awaitingApproval, previous: .reconnecting, engine: "own", retries: retries, now: at(start + 1))
            }
            let r = sleeper.handle(failed ? .disconnected : .connected, previous: approval ? .awaitingApproval : .reconnecting,
                                   engine: "own", retries: retries, now: at(end))
            if let r { history = DropRecord.appending(r, to: history) }
        }
        drop(10_000, 10_001)                       // awake: an ordinary record
        sleeper.noteSleep(now: at(11_000))
        drop(12_000, 12_001)
        drop(13_000, 13_001)
        sleeper.noteSleep(now: at(13_500))         // repeated notice keeps the window
        drop(14_000, 14_002)
        check(history.count == 2 && history[0].sleepSince == nil, "awake drop stays its own record (\(history.count))")
        let night = history.last!
        check(night.sleepSince == at(11_000) && night.sleepDropCount == 3 && night.durationSeconds == 4
              && night.droppedAt == at(12_000) && night.latestDropAt == at(14_000) && night.recoveredAt == at(14_002),
              "three sleep drops fold into one: count, down time, span")
        check(night.summary == "电脑睡眠时断了 3 次，合计 4 秒，每次都自己续上了（没有重新登录）", "sleep summary: \(night.summary)")
        check(night.panelSummary == "睡眠中断了 3 次（合计 4 秒），都已恢复", "sleep panel: \(night.panelSummary)")
        // A drop found just after the lid opens is still the sleep's; later ones are not.
        sleeper.noteWake(now: at(15_000))
        drop(15_030, 15_090, retries: 2, approval: true)
        check(history.count == 2 && history.last!.sleepDropCount == 4 && history.last!.retries == 2
              && history.last!.approvals == 1 && history.last!.durationSeconds == 64,
              "drop within the wake grace folds in with its re-logins and approval")
        check(history.last!.summary == "电脑睡眠时断了 4 次，合计 1 分 4 秒，共重新登录 2 次，都已恢复；其中 1 次等你在手机上批准",
              "sleep summary with re-logins: \(history.last!.summary)")
        drop(15_200, 15_201)
        check(history.count == 3 && history.last!.sleepSince == nil, "after the grace: an ordinary record")
        // The next night is a new sleep record; one that ends badly says so.
        sleeper.noteSleep(now: at(20_000))
        drop(20_100, 20_105)
        check(history.count == 4 && history.last!.summary == "电脑睡眠时断了 5 秒，连接自己续上了（没有重新登录）",
              "single sleep drop: \(history.last!.summary)")
        drop(20_200, 20_500, retries: 3, failed: true)
        let bad = history.last!.applyingTerminal(3)
        check(history.count == 4 && bad.summary == "电脑睡眠时断了 2 次，合计 5 分 5 秒，共重新登录 3 次，最后一次停止重试：重试次数用完",
              "failed sleep record: \(bad.summary)")
        check(bad.panelSummary == "睡眠中断了 2 次（合计 5 分 5 秒），重新登录 3 次，没恢复", "failed sleep panel: \(bad.panelSummary)")
        let sleepData = try! JSONEncoder().encode(history)
        check((try? JSONDecoder().decode([DropRecord].self, from: sleepData)) == history, "sleep records round trip")

        print("FAILURES=\(failures)")
        exit(failures == 0 ? 0 : 1)
    }
}
