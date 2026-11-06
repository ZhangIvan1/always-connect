import Foundation

/// The own connection's self-check after it comes up (DESIGN.md §26.11).
/// Twice a connected own connection left the Mac without a usable
/// network while the panel said 已连接, and the user had to rescue it by
/// hand (§26.8, §26.9). For the first two minutes of every session the
/// App probes the web through the tunnel; if nothing at all answers for
/// 30 seconds it disconnects (VPN off, direct network back) and says why.
/// After the window the session is trusted to its own drop handling.
///
/// The verdict is a pure value so the rule is tested without a network
/// (core/scripts/ConnectionCheckTest.swift).
struct ConnectionVerdict {
    enum Outcome: Equatable { case keepChecking, healthy, giveUp }

    /// How long a fresh session is watched.
    static let window: TimeInterval = 120
    /// No answer at all for this long: the session is unusable.
    static let silence: TimeInterval = 30

    private var lastAnswer: TimeInterval = 0
    private var failedRounds = 0

    /// `elapsed`: seconds since the session came up.
    mutating func record(answered: Bool, at elapsed: TimeInterval) -> Outcome {
        if answered {
            lastAnswer = elapsed
            failedRounds = 0
        } else {
            failedRounds += 1
            // Several rounds, not one slow probe, and 30 s of silence.
            if failedRounds >= 3, elapsed - lastAnswer >= Self.silence { return .giveUp }
        }
        return elapsed >= Self.window ? .healthy : .keepChecking
    }
}

final class ConnectionCheck {
    /// Any HTTP answer from any of these counts: the point is whether
    /// traffic gets through the tunnel and back, names included, not
    /// whether one site is up. HTTPS only (App Transport Security).
    static let probes = [
        "https://captive.apple.com/hotspot-detect.html",
        "https://www.apple.com/library/test/success.html",
        "https://www.gstatic.com/generate_204",
        "https://www.baidu.com/",
    ].compactMap(URL.init(string:))

    private var verdict = ConnectionVerdict()
    private var started = Date()
    private var generation = 0
    private let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 4
        configuration.timeoutIntervalForResource = 5
        configuration.waitsForConnectivity = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpMaximumConnectionsPerHost = 1
        return URLSession(configuration: configuration)
    }()

    /// Starts watching a session that just came up; `onGiveUp` runs on
    /// the main queue at most once. A new start or stop ends the last.
    func start(onGiveUp: @escaping () -> Void) {
        generation += 1
        verdict = ConnectionVerdict()
        started = Date()
        round(generation, onGiveUp)
    }

    func stop() {
        generation += 1
    }

    private func round(_ current: Int, _ onGiveUp: @escaping () -> Void) {
        guard current == generation else { return }
        let group = DispatchGroup()
        let lock = NSLock()
        var answered = false
        for url in Self.probes {
            group.enter()
            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"
            session.dataTask(with: request) { _, response, _ in
                if response is HTTPURLResponse {
                    lock.lock(); answered = true; lock.unlock()
                }
                group.leave()
            }.resume()
        }
        group.notify(queue: .main) { [weak self] in
            guard let self, current == self.generation else { return }
            let elapsed = Date().timeIntervalSince(self.started)
            switch self.verdict.record(answered: answered, at: elapsed) {
            case .giveUp:
                self.generation += 1
                onGiveUp()
            case .healthy:
                self.generation += 1
            case .keepChecking:
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                    self?.round(current, onGiveUp)
                }
            }
        }
    }
}
