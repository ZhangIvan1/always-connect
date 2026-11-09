import Foundation

/// Lifetime of one system disconnect, independent of its XPC reply.
/// A deadline only requests verification; it never authorizes a connection.
/// The service's serial status/held replies fence earlier disconnect messages.
final class OnDemandDisconnect {
    typealias Token = UInt64
    var stop: (Token, @escaping () -> Void, @escaping () -> Void) -> Void = { _, _, _ in }
    var verifyIdle: (@escaping (Bool) -> Void) -> Void = { done in done(false) }
    var settled: () -> Void = {}
    var needsAttention: () -> Void = {}
    var schedule: (@escaping () -> Void) -> Void = { action in
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: action)
    }

    private(set) var waiting = false
    private var generation: Token = 0
    private var verification: Token = 0
    private var localStopped = false
    private var checking = false
    private var suspended = false

    func isCurrent(_ token: Token) -> Bool {
        waiting && generation == token
    }

    func begin() {
        guard !waiting else { return }
        generation &+= 1
        let token = generation
        waiting = true
        localStopped = false
        stop(
            token,
            { [weak self] in
                guard let self, self.isCurrent(token) else { return }
                self.localStopped = true
                self.reconcile()
            },
            { [weak self] in
                guard let self, self.isCurrent(token) else { return }
                self.reconcile()
            })
        schedule { [weak self] in
            guard let self, self.isCurrent(token) else { return }
            self.needsAttention()
            self.reconcile()
        }
    }

    /// Lost transports and explicit recovery invalidate in-flight observations,
    /// not the local Cisco stop: its completion must precede any new session.
    func transportLost() {
        verification &+= 1
        checking = false
    }

    func suspend() {
        suspended = true
        transportLost()
    }

    func recover() {
        suspended = false
        recheck()
    }

    /// A newer event supersedes even an observation whose reply was lost.
    func recheck() {
        transportLost()
        reconcile()
    }

    /// Retry only on a real event or explicit user action; no polling.
    func reconcile() {
        guard waiting, localStopped, !checking, !suspended else { return }
        checking = true
        verification &+= 1
        let observation = verification
        let token = generation
        verifyIdle { [weak self] idle in
            guard let self, self.isCurrent(token), self.verification == observation else { return }
            self.checking = false
            guard idle, !self.suspended else { return }
            self.waiting = false
            self.verification &+= 1
            self.settled()
        }
    }
}
