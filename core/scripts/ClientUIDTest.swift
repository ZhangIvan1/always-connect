import Foundation

@main struct ClientUIDTest {
    static func main() {
        let policy = ClientUIDPolicy()
        precondition(policy.accept(501))
        precondition(policy.accept(501)) // App and its settings child/relaunch
        precondition(!policy.accept(502))
        precondition(!policy.accept(0))
        precondition(policy.accept(501)) // refusing another uid changes nothing
        let simultaneous = ClientUIDPolicy()
        let lock = NSLock()
        var accepted = Set<uid_t>()
        DispatchQueue.concurrentPerform(iterations: 100) { index in
            let uid = uid_t(501 + index % 2)
            if simultaneous.accept(uid) {
                lock.lock(); accepted.insert(uid); lock.unlock()
            }
        }
        precondition(accepted.count == 1)
        // Once the daemon exits, a new daemon has no previous owner.
        precondition(ClientUIDPolicy().accept(502))
        print("PASS uid ownership, same-user relaunch, competing users, new daemon")
    }
}
