import Foundation

/// One login owns a daemon lifetime, including crash-recovery grace. The
/// daemon exits after that login has quit and its session is idle, allowing
/// the next user to acquire a fresh daemon. A settings child has the same uid.
final class ClientUIDPolicy {
    private let lock = NSLock()
    private var owner: uid_t?

    func accept(_ uid: uid_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let owner { return owner == uid }
        owner = uid
        return true
    }
}
