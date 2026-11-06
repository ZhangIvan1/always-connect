import Darwin
import Foundation

/// "Quit leaves nothing of ours running" (DESIGN.md §23.11): the App
/// and the background service each end every process they started
/// before they exit. A child process does not die with its parent on
/// macOS — a Cisco CLI login still waiting for the phone, or an
/// openconnect still logging out, would otherwise be re-parented to
/// launchd and keep running.
enum ProcessSweep {
    /// Every live descendant of `pid` (children first, then theirs).
    static func descendants(of pid: pid_t = getpid()) -> [pid_t] {
        var result: [pid_t] = []
        var frontier = [pid]
        while let parent = frontier.popLast() {
            for child in children(of: parent) where !result.contains(child) {
                result.append(child)
                frontier.append(child)
            }
        }
        return result
    }

    static func children(of pid: pid_t) -> [pid_t] {
        let count = proc_listchildpids(pid, nil, 0)
        guard count > 0 else { return [] }
        // Room for children started between the two calls.
        var pids = [pid_t](repeating: 0, count: Int(count) + 16)
        let filled = pids.withUnsafeMutableBytes { buffer in
            proc_listchildpids(pid, buffer.baseAddress, Int32(buffer.count))
        }
        guard filled > 0 else { return [] }
        return Array(pids.prefix(Int(filled))).filter { $0 > 0 }
    }

    /// SIGTERM to every pid, up to `grace` seconds for them to go, then
    /// SIGKILL to whatever is left. Returns the pids that needed
    /// SIGKILL (for the log). Blocks the calling thread.
    @discardableResult
    static func terminate(_ pids: [pid_t], grace: TimeInterval = 2, signal: Int32 = SIGTERM) -> [pid_t] {
        let targets = pids.filter { $0 > 1 && $0 != getpid() }
        guard !targets.isEmpty else { return [] }
        targets.forEach { kill($0, signal) }
        let deadline = Date().addingTimeInterval(grace)
        var alive = targets
        while !alive.isEmpty, Date() < deadline {
            usleep(100_000)
            alive = alive.filter(isAlive)
        }
        alive.forEach { kill($0, SIGKILL) }
        return alive
    }

    /// End every descendant of this process.
    @discardableResult
    static func terminateDescendants(grace: TimeInterval = 2) -> [pid_t] {
        terminate(descendants(), grace: grace)
    }

    /// Still running (a zombie whose parent has not reaped it yet
    /// counts as gone: it holds no resources but its pid).
    static func isAlive(_ pid: pid_t) -> Bool {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let got = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard got == size else { return kill(pid, 0) == 0 }
        return info.pbi_status != UInt32(SZOMB)
    }

    /// The full command line of a process (argv joined by spaces), or
    /// nil when it cannot be read (gone, or another user's process
    /// without root).
    static func commandLine(of pid: pid_t) -> String? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > 4 else { return nil }
        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var index = 4
        // Executable path, then NUL padding, then argv.
        while index < size, buffer[index] != 0 { index += 1 }
        while index < size, buffer[index] == 0 { index += 1 }
        var args: [String] = []
        var start = index
        while index < size, args.count < Int(argc) {
            if buffer[index] == 0 {
                args.append(String(decoding: buffer[start..<index], as: UTF8.self))
                start = index + 1
            }
            index += 1
        }
        return args.isEmpty ? nil : args.joined(separator: " ")
    }

    /// Every pid on the system whose command line contains `marker`.
    static func pids(commandContaining marker: String) -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let filled = pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count))
        }
        guard filled > 0 else { return [] }
        return pids.prefix(Int(filled)).filter { pid in
            pid > 1 && pid != getpid() && (commandLine(of: pid)?.contains(marker) ?? false)
        }
    }
}
