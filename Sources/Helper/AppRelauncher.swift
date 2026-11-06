import Darwin
import Foundation

/// Brings the App back when it vanished while the network gate holds
/// (crash, force quit; DESIGN.md §25.2). A quit releases first, so a
/// hold outliving the App means it did not leave on purpose.
///
/// The App is reopened in its user's session, as that user, in the
/// background (`open -g`); at most 3 times in 10 minutes, so an App
/// that crashes at launch cannot loop. If it does not come back, the
/// gate's grace period still ends the hold.
final class AppRelauncher {
    struct App {
        var path: String
        var uid: uid_t

        /// The bundle of a connected App, from its pid; nil when it is
        /// not an .app (a test tool) or cannot be read.
        init?(pid: pid_t, uid: uid_t) {
            var buffer = [CChar](repeating: 0, count: 4096)
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
            let exe = String(cString: buffer)
            guard let range = exe.range(of: ".app/Contents/MacOS/", options: .backwards) else {
                return nil
            }
            path = String(exe[..<range.lowerBound]) + ".app"
            self.uid = uid
        }

        init(path: String, uid: uid_t) {
            self.path = path
            self.uid = uid
        }
    }

    private var app: App?
    private var recent: [Date] = []

    func remember(_ app: App) { self.app = app }

    func relaunch() {
        guard let app else { return }
        let now = Date()
        recent = recent.filter { now.timeIntervalSince($0) < 600 }
        guard recent.count < 3 else {
            HelperSession.log("relaunch: limit reached, leaving it to the grace period")
            return
        }
        recent.append(now)
        if let root = TestSeam.root {
            let line = "\(app.uid) \(app.path)\n"
            let log = root.appendingPathComponent("relaunch.log")
            if let handle = try? FileHandle(forWritingTo: log) {
                handle.seekToEndOfFile()
                handle.write(Data(line.utf8))
                try? handle.close()
            } else {
                try? line.write(to: log, atomically: true, encoding: .utf8)
            }
            return
        }
        guard FileManager.default.fileExists(atPath: app.path),
              let pw = getpwuid(app.uid) else { return }
        let user = String(cString: pw.pointee.pw_name)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["asuser", String(app.uid), "/usr/bin/sudo", "-u", user,
                       "/usr/bin/open", "-g", app.path]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            HelperSession.log("relaunch: reopening the App after it vanished while holding")
        } catch {
            HelperSession.log("relaunch: could not start open")
        }
    }
}
