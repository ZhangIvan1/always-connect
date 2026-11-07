import AppKit

// AppQuit (DESIGN.md §37): a quit answered with .terminateLater and wound
// down through main-queue callbacks must finish whatever context asked
// for it. Run by scripts/quit-test.sh as `quit-test <caller>`; exits 0 when
// the App quit, the script kills it when it hangs.
final class Delegate: NSObject, NSApplicationDelegate {
    let caller = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "gcd"

    func applicationDidFinishLaunching(_ notification: Notification) {
        switch caller {
        case "gcd":      // the update's and the uninstaller's completion blocks
            DispatchQueue.main.async { AppQuit.request() }
        case "opqueue":  // a distributed-notification observer on .main (Settings → App)
            OperationQueue.main.addOperation { AppQuit.request() }
        case "background":
            DispatchQueue.global().async { AppQuit.request() }
        case "plain-gcd": // the old call, kept to show the harness detects the hang
            DispatchQueue.main.async { NSApp.terminate(nil) }
        default:
            AppQuit.request()
        }
    }

    // As AppDelegate: the wind-down answers through the main queue.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            AppQuit.onRunLoop { NSApp.reply(toApplicationShouldTerminate: true) }
        }
        return .terminateLater
    }
}

@main
struct QuitTest {
    static let delegate = Delegate()
    static func main() {
        NSApplication.shared.delegate = delegate
        NSApp.setActivationPolicy(.prohibited)
        NSApp.run()
    }
}
