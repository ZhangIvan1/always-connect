import AppKit

/// The App's normal quit (VPN off, network direct, DESIGN.md §21.5),
/// started from the run loop itself (DESIGN.md §37).
///
/// AppDelegate answers a quit with `.terminateLater` and winds the VPN
/// down through main-queue callbacks; AppKit waits for the answer in a
/// nested run loop inside `terminate`. A nested run loop never drains the
/// main dispatch queue while it is itself inside a main-queue block — and
/// OperationQueue.main (distributed-notification observers) runs on that
/// queue too. Calling `terminate` from such a block therefore waited
/// forever: the uninstall from Settings (2026-11-07) hid the icon, stopped
/// the relay and hung until the uninstall script's 60 s kill; the
/// one-click update quit the same way. Measured with a minimal App:
/// terminate from DispatchQueue.main.async or OperationQueue.main hangs,
/// from a timer or a run-loop block it exits.
enum AppQuit {
    static func request() {
        onRunLoop { NSApp.terminate(nil) }
    }

    /// Runs `block` from the main run loop, outside any dispatch block,
    /// in every mode (also the modal one AppKit waits for the reply in).
    static func onRunLoop(_ block: @escaping () -> Void) {
        CFRunLoopPerformBlock(CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue, block)
        CFRunLoopWakeUp(CFRunLoopGetMain())
    }
}
