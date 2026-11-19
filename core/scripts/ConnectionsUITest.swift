import AppKit
import SwiftUI

private final class Fixture: ObservableObject {
    @Published var rows = (1...180).map(Fixture.row)

    static func row(_ index: Int) -> ConnectionRow {
        ConnectionRow(process: "Example Browser", pid: 1, proto: "udp",
                      remote: "192.0.2.\(index)", port: index.isMultiple(of: 2) ? 443 : 3478,
                      host: "site-\(index).example.com", via: "vpn", interface: "utun0", reason: "VPN")
    }
}

private struct FixtureSettings: View {
    @ObservedObject var fixture: Fixture

    var body: some View {
        SettingsView(connectionPreview: fixture.rows)
    }
}

@main
struct ConnectionsUITest {
    @MainActor static func main() {
        _ = NSApplication.shared
        CiscoEngine.cliPath = "/nonexistent/connections-ui-test/vpn"
        let fixture = Fixture()
        let controller = NSHostingController(rootView: FixtureSettings(fixture: fixture))
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: SettingsWindow.size),
                              styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentViewController = controller
        window.setContentSize(SettingsWindow.size)
        let root = controller.view

        func settle() {
            root.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.07))
            root.layoutSubtreeIfNeeded()
        }

        settle()
        guard let table = findTable(in: root), let scroll = table.enclosingScrollView else {
            fail("the connection tab did not create a native scrollable table")
        }
        check(table.numberOfRows == 180, "180 sample connections reach the table")
        check(table.tableColumns.count == 6, "all six columns exist")
        let protocolFont = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        for port in [443, 3478] {
            let label = ConnectionsPage.protocolName("udp", port)
            let width = (label as NSString).size(withAttributes: [.font: protocolFont]).width
            check(table.tableColumns[2].width >= width, "the protocol column fits \(label)")
        }

        func visible(_ row: Int) -> Bool {
            let rowBounds = table.rect(ofRow: row)
            let viewport = scroll.documentVisibleRect
            return rowBounds.minY >= viewport.minY && rowBounds.maxY <= viewport.maxY
        }

        func wheel(_ lines: Int32) {
            let clip = scroll.contentView
            let point = clip.convert(NSPoint(x: clip.bounds.midX, y: clip.bounds.midY), to: root)
            guard let hit = root.hitTest(root.convert(point, to: root.superview)),
                  hit === scroll || hit.isDescendant(of: scroll),
                  let raw = CGEvent(scrollWheelEvent2Source: nil, units: .line,
                                    wheelCount: 1, wheel1: lines, wheel2: 0, wheel3: 0),
                  let event = NSEvent(cgEvent: raw) else {
                fail("wheel hit testing did not reach the table")
            }
            hit.scrollWheel(with: event)
            settle()
        }

        let defaultViewport = scroll.contentView.bounds.size
        check(table.rect(ofColumn: 5).maxX <= scroll.documentVisibleRect.maxX,
              "all columns fit at the default window size")
        for size in [SettingsWindow.size, SettingsWindow.minimumSize] {
            window.setContentSize(size)
            settle()
            check(visible(0) && !visible(table.numberOfRows - 1), "the list starts at the top and overflows")
            wheel(-16)
            check(!visible(0), "scrolling down moves the table, not the settings page")
            let offset = scroll.contentView.bounds.minY
            for _ in 0..<3 {
                let count = fixture.rows.count
                fixture.rows.append(Fixture.row(count + 1))
                let deadline = Date(timeIntervalSinceNow: 2)
                repeat { settle() } while table.numberOfRows != count + 1 && Date() < deadline
                check(table.numberOfRows == count + 1, "a new sample reaches the same table")
                check(abs(scroll.contentView.bounds.minY - offset) <= 1, "refresh keeps the scroll position")
            }
            for _ in 0..<40 where !visible(table.numberOfRows - 1) { wheel(-32) }
            check(visible(table.numberOfRows - 1), "scrolling reaches the final row")
            for _ in 0..<40 where !visible(0) { wheel(32) }
            check(visible(0), "scrolling back up reaches the first row")
        }
        check(scroll.contentView.bounds.width < defaultViewport.width &&
              scroll.contentView.bounds.height < defaultViewport.height, "the table resizes with the settings window")
        check(scroll.enclosingScrollView == nil, "no enclosing form scrolls around the table")
        print("PASS connection table scrolls both ways, tracks resizing and keeps position across row updates")
    }

    private static func findTable(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        return view.subviews.lazy.compactMap(findTable).first
    }

    private static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}
