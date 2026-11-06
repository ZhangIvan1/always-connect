import AppKit

/// The status icon: the same globe as the App icon (GlobeGeometry, user's
/// choice 2026-11-05), with our states as a badge
/// in the lower right: green padlock = connected, yellow dots =
/// connecting / waiting for approval, red "!" = dropped and blocked (or
/// still held), no badge and a dimmed globe = off. Drawn in code at any
/// size, so the menu bar (18 pt) and the panel header share one look;
/// the globe uses label colours, which resolve per appearance at draw
/// time (light/dark menu bar).
enum GlobeIcon {
    enum Badge { case none, lock, busy, alert }

    static func badge(for state: HelperClient.State, held: Bool) -> Badge {
        switch state {
        case .connected: return .lock
        case .connecting, .authenticating, .awaitingApproval: return .busy
        case .reconnecting: return .alert
        case .disconnected: return held ? .alert : .none
        }
    }

    static func image(_ badge: Badge, size: CGFloat = 18) -> NSImage {
        let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            draw(badge, in: rect)
            return true
        }
        image.isTemplate = false
        return image
    }

    /// GlobeGeometry's globe on a 1024-unit grid, label-coloured with
    /// the arc green while connected; the badge cut out of the globe in
    /// the lower right.
    private static func draw(_ badge: Badge, in rect: NSRect) {
        guard let cg = NSGraphicsContext.current?.cgContext else { return }
        cg.saveGState()
        cg.translateBy(x: rect.minX, y: rect.minY)
        cg.scaleBy(x: rect.width / 1024, y: rect.height / 1024)
        defer { cg.restoreGState() }
        // Off: half strength, drawn as one layer so crossings do not darken.
        if badge == .none { cg.setAlpha(0.5) }
        cg.beginTransparencyLayer(auxiliaryInfo: nil)
        let ink = NSColor.labelColor
        GlobeGeometry.drawGlobe(center: NSPoint(x: 450, y: 560), radius: 390, width: 1.7,
                                outline: ink, sweep: ink.withAlphaComponent(0.85),
                                arc: badge == .lock ? GlobeGeometry.green : ink)
        if badge != .none {
            NSGraphicsContext.current?.compositingOperation = .clear
            NSBezierPath(ovalIn: NSRect(x: 560, y: -40, width: 510, height: 510)).fill()
            NSGraphicsContext.current?.compositingOperation = .sourceOver
        }
        cg.endTransparencyLayer()

        let b = NSRect(x: 600, y: 20, width: 400, height: 400)
        switch badge {
        case .lock:
            GlobeGeometry.drawLock(origin: NSPoint(x: 610, y: 10), unit: 52, color: GlobeGeometry.green)
        case .busy:
            NSColor.systemYellow.setFill()
            NSBezierPath(ovalIn: b).fill()
            NSColor.black.withAlphaComponent(0.7).setFill()
            for i in 0..<3 {
                NSBezierPath(ovalIn: NSRect(x: b.minX + 80 + CGFloat(i) * 95, y: b.midY - 30,
                                            width: 60, height: 60)).fill()
            }
        case .alert:
            NSColor.systemRed.setFill()
            NSBezierPath(ovalIn: b).fill()
            NSColor.white.setFill()
            NSBezierPath(roundedRect: NSRect(x: b.midX - 32, y: b.minY + 150, width: 64, height: 190),
                         xRadius: 30, yRadius: 30).fill()
            NSBezierPath(ovalIn: NSRect(x: b.midX - 36, y: b.minY + 50, width: 72, height: 72)).fill()
        case .none:
            break
        }
    }
}
