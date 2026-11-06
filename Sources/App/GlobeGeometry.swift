import AppKit

/// The one globe shape behind both the App icon and the menu-bar icon
/// (UI-DESIGN.md §App 图标): a round outline around a tilted equator and
/// meridian, the meridian green while connected; a frosted glass tile in
/// the App icon. Original drawing (2026-11-06, DESIGN.md §34.4); it no
/// longer follows any vendor's artwork. Drawn in a 1024-unit
/// square; callers scale the context. No App dependencies, so
/// scripts/make-app-icon.swift compiles it too.
enum GlobeGeometry {
    static let navy = NSColor(calibratedRed: 0.07, green: 0.16, blue: 0.30, alpha: 1)
    static let green = NSColor(calibratedRed: 0.22, green: 0.78, blue: 0.42, alpha: 1)

    /// `width` scales every stroke (the menu bar needs heavier lines).
    /// A plain latitude/longitude globe tilted 24° (DESIGN.md §34.4): an
    /// equator and one meridian, both ellipses that meet the ring on its
    /// centre line. They are drawn first so the ring covers every join
    /// and the lines tuck under it smoothly (user, 2026-11-06).
    static func drawGlobe(center c: NSPoint, radius r: CGFloat, width: CGFloat,
                          outline: NSColor, sweep: NSColor, arc: NSColor) {
        NSGraphicsContext.saveGraphicsState()
        let tilt = NSAffineTransform()
        tilt.translateX(by: c.x, yBy: c.y)
        tilt.rotate(byDegrees: -24)
        tilt.concat()
        sweep.setStroke()
        let equator = NSBezierPath(ovalIn: NSRect(x: -r, y: -r * 0.36, width: 2 * r, height: 0.72 * r))
        equator.lineWidth = 34 * width
        equator.stroke()
        arc.setStroke()
        let meridian = NSBezierPath(ovalIn: NSRect(x: -r * 0.46, y: -r, width: 0.92 * r, height: 2 * r))
        meridian.lineWidth = 38 * width
        meridian.stroke()
        NSGraphicsContext.restoreGraphicsState()

        outline.setStroke()
        let ring = NSBezierPath(ovalIn: NSRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r))
        ring.lineWidth = 46 * width
        ring.stroke()
    }

    /// A padlock whose body spans 6.2 `unit`s, its box's lower left at `origin`.
    static func drawLock(origin o: NSPoint, unit u: CGFloat, color: NSColor) {
        color.setFill()
        color.setStroke()
        NSBezierPath(roundedRect: NSRect(x: o.x + 0.9 * u, y: o.y + 0.6 * u, width: 6.2 * u, height: 4.5 * u),
                     xRadius: 1 * u, yRadius: 1 * u).fill()
        let shackle = NSBezierPath()
        shackle.appendArc(withCenter: NSPoint(x: o.x + 4 * u, y: o.y + 5 * u), radius: 1.9 * u,
                          startAngle: 0, endAngle: 180)
        shackle.lineWidth = 1.2 * u
        shackle.stroke()
    }

    /// The App icon (option A3). Full bleed on purpose: macOS 26 puts
    /// any icon that does not fill its square into a grey tile and
    /// shrinks it (seen 2026-11-05), so the frosted glass is the whole
    /// tile and the system's own mask gives the rounded corners.
    static func drawAppIcon() {
        let full = NSRect(x: 0, y: 0, width: 1024, height: 1024)
        NSGradient(colors: [NSColor(calibratedRed: 0.97, green: 0.99, blue: 1.0, alpha: 1),
                            NSColor(calibratedRed: 0.80, green: 0.89, blue: 0.97, alpha: 1)])!
            .draw(in: full, angle: -90)
        // Glass: a soft light from the upper left, a faint cool depth below.
        NSGradient(colors: [NSColor.white.withAlphaComponent(0.9), NSColor.white.withAlphaComponent(0)])!
            .draw(fromCenter: NSPoint(x: 330, y: 760), radius: 0, toCenter: NSPoint(x: 330, y: 760), radius: 620,
                  options: [])
        NSGradient(colors: [NSColor(calibratedRed: 0.55, green: 0.72, blue: 0.92, alpha: 0),
                            NSColor(calibratedRed: 0.55, green: 0.72, blue: 0.92, alpha: 0.35)])!
            .draw(fromCenter: NSPoint(x: 512, y: 512), radius: 380, toCenter: NSPoint(x: 512, y: 512), radius: 760,
                  options: [])
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = navy.withAlphaComponent(0.25)
        shadow.shadowOffset = NSSize(width: 0, height: -14)
        shadow.shadowBlurRadius = 24
        shadow.set()
        drawGlobe(center: NSPoint(x: 500, y: 520), radius: 405, width: 1.45,
                  outline: navy, sweep: navy.withAlphaComponent(0.85), arc: green)
        NSGraphicsContext.restoreGraphicsState()
        let u: CGFloat = 32
        let o = NSPoint(x: 690, y: 70)
        NSColor.white.setFill()
        NSBezierPath(ovalIn: NSRect(x: o.x, y: o.y, width: 8 * u, height: 8 * u)
            .insetBy(dx: -1.2 * u, dy: -1.2 * u)).fill()
        drawLock(origin: o, unit: u, color: green)
    }
}
