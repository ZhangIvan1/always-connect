// Draws the App icon (Sources/App/AppIcon.icns) with GlobeGeometry, the
// same globe as the menu-bar icon (option A3: frosted glass sphere, no
// tile). Usage:
//   swiftc -O -parse-as-library Sources/App/GlobeGeometry.swift scripts/make-app-icon.swift -o /tmp/make-app-icon
//   /tmp/make-app-icon /tmp/AppIcon.iconset && iconutil -c icns /tmp/AppIcon.iconset -o Sources/App/AppIcon.icns
import AppKit

func render(size: CGFloat) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current!.cgContext.scaleBy(x: size / 1024, y: size / 1024)
    GlobeGeometry.drawAppIcon()
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

@main
struct MakeAppIcon {
    static func main() {
        let out = URL(fileURLWithPath: CommandLine.arguments[1])
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        for base in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
                try! render(size: CGFloat(base * scale)).representation(using: .png, properties: [:])!
                    .write(to: out.appendingPathComponent(name))
            }
        }
    }
}
