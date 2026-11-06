import AppKit
import SwiftUI

// The approval reminder's window and bubble (DESIGN.md §29); the
// controller is ApprovalPrompt. AppKit/SwiftUI only, so offscreen
// renders compile it with ApprovalPromptTracker.swift alone.

enum ApprovalBubbleMetrics {
    static let width: CGFloat = 290
    static let bodyHeight: CGFloat = 50
    static let arrowHeight: CGFloat = 7
    /// Room for the shadow inside the borderless window.
    static let sidePad: CGFloat = 20
    static let bottomPad: CGFloat = 24
    /// The glow also spreads upward round the arrow; the window reaches
    /// this far over the menu bar so it is not cut flat.
    static let topPad: CGFloat = 10
    static var windowWidth: CGFloat { width + sidePad * 2 }
    static var windowHeight: CGFloat { topPad + arrowHeight + bodyHeight + bottomPad }
}

/// Borderless, non-activating, never key: clicks work, focus stays
/// where the user is typing.
final class ApprovalCardPanel: NSPanel {
    init() {
        super.init(contentRect: NSRect(x: 0, y: 0, width: ApprovalBubbleMetrics.windowWidth,
                                       height: ApprovalBubbleMetrics.windowHeight),
                   styleMask: [.borderless, .nonactivatingPanel],
                   backing: .buffered, defer: true)
        isFloatingPanel = true
        level = .statusBar
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        backgroundColor = .clear
        isOpaque = false
        hasShadow = false  // drawn by the bubble, which has an arrow
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        animationBehavior = .none
    }

    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

/// The first click on an inactive window acts at once.
final class FirstClickHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

final class ApprovalCardModel: ObservableObject {
    @Published var card: ApprovalPromptTracker.Card?
    /// Arrow position from the bubble's left edge; nil = no arrow.
    @Published var arrowX: CGFloat?
}

struct ApprovalCardView: View {
    @ObservedObject var model: ApprovalCardModel
    var onHide: () -> Void
    var onOpen: () -> Void

    var body: some View {
        Group {
            if let card = model.card {
                ApprovalBubble(card: card, arrowX: model.arrowX, onHide: onHide, onOpen: onOpen)
            } else {
                Color.clear.frame(width: ApprovalBubbleMetrics.width,
                                  height: ApprovalBubbleMetrics.bodyHeight + ApprovalBubbleMetrics.arrowHeight)
            }
        }
        .padding(EdgeInsets(top: ApprovalBubbleMetrics.topPad, leading: ApprovalBubbleMetrics.sidePad,
                            bottom: ApprovalBubbleMetrics.bottomPad,
                            trailing: ApprovalBubbleMetrics.sidePad))
    }
}

/// Popover-like bubble: arrow on top pointing at the menu-bar icon.
/// Black and white only (user, 2026-11-06: no colour schemes, no drawn
/// border): system glass with a soft glow round its edge — white in
/// dark mode, a faint dark one in light mode — that breathes while
/// waiting. The glow is what makes it stand out.
struct ApprovalBubble: View {
    var card: ApprovalPromptTracker.Card
    var arrowX: CGFloat?
    var onHide: () -> Void = {}
    var onOpen: () -> Void = {}
    /// Fixed clock for offscreen renders; nil = live.
    var now: Date?
    /// Offscreen renders: draw the glow at its brightest.
    var glowFrozen = false
    @Environment(\.colorScheme) private var scheme

    /// The icon is the one coloured thing (user, 2026-11-06): orange
    /// while the phone is asked, blue while connecting, green when done.
    static func iconColor(_ stage: ApprovalPromptTracker.Stage) -> Color {
        switch stage {
        case .waiting: return .orange
        case .establishing: return .blue
        case .connected: return .green
        }
    }

    var body: some View {
        let shape = CalloutShape(arrowX: arrowX, arrowHeight: ApprovalBubbleMetrics.arrowHeight)
        let ink: Color = scheme == .dark ? .white : .black
        HStack(spacing: 10) {
            ApprovalCardIcon(stage: card.stage, tint: Self.iconColor(card.stage))
            VStack(alignment: .leading, spacing: 1) {
                Text(card.title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(ink)
                    .lineLimit(1)
                Group {
                    if let now {
                        Text(card.subtitle(now: now))
                    } else {
                        TimelineView(.periodic(from: card.since, by: 1)) { context in
                            Text(card.subtitle(now: context.date))
                        }
                    }
                }
                .font(.system(size: 11.5))
                .foregroundStyle(ink.opacity(0.65))
                .monospacedDigit()
                .lineLimit(1)
            }
            Spacer(minLength: 6)
            if card.stage != .connected {
                Button(action: onHide) {
                    Image(systemName: "xmark")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(ink.opacity(0.7))
                        .frame(width: 20, height: 20)
                        .background(Circle().fill(ink.opacity(0.1)))
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help("先隐藏（下次请求时再出现）")
            }
        }
        .padding(.horizontal, 11)
        .frame(width: ApprovalBubbleMetrics.width, height: ApprovalBubbleMetrics.bodyHeight)
        .padding(.top, ApprovalBubbleMetrics.arrowHeight)
        .background(shape.fill(.regularMaterial))
        .background(ApprovalBubbleEdge(shape: shape, ink: ink, strength: scheme == .dark ? 1 : 0.55,
                                       breathing: card.stage == .waiting, frozen: glowFrozen))
        .contentShape(shape)
        .onTapGesture(perform: onOpen)
        .shadow(color: .black.opacity(0.2), radius: 8, y: 3)
    }
}

/// A soft glow in the ink colour outside the edge, no hard outline (user,
/// 2026-11-06: the drawn border looked unnatural); it breathes while
/// waiting (still when "reduce motion" is on).
private struct ApprovalBubbleEdge: View {
    var shape: CalloutShape
    var ink: Color
    /// A dark glow on a light screen reads as a smudge: weaker there.
    var strength: Double
    var breathing: Bool
    var frozen: Bool
    @State private var bright = false

    var body: some View {
        let on = frozen || bright || !breathing
        // Blurred copy of the shape with the shape itself cut out: the
        // glow only spreads outward from the edge, never over the glass
        // (user, 2026-11-06).
        shape.fill(ink)
            .blur(radius: on ? 10 : 7)
            .opacity((on ? 1 : 0.5) * strength)
            .mask(
                Rectangle().padding(-40)
                    .overlay(shape.fill(Color.black).blendMode(.destinationOut))
                    .compositingGroup())
            .allowsHitTesting(false)
        .onAppear {
            guard breathing, !frozen,
                  !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion else { return }
            withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
                bright = true
            }
        }
    }
}

/// Rounded rectangle with a small triangle on its top edge at arrowX,
/// traced as one outline so the edge line runs round the arrow too.
struct CalloutShape: Shape {
    var arrowX: CGFloat?
    var arrowHeight: CGFloat
    var radius: CGFloat = 12

    func path(in rect: CGRect) -> Path {
        let body = CGRect(x: rect.minX, y: rect.minY + arrowHeight,
                          width: rect.width, height: rect.height - arrowHeight)
        let r = radius
        var p = Path()
        p.move(to: CGPoint(x: body.minX + r, y: body.minY))
        if let arrowX {
            let half = arrowHeight * 1.3
            let x = min(max(rect.minX + arrowX, body.minX + r + half), body.maxX - r - half)
            p.addLine(to: CGPoint(x: x - half, y: body.minY))
            p.addQuadCurve(to: CGPoint(x: x, y: rect.minY),
                           control: CGPoint(x: x - half * 0.35, y: body.minY))
            p.addQuadCurve(to: CGPoint(x: x + half, y: body.minY),
                           control: CGPoint(x: x + half * 0.35, y: body.minY))
        }
        p.addLine(to: CGPoint(x: body.maxX - r, y: body.minY))
        p.addArc(center: CGPoint(x: body.maxX - r, y: body.minY + r), radius: r,
                 startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
        p.addLine(to: CGPoint(x: body.maxX, y: body.maxY - r))
        p.addArc(center: CGPoint(x: body.maxX - r, y: body.maxY - r), radius: r,
                 startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
        p.addLine(to: CGPoint(x: body.minX + r, y: body.maxY))
        p.addArc(center: CGPoint(x: body.minX + r, y: body.maxY - r), radius: r,
                 startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
        p.addLine(to: CGPoint(x: body.minX, y: body.minY + r))
        p.addArc(center: CGPoint(x: body.minX + r, y: body.minY + r), radius: r,
                 startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        p.closeSubpath()
        return p
    }
}

/// Phone with a ring rippling out while waiting; dots, then a check.
struct ApprovalCardIcon: View {
    var stage: ApprovalPromptTracker.Stage
    var tint: Color

    var body: some View {
        ZStack {
            Circle().fill(tint.opacity(0.18))
            if stage == .waiting, !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
                RippleRing(tint: tint)
            }
            switch stage {
            case .waiting:
                Image(systemName: "iphone.radiowaves.left.and.right")
                    .font(.system(size: 14, weight: .semibold))
            case .establishing:
                Image(systemName: "ellipsis")
                    .font(.system(size: 14, weight: .heavy))
            case .connected:
                Image(systemName: "checkmark")
                    .font(.system(size: 14, weight: .heavy))
            }
        }
        .foregroundStyle(tint)
        .frame(width: 32, height: 32)
    }
}

/// One ring growing out of the icon and fading, over and over. Its own
/// view so every new wait starts the animation afresh.
private struct RippleRing: View {
    var tint: Color
    @State private var out = false

    var body: some View {
        Circle()
            .stroke(tint.opacity(0.55), lineWidth: 1.3)
            .scaleEffect(out ? 1.4 : 1)
            .opacity(out ? 0 : 1)
            .onAppear {
                withAnimation(.easeOut(duration: 1.6).repeatForever(autoreverses: false)) {
                    out = true
                }
            }
    }
}
