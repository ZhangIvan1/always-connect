import SwiftUI

/// The one switch used everywhere in the App (DESIGN.md §21.14).
///
/// The system switch draws itself grey whenever its window is not the
/// active one, so in the menu-bar panel an ON switch looked OFF (user
/// report, twice). This draws the state itself: accent-coloured track
/// when on, grey when off, the same in active and inactive windows. A
/// hidden label (labelsHidden) is honoured; otherwise label left,
/// switch right, as in System Settings rows.
struct AlwaysSwitchStyle: ToggleStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 8) {
            configuration.label
            Spacer(minLength: 8)
            ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                Capsule()
                    .fill(configuration.isOn ? Color.accentColor : Color.secondary.opacity(0.32))
                Circle()
                    .fill(Color.white)
                    .shadow(color: .black.opacity(0.25), radius: 1, y: 0.5)
                    .padding(2)
            }
            .frame(width: 34, height: 20)
            .opacity(isEnabled ? 1 : 0.45)
            .animation(.easeOut(duration: 0.15), value: configuration.isOn)
            .contentShape(Capsule())
            .onTapGesture { configuration.isOn.toggle() }
            .accessibilityElement()
            .accessibilityLabel("开关")
            .accessibilityValue(configuration.isOn ? "开" : "关")
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { configuration.isOn.toggle() }
        }
    }
}

extension ToggleStyle where Self == AlwaysSwitchStyle {
    static var always: AlwaysSwitchStyle { AlwaysSwitchStyle() }
}
