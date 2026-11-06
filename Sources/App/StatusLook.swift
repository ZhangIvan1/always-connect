import AppKit
import SwiftUI

/// Headline and colour per situation for the panel header (UI-DESIGN.md
/// §三). The icon itself is GlobeIcon (globe + state badge, as the
/// user asked); `symbol` remains an SF Symbol fallback.
struct StatusLook {
    var symbol: String
    var color: NSColor
    var headline: String

    static func of(_ state: HelperClient.State, held: Bool, hasCredentials: Bool) -> StatusLook {
        switch state {
        case .connected:
            return StatusLook(symbol: "checkmark.shield.fill", color: .systemGreen, headline: "已连接")
        case .connecting, .authenticating:
            return StatusLook(symbol: "shield.lefthalf.fill", color: .systemYellow, headline: "正在连接…")
        case .awaitingApproval:
            return StatusLook(symbol: "iphone.radiowaves.left.and.right", color: .systemYellow,
                              headline: "请在手机上确认登录")
        case .reconnecting:
            return StatusLook(symbol: "exclamationmark.shield.fill", color: .systemRed,
                              headline: "VPN 断了，正在重连")
        case .disconnected where held:
            return StatusLook(symbol: "exclamationmark.shield.fill", color: .systemRed,
                              headline: "未连接，网络仍处暂停")
        case .disconnected:
            return StatusLook(symbol: "shield.slash", color: .secondaryLabelColor,
                              headline: hasCredentials ? "未连接（直连网络）" : "还没填账号")
        }
    }

    var image: NSImage? {
        NSImage(systemSymbolName: symbol, accessibilityDescription: headline)
            ?? NSImage(systemSymbolName: "shield", accessibilityDescription: headline)
    }
}
