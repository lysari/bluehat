import AppKit
import BluehatCore
import SwiftUI

enum Palette {
    static let brand = Color(nsColor: .systemBlue)
    static let onBrand = Color.white
    static let scanPillFill = Color(.sRGB, red: 0, green: 0x71 / 255, blue: 0xE3 / 255)
    static let scanPillDeepFill = Color(.sRGB, red: 0x5B / 255, green: 0x45 / 255, blue: 0xD6 / 255)
    static let scanPillCancelFill = Color(.sRGB, red: 0xDB / 255, green: 0x2A / 255, blue: 0x2E / 255)
    static let scanPillDisabledFill = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? NSColor(srgbRed: 0x3F / 255, green: 0x41 / 255, blue: 0x44 / 255, alpha: 1) : NSColor(srgbRed: 0xD8 / 255, green: 0xDA / 255, blue: 0xDD / 255, alpha: 1)
    })
    static let scanPillDisabledText = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? NSColor(srgbRed: 0xB0 / 255, green: 0xB2 / 255, blue: 0xB5 / 255, alpha: 1) : NSColor(srgbRed: 0x5C / 255, green: 0x5E / 255, blue: 0x62 / 255, alpha: 1)
    })
    static let scanPillFeedback = Color.black
    static let scanPillHoverOpacity = 0.12
    static let scanPillPressedOpacity = 0.24
    static let scanPillDividerOpacity = 0.45
    static let safe = Color(nsColor: .systemGreen)
    static let notice = Color(nsColor: .systemOrange)
    static let failure = Color(nsColor: .systemRed)
    static let idle = Color(nsColor: .systemBlue)
    static let secondaryText = Color(nsColor: .secondaryLabelColor)
    static let tertiaryText = Color(nsColor: .tertiaryLabelColor)
    static let panelMaterial = NSVisualEffectView.Material.menu
    static let cardFill = Color(nsColor: .quaternarySystemFill)
    static let cardStroke = Color(nsColor: .separatorColor)
    static let tintFillOpacity = 0.16
    static let ringTrack = Color(nsColor: .quaternaryLabelColor)
    static let emptyArea = Color(nsColor: .tertiaryLabelColor)
    static let ringGlowOpacity = 0.22
    static let sweepOpacity = 0.32
    static let heroWashOpacity = 0.10
    static let segmentGlowOpacity = 0.45
    static let emblemSideShade = 0.38
    static let emblemFaceLift = 0.22
    static let emblemBevelOpacity = 0.55
    static let emblemGlossOpacity = 0.38
    static let emblemGroundShadowOpacity = 0.35
    static let emblemGlyphShadowOpacity = 0.3
    static let menuBarRingTrackOpacity = 0.45

    static func severity(_ severity: Severity) -> Color {
        switch severity {
        case .critical, .high: Color(nsColor: .systemRed)
        case .medium: Color(nsColor: .systemOrange)
        case .low: Color(nsColor: .systemTeal)
        case .info: Color(nsColor: .systemBlue)
        }
    }
}
