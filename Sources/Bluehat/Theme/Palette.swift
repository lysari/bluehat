import AppKit
import BluehatCore
import SwiftUI

enum Palette {
    static let brand = Color(nsColor: .systemBlue)
    static let onBrand = Color.white
    static let safe = Color(nsColor: .systemGreen)
    static let notice = Color(nsColor: .systemOrange)
    static let failure = Color(nsColor: .systemRed)
    static let idle = Color(nsColor: .systemBlue)
    static let primaryText = Color(nsColor: .labelColor)
    static let secondaryText = Color(nsColor: .secondaryLabelColor)
    static let tertiaryText = Color(nsColor: .tertiaryLabelColor)
    static let cardFill = Color(nsColor: .quaternarySystemFill)
    static let cardStroke = Color(nsColor: .separatorColor)
    static let tintFillOpacity = 0.16
    static let ringTrack = Color(nsColor: .quaternaryLabelColor)
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

    static func severity(_ severity: Severity) -> Color {
        switch severity {
        case .critical, .high: Color(nsColor: .systemRed)
        case .medium: Color(nsColor: .systemOrange)
        case .low: Color(nsColor: .systemTeal)
        case .info: Color(nsColor: .systemBlue)
        }
    }
}
