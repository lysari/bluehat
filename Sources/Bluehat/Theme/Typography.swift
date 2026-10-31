import AppKit
import SwiftUI

enum Typography {
    static let appTitle = Font.system(size: 14, weight: .semibold)
    static let statusTitle = Font.system(size: 15, weight: .semibold)
    static let welcomeTitle = Font.system(size: 22, weight: .bold)
    static let featureSymbol = Font.system(size: 18)
    static let sectionTitle = Font.system(size: 11, weight: .semibold)
    static let body = Font.system(size: 13)
    static let rowTitle = Font.system(size: 13, weight: .medium)
    static let caption = Font.system(size: 11)
    static let captionEmphasis = Font.system(size: 11, weight: .semibold)
    static let detail = Font.system(size: 11).monospaced()
    static let count = Font.system(size: 11, weight: .semibold).monospacedDigit()
    static let headerAction = Font.system(size: 15)
    @MainActor static let menuBarCount = NSFont.monospacedDigitSystemFont(ofSize: NSFont.menuBarFont(ofSize: 0).pointSize, weight: .regular)
}
