import AppKit

extension ScanStore.MenuBarState {
    private static let largestShownCount = 99

    var image: NSImage {
        let shield = Self.symbol("shield.fill", pointSize: Metrics.menuBarSymbolSize, weight: .regular)
        let image = NSImage(size: NSSize(width: shield.size.width, height: Metrics.menuBarCanvasHeight), flipped: false) { bounds in
            let glyph = NSRect(x: bounds.midX - shield.size.width / 2, y: bounds.midY - shield.size.height / 2, width: shield.size.width, height: shield.size.height)
            shield.draw(in: glyph)
            let face = NSPoint(x: glyph.midX, y: glyph.midY + Metrics.menuBarSymbolSize * Metrics.emblemFaceRaiseRatio)
            switch self {
            case .ready: break
            case .scanning(let progress): Self.cutRing(around: face, progress: progress)
            case .safe: Self.cutMark("checkmark", at: face)
            case .issues: Self.cutMark("exclamationmark", at: face)
            case .failed: Self.cutMark("xmark", at: face)
            }
            return true
        }
        image.isTemplate = true
        return image
    }

    var title: String {
        guard case .issues(let count) = self else { return "" }
        return count > Self.largestShownCount ? "\(Self.largestShownCount)+" : "\(count)"
    }

    var accessibilityLabel: String {
        switch self {
        case .ready: "Bluehat, not scanned"
        case .scanning: "Bluehat, scanning"
        case .safe: "Bluehat, no issues"
        case .issues(let count): "Bluehat, \(counted(count, "issue"))"
        case .failed: "Bluehat, couldn't load rules"
        }
    }

    private static func symbol(_ name: String, pointSize: CGFloat, weight: NSFont.Weight) -> NSImage {
        NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(.init(pointSize: pointSize, weight: weight)) ?? NSImage()
    }

    private static func cutMark(_ name: String, at center: NSPoint) {
        let mark = symbol(name, pointSize: Metrics.menuBarSymbolSize * Metrics.menuBarMarkRatio, weight: .black)
        mark.draw(in: NSRect(x: center.x - mark.size.width / 2, y: center.y - mark.size.height / 2, width: mark.size.width, height: mark.size.height), from: .zero, operation: .destinationOut, fraction: 1)
    }

    private static func cutRing(around center: NSPoint, progress: Double) {
        let radius = Metrics.menuBarSymbolSize * Metrics.menuBarRingRatio / 2
        NSGraphicsContext.current?.compositingOperation = .destinationOut
        let track = NSBezierPath(ovalIn: NSRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2))
        track.lineWidth = Metrics.menuBarRingLineWidth
        NSColor.black.withAlphaComponent(Palette.menuBarRingTrackOpacity).setStroke()
        track.stroke()
        guard progress > 0 else { return }
        let arc = NSBezierPath()
        arc.appendArc(withCenter: center, radius: radius, startAngle: 90, endAngle: 90 - 360 * progress, clockwise: true)
        arc.lineWidth = Metrics.menuBarRingLineWidth
        arc.lineCapStyle = .round
        NSColor.black.setStroke()
        arc.stroke()
    }
}
