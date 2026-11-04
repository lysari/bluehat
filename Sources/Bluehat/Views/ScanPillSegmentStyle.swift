import SwiftUI

struct ScanPillSegmentStyle: ButtonStyle {
    let edge: HorizontalEdge
    let fill: Color
    var fitsLabel = false

    func makeBody(configuration: Configuration) -> some View {
        ScanPillSegment(edge: edge, fill: fill, fitsLabel: fitsLabel, isPressed: configuration.isPressed, label: configuration.label)
    }
}

private struct ScanPillSegment<Label: View>: View {
    let edge: HorizontalEdge
    let fill: Color
    let fitsLabel: Bool
    let isPressed: Bool
    let label: Label
    @State private var isHovered = false
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.isFocused) private var isFocused
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var shape: UnevenRoundedRectangle {
        let leadingRadius = edge == .leading ? Metrics.scanPillRadius : 0
        let trailingRadius = edge == .trailing ? Metrics.scanPillRadius : 0
        return UnevenRoundedRectangle(topLeadingRadius: leadingRadius, bottomLeadingRadius: leadingRadius, bottomTrailingRadius: trailingRadius, topTrailingRadius: trailingRadius)
    }

    private var feedbackOpacity: Double {
        guard isEnabled else { return 0 }
        if isPressed { return Palette.scanPillPressedOpacity }
        return isHovered ? Palette.scanPillHoverOpacity : 0
    }

    var body: some View {
        label
            .font(Typography.rowTitle)
            .foregroundStyle(isEnabled ? Palette.onBrand : Palette.scanPillDisabledText)
            .lineLimit(1)
            .padding(.horizontal, fitsLabel ? Metrics.scanPillFittedPadding : 0)
            .frame(maxWidth: fitsLabel ? nil : .infinity, maxHeight: .infinity)
            .clipShape(shape)
            .background {
                shape.fill(Palette.scanPillFeedback)
                    .animation(reduceMotion ? nil : Motion.feedback) { $0.opacity(feedbackOpacity) }
            }
            .background(isEnabled ? fill : Palette.scanPillDisabledFill, in: shape)
            .overlay {
                if isFocused, isEnabled {
                    shape.inset(by: Metrics.scanPillFocusInset)
                        .strokeBorder(Palette.onBrand, lineWidth: Metrics.scanPillFocusWidth)
                }
            }
            .contentShape(.rect)
            .onHover { isHovered = $0 }
            .animation(reduceMotion ? nil : Motion.standard, value: isEnabled)
    }
}
