import BluehatCore
import SwiftUI

struct FindingGroupHeader<Actions: View>: View {
    let title: String
    let symbol: String
    let count: Int
    let worstSeverity: Severity?
    let isExpanded: Bool
    var noun = "finding"
    let onToggle: () -> Void
    @ViewBuilder let actions: Actions
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Button {
                withAnimation(reduceMotion ? nil : Motion.standard, onToggle)
            } label: {
                toggleLabel
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(title), \(counted(count, noun))")
            .accessibilityValue(isExpanded ? "Expanded" : "Collapsed")
            .accessibilityHint(isExpanded ? "Hides this group's \(noun)s" : "Shows this group's \(noun)s")
            .accessibilityAddTraits(.isHeader)
            actions
        }
        .font(Typography.captionEmphasis)
    }

    private var toggleLabel: some View {
        HStack(spacing: Metrics.spaceMedium) {
            HStack(spacing: 0) {
                Image(systemName: "chevron.right")
                    .foregroundStyle(Palette.tertiaryText)
                    .rotationEffect(.degrees(isExpanded ? Metrics.groupChevronExpandedDegrees : 0))
                    .frame(width: Metrics.groupChevronWidth)
                Image(systemName: symbol)
                    .foregroundStyle(Palette.secondaryText)
                    .frame(width: Metrics.findingBadge - Metrics.groupChevronWidth)
            }
            Text(title)
                .foregroundStyle(Palette.secondaryText)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("\(count)")
                .font(Typography.count)
                .foregroundStyle(worstSeverity.map(Palette.severity) ?? Palette.secondaryText)
        }
        .padding(.vertical, Metrics.spaceSmall)
        .contentShape(.rect)
    }
}
