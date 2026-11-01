import BluehatCore
import SwiftUI

struct FindingRow: View {
    let finding: Finding
    let onOpen: () -> Void

    private var tint: Color {
        Palette.severity(finding.rule.severity)
    }

    var body: some View {
        Button(action: onOpen) {
            content
        }
        .buttonStyle(.plain)
        .accessibilityHint("Shows details and how to fix it")
    }

    private var content: some View {
        HStack(alignment: .top, spacing: Metrics.spaceMedium) {
            Image(systemName: finding.rule.severity.symbol)
                .font(.system(size: Metrics.findingSymbol, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: Metrics.findingBadge, height: Metrics.findingBadge)
                .background(tint.opacity(Palette.tintFillOpacity), in: .circle)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text(finding.rule.title)
                    .font(Typography.rowTitle)
                    .fixedSize(horizontal: false, vertical: true)
                Text(finding.detail)
                    .font(Typography.detail)
                    .foregroundStyle(Palette.secondaryText)
                    .lineLimit(2)
                    .truncationMode(.middle)
                HStack(spacing: Metrics.spaceSmall) {
                    Text(finding.rule.severity.rawValue.capitalized)
                        .font(Typography.captionEmphasis)
                        .foregroundStyle(tint)
                    Text("·")
                    Text(finding.rule.category.title)
                        .font(Typography.caption)
                }
                .foregroundStyle(Palette.tertiaryText)
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right")
                .font(Typography.captionEmphasis)
                .foregroundStyle(Palette.tertiaryText)
                .frame(height: Metrics.findingBadge)
                .accessibilityHidden(true)
        }
        .padding(.vertical, Metrics.spaceMedium)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }
}
