import BluehatCore
import SwiftUI

struct CheckRow: View {
    let kind: CheckKind
    let findings: [Finding]
    let hasRules: Bool
    let isChecked: Bool

    var body: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Image(systemName: kind.symbol)
                .foregroundStyle(Palette.secondaryText)
                .frame(width: Metrics.checkSymbolWidth)
                .accessibilityHidden(true)
            Text(kind.title)
                .font(Typography.body)
                .lineLimit(1)
            Spacer(minLength: Metrics.spaceSmall)
            status
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var status: some View {
        if !hasRules {
            Image(systemName: "minus.circle")
                .foregroundStyle(Palette.emptyArea)
                .accessibilityLabel("Nothing to check yet")
                .help("Nothing to check yet")
        } else if !isChecked {
            Circle()
                .fill(Palette.tertiaryText)
                .frame(width: Metrics.severityDot, height: Metrics.severityDot)
                .accessibilityLabel("Not checked yet")
        } else if let worst = findings.map(\.rule.severity).max() {
            Text("\(findings.count)")
                .font(Typography.count)
                .foregroundStyle(Palette.severity(worst))
                .accessibilityLabel(counted(findings.count, "finding"))
        } else {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Palette.safe)
                .accessibilityLabel("Passed")
        }
    }
}
