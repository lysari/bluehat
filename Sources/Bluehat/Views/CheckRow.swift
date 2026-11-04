import BluehatCore
import SwiftUI

struct CheckRow: View {
    let title: String
    let symbol: String
    let details: CheckDetails
    let status: CheckStatus
    let findings: [Finding]
    let ignoredCount: Int
    var walkedItemCount = 0
    @State private var isShowingDetails = false
    @State private var isHovered = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var worstSeverity: Severity? {
        findings.map(\.rule.severity).max()
    }

    private var isShowingItemCount: Bool {
        status == .running && walkedItemCount > 0
    }

    private var highlight: Color {
        if status == .running { return Palette.brand.opacity(Palette.tintFillOpacity) }
        return isHovered || isShowingDetails ? Palette.cardFill : .clear
    }

    var body: some View {
        Button {
            isShowingDetails.toggle()
        } label: {
            label
        }
        .buttonStyle(.plain)
        .accessibilityHint("Opens details")
        .onHover { isHovered = $0 }
        .popover(isPresented: $isShowingDetails, arrowEdge: .trailing) {
            CheckDetailsView(title: title, symbol: symbol, details: details, statusLine: statusLine, statusTint: worstSeverity.map(Palette.severity) ?? Palette.secondaryText) {
                isShowingDetails = false
            }
        }
    }

    private var label: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Image(systemName: symbol)
                .foregroundStyle(Palette.secondaryText)
                .frame(width: Metrics.checkSymbolWidth)
                .accessibilityHidden(true)
            Text(title)
                .font(Typography.body)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
            if isShowingItemCount {
                Text("\(walkedItemCount.formatted()) items")
                    .font(Typography.caption)
                    .monospacedDigit()
                    .foregroundStyle(Palette.secondaryText)
            }
            statusMark
                .frame(minWidth: Metrics.checkStatusWidth)
        }
        .background {
            RoundedRectangle(cornerRadius: Metrics.checkRowHighlightRadius, style: .continuous)
                .fill(highlight)
                .padding(-Metrics.checkRowHighlightOutset)
                .animation(reduceMotion ? nil : Motion.feedback, value: highlight)
        }
        .contentShape(Rectangle().inset(by: -Metrics.checkRowHighlightOutset))
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var statusMark: some View {
        switch status {
        case .nothingToCheck:
            Image(systemName: "minus.circle")
                .foregroundStyle(Palette.emptyArea)
                .accessibilityLabel("Nothing to check yet")
                .help("Nothing to check yet")
        case .notRun, .waiting:
            Circle()
                .fill(Palette.tertiaryText)
                .frame(width: Metrics.severityDot, height: Metrics.severityDot)
                .accessibilityLabel("Not checked yet")
        case .running:
            runningMark
                .frame(width: Metrics.checkStatusWidth, height: Metrics.checkStatusWidth)
                .accessibilityLabel("Checking now")
        case .finished, .stoppedEarly:
            if let worstSeverity {
                Text("\(findings.count)")
                    .font(Typography.count)
                    .foregroundStyle(Palette.severity(worstSeverity))
                    .accessibilityLabel(counted(findings.count, "finding"))
            } else if status == .stoppedEarly {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.notice)
                    .accessibilityLabel("Stopped early")
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Palette.safe)
                    .accessibilityLabel("Passed")
            }
        }
    }

    @ViewBuilder
    private var runningMark: some View {
        if reduceMotion {
            Image(systemName: "circle.dotted")
                .foregroundStyle(Palette.brand)
        } else {
            ProgressView()
                .progressViewStyle(.circular)
                .controlSize(.mini)
        }
    }

    private var statusLine: String {
        switch status {
        case .nothingToCheck: "Nothing to check yet: the rulebook has no rule for this."
        case .notRun: "Not checked yet."
        case .waiting: "Waiting for its turn in this scan."
        case .running: isShowingItemCount ? "Checking now: \(walkedItemCount.formatted()) items so far." : "Checking now."
        case .finished: finishedLine
        case .stoppedEarly: findings.isEmpty ? "Stopped early at the memory limit." : "\(counted(findings.count, "finding")) before it stopped at the memory limit."
        }
    }

    private var finishedLine: String {
        let result = findings.isEmpty ? "Passed in the latest scan" : "\(counted(findings.count, "finding")) in the latest scan"
        return ignoredCount == 0 ? "\(result)." : "\(result) · \(ignoredCount) ignored."
    }
}
