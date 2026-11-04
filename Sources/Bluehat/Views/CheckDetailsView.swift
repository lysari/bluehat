import AppKit
import SwiftUI

struct CheckDetailsView: View {
    private static let escapeKeyCode: UInt16 = 53

    let title: String
    let symbol: String
    let details: CheckDetails
    let statusLine: String
    let statusTint: Color
    let onClose: () -> Void
    @State private var escapeMonitor: Any?

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceLarge) {
            HStack(spacing: Metrics.spaceSmall) {
                Image(systemName: symbol)
                    .foregroundStyle(Palette.secondaryText)
                    .frame(width: Metrics.checkSymbolWidth)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                    Text(title)
                        .font(Typography.statusTitle)
                    Text(statusLine)
                        .font(Typography.caption)
                        .foregroundStyle(statusTint)
                        .lineLimit(1)
                }
            }
            .accessibilityElement(children: .combine)
            section("What it looks for", details.looksFor)
            section("Where it looks", details.looksIn)
            section("What a finding means for you", details.findingMeans)
            VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                sectionTitle("Privacy")
                privacyLine("File contents:", details.fileContents)
                privacyLine("Internet:", details.internet)
            }
        }
        .padding(Metrics.cardPadding)
        .frame(width: Metrics.checkDetailsWidth, alignment: .leading)
        .onAppear {
            escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
                guard event.keyCode == Self.escapeKeyCode else { return event }
                onClose()
                return nil
            }
        }
        .onDisappear {
            escapeMonitor.map(NSEvent.removeMonitor)
            escapeMonitor = nil
        }
    }

    private func section(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: Metrics.spaceTight) {
            sectionTitle(title)
            Text(text)
                .font(Typography.body)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .font(Typography.captionEmphasis)
            .foregroundStyle(Palette.secondaryText)
            .accessibilityAddTraits(.isHeader)
    }

    private func privacyLine(_ label: String, _ text: String) -> some View {
        Text("\(Text(label).fontWeight(.medium)) \(text)")
            .font(Typography.body)
            .fixedSize(horizontal: false, vertical: true)
    }
}
