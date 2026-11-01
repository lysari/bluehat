import AppKit
import BluehatCore
import SwiftUI

struct FindingDetailView: View {
    let finding: Finding
    let store: ScanStore
    let onBack: () -> Void
    let onIgnore: () -> Void
    @Environment(\.openURL) private var openURL

    private var tint: Color {
        Palette.severity(finding.rule.severity)
    }

    private var references: [URL] {
        (finding.rule.references ?? []).compactMap(URL.init(string:))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSection) {
            Button(action: onBack) {
                Label("Findings", systemImage: "chevron.left")
                    .font(Typography.rowTitle)
            }
            .buttonStyle(.borderless)
            .keyboardShortcut(.cancelAction)
            HStack(spacing: Metrics.spaceLarge) {
                ShieldEmblem(tint: tint, face: .symbol(finding.rule.severity.emblemSymbol), size: Metrics.detailEmblem, isFloating: false)
                VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                    Text(finding.rule.title)
                        .font(Typography.statusTitle)
                        .fixedSize(horizontal: false, vertical: true)
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
            }
            .accessibilityElement(children: .combine)
            section("What was found") {
                VStack(alignment: .leading, spacing: Metrics.spaceMedium) {
                    Text(finding.detail)
                        .font(Typography.detail)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: Metrics.spaceMedium) {
                        if let path = finding.path {
                            Button("Show in Finder", systemImage: "folder") {
                                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                            }
                        }
                        Button("Copy", systemImage: "doc.on.doc") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(finding.detail, forType: .string)
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            section("Why it matters") {
                Text(finding.rule.summary ?? finding.rule.category.whyItMatters)
                    .font(Typography.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
            section("How to fix") {
                VStack(alignment: .leading, spacing: Metrics.spaceMedium) {
                    Text(finding.rule.remedy ?? finding.rule.check.fixHint)
                        .font(Typography.body)
                        .fixedSize(horizontal: false, vertical: true)
                    if finding.rule.check == .softwareVersion, let path = finding.path {
                        InstallationActions(path: path, store: store, onMovedToTrash: onBack)
                    }
                }
            }
            if !references.isEmpty {
                section("Learn more") {
                    VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                        ForEach(references, id: \.self) { url in
                            Button(url.host() ?? url.absoluteString, systemImage: "arrow.up.right.square") { openURL(url) }
                                .buttonStyle(.link)
                        }
                    }
                }
            }
            HStack {
                Text("Bluehat never changes anything unless you ask.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.tertiaryText)
                Spacer()
                Button("Ignore", systemImage: "eye.slash", action: onIgnore)
                    .help("Hide this exact finding from future scans. You can undo it in Settings › Ignored.")
            }
        }
    }

    private func section(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            Text(title.uppercased())
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.secondaryText)
                .padding(.leading, Metrics.spaceTight)
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Metrics.cardPadding)
                .card()
        }
    }
}
