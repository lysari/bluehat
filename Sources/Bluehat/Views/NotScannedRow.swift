import AppKit
import BluehatCore
import SwiftUI

struct NotScannedRow: View {
    let entry: NotScannedEntry

    var body: some View {
        HStack(alignment: .top, spacing: Metrics.spaceMedium) {
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text(entry.name)
                    .font(Typography.detail)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Text(entry.explanation)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 0)
            if let path = entry.path {
                Button("Show in Finder", systemImage: "folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .foregroundStyle(Palette.secondaryText)
                .help("Show in Finder")
                .accessibilityLabel("Show \(entry.name) in Finder")
            }
        }
        .padding(.vertical, Metrics.spaceMedium)
    }
}
