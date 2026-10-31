import BluehatCore
import SwiftUI

struct IgnoredSettingsTab: View {
    let settings: SettingsStore

    var body: some View {
        Form {
            Section {
                if settings.ignored.isEmpty {
                    ContentUnavailableView("No Ignored Findings", systemImage: "eye", description: Text("Findings you ignore from a finding's detail view appear here."))
                } else {
                    ForEach(settings.ignored) { entry in
                        HStack(alignment: .firstTextBaseline, spacing: Metrics.spaceMedium) {
                            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                                Text(entry.title)
                                    .font(Typography.rowTitle)
                                Text(entry.detail)
                                    .font(Typography.detail)
                                    .foregroundStyle(Palette.secondaryText)
                                    .lineLimit(2)
                                    .truncationMode(.middle)
                                Text("Ignored \(entry.ignoredAt.formatted(date: .abbreviated, time: .shortened))")
                                    .font(Typography.caption)
                                    .foregroundStyle(Palette.tertiaryText)
                            }
                            Spacer()
                            Button("Stop Ignoring") { settings.stopIgnoring(entry) }
                        }
                    }
                }
            } footer: {
                Text("An ignored finding stays hidden only while its rule, full details and location match exactly, so a changed or different file, command, launch item or port shows up again. The panel always shows how many findings are ignored.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
        }
        .formStyle(.grouped)
    }
}
