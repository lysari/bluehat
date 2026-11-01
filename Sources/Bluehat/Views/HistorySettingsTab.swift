import BluehatCore
import SwiftUI

struct HistorySettingsTab: View {
    let history: ScanHistory

    var body: some View {
        Form {
            Section {
                if history.records.isEmpty {
                    ContentUnavailableView("No Scans Yet", systemImage: "clock", description: Text("Each scan is saved here with what changed since the one before."))
                } else {
                    ForEach(history.records) { record in
                        HistoryRow(record: record, changes: history.changes(for: record))
                    }
                }
            } footer: {
                Text("Bluehat keeps the last \(ScanHistory.maxRecords) scans on this Mac.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            .overlayScrollers()
        }
        .formStyle(.grouped)
    }
}

private struct HistoryRow: View {
    let record: ScanRecord
    let changes: ScanChanges

    private var tint: Color {
        record.issues.map(\.severity).max().map(Palette.severity) ?? Palette.safe
    }

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                if changes.isEmpty {
                    Text("Nothing changed since the scan before.")
                        .foregroundStyle(Palette.secondaryText)
                }
                ForEach(changes.new) { entry in
                    change(entry, kind: "New", symbol: "plus.circle.fill", tint: Palette.severity(entry.severity))
                }
                ForEach(changes.resolved) { entry in
                    change(entry, kind: "Resolved", symbol: "checkmark.circle.fill", tint: Palette.safe)
                }
            }
            .font(Typography.caption)
            .padding(.vertical, Metrics.spaceSmall)
        } label: {
            HStack(spacing: Metrics.spaceMedium) {
                Image(systemName: record.issues.isEmpty ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .foregroundStyle(tint)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                    Text(record.date.formatted(date: .abbreviated, time: .shortened))
                        .font(Typography.rowTitle)
                    Text("Rules v\(String(record.rulesVersion)) · \(record.duration.formatted(.number.precision(.fractionLength(1))))s")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                Spacer()
                Text(summary)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            .accessibilityElement(children: .combine)
        }
    }

    private var summary: String {
        var parts = [record.issues.isEmpty ? "No issues" : counted(record.issues.count, "issue")]
        if !changes.new.isEmpty { parts.append("\(changes.new.count) new") }
        if !changes.resolved.isEmpty { parts.append("\(changes.resolved.count) resolved") }
        return parts.joined(separator: " · ")
    }

    private func change(_ entry: ScanRecord.Entry, kind: String, symbol: String, tint: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Metrics.spaceSmall) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text(entry.title)
                Text(entry.detail)
                    .font(Typography.detail)
                    .foregroundStyle(Palette.secondaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(kind): \(entry.title)")
    }
}
