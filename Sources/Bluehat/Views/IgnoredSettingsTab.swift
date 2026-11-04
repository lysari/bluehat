import BluehatCore
import SwiftUI

struct IgnoredSettingsTab: View {
    private static let otherTitle = "Other"
    private static let otherSymbol = "questionmark.circle"

    let settings: SettingsStore
    let rules: FeedReview<Rulebook>
    let malwareFeed: FeedReview<MalwareFeed>
    @State private var collapsedGroups: Set<CheckKind?> = []
    @State private var groupToRemove: IgnoredFindingGroup?

    var body: some View {
        Group {
            if settings.ignored.isEmpty {
                emptyState
            } else {
                groupList
            }
        }
        .confirmationDialog(removeAllTitle, isPresented: isConfirmingRemoveAll, titleVisibility: .visible, presenting: groupToRemove) { group in
            Button("Remove All (\(group.entries.count))") {
                settings.stopIgnoring(group)
            }
        } message: { _ in
            Text("These findings show up again on the next scan, if they are still there.")
        }
        .task {
            guard settings.ignored.contains(where: { $0.check == nil }) else { return }
            await rules.loadLocal()
            await malwareFeed.loadLocal()
            settings.fillInIgnored(from: (rules.local?.payload.rules ?? []) + (malwareFeed.local?.payload.rules ?? []))
        }
    }

    private var emptyState: some View {
        Form {
            Section {
                ContentUnavailableView("No Ignored Findings", systemImage: "eye", description: Text("Findings you ignore from the findings list appear here."))
            } footer: {
                footer
            }
            .overlayScrollers(flashesOnAppear: true)
        }
        .formStyle(.grouped)
    }

    private var groupList: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceMedium) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(IgnoredFindingGroup.groups(of: settings.ignored)) { group in
                        groupSection(group)
                    }
                }
                .padding(.horizontal, Metrics.cardPadding)
                .overlayScrollers(flashesOnAppear: true)
            }
            .contentMargins(.vertical, Metrics.scrollIndicatorInset, for: .scrollIndicators)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .card()
            footer
        }
        .padding(Metrics.ignoredTabPadding)
    }

    private var footer: some View {
        Text("An ignored finding stays hidden only while its rule, full details and location match exactly, so a changed or different file, command, launch item or port shows up again. The panel always shows how many findings are ignored.")
            .font(Typography.caption)
            .foregroundStyle(Palette.secondaryText)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func groupSection(_ group: IgnoredFindingGroup) -> some View {
        let isExpanded = !collapsedGroups.contains(group.check)
        return Section {
            if isExpanded {
                ForEach(group.entries) { entry in
                    IgnoredRow(entry: entry) { settings.stopIgnoring(entry) }
                    if entry.id != group.entries.last?.id {
                        Divider()
                    }
                }
            }
        } header: {
            FindingGroupHeader(title: title(of: group), symbol: group.check?.symbol ?? Self.otherSymbol, count: group.entries.count, worstSeverity: group.worstSeverity, isExpanded: isExpanded) {
                if collapsedGroups.remove(group.check) == nil {
                    collapsedGroups.insert(group.check)
                }
            } actions: {
                Button("Remove All…") { groupToRemove = group }
                    .controlSize(.small)
                    .accessibilityLabel("Remove all \(title(of: group)) findings from Ignored")
            }
        }
    }

    private func title(of group: IgnoredFindingGroup) -> String {
        group.check?.title ?? Self.otherTitle
    }

    private var removeAllTitle: String {
        guard let groupToRemove else { return "" }
        return "Remove \(counted(groupToRemove.entries.count, "finding")) in \(title(of: groupToRemove)) from Ignored?"
    }

    private var isConfirmingRemoveAll: Binding<Bool> {
        Binding {
            groupToRemove != nil
        } set: { isPresented in
            if !isPresented { groupToRemove = nil }
        }
    }
}

private struct IgnoredRow: View {
    let entry: IgnoredFinding
    let onStopIgnoring: () -> Void

    var body: some View {
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
            Button("Stop Ignoring", action: onStopIgnoring)
        }
        .padding(.vertical, Metrics.spaceMedium)
    }
}
