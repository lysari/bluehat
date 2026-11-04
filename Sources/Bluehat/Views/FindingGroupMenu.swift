import BluehatCore
import SwiftUI

struct FindingGroupMenu: View {
    let group: FindingGroup
    let store: ScanStore
    let isFiltered: Bool
    let onCopyFixSteps: () -> Void
    let onIgnoreAll: () -> Void
    let onMoveAllToTrash: () -> Void
    @State private var trashableCount = 0

    private var softwarePaths: [String] {
        guard group.check == .softwareVersion, !store.isBusy else { return [] }
        return group.findings.compactMap(\.path)
    }

    var body: some View {
        Menu {
            Button(isFiltered ? "Copy Fix Steps for \(group.findings.count) Shown" : "Copy Fix Steps", systemImage: "doc.on.doc", action: onCopyFixSteps)
            Divider()
            Button(isFiltered ? "Ignore \(group.findings.count) Shown…" : "Ignore All (\(group.findings.count))…", systemImage: "eye.slash", action: onIgnoreAll)
            if trashableCount > 0 {
                Button(isFiltered ? "Move \(trashableCount) Shown to Trash…" : "Move All to Trash (\(trashableCount))…", systemImage: "trash", action: onMoveAllToTrash)
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(Typography.body)
                .foregroundStyle(Palette.secondaryText)
                .frame(width: Metrics.groupMenuSize, height: Metrics.groupMenuSize)
                .contentShape(.rect)
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .menuIndicator(.hidden)
        .fixedSize()
        .help(isFiltered ? "Actions for the \(group.check.title) findings shown" : "Actions for all \(group.check.title) findings")
        .accessibilityLabel("Actions for \(group.check.title)")
        .task(id: softwarePaths) {
            trashableCount = softwarePaths.isEmpty ? 0 : store.trashPlan(for: group).findingCount
        }
    }
}
