import BluehatCore
import SwiftUI

struct GroupTrashSheet: View {
    let title: String
    let plan: TrashPlan
    let isFiltered: Bool
    let store: ScanStore
    @State private var result: TrashPlan.Result?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceLarge) {
            if let result {
                outcome(result)
            } else {
                confirmation
            }
        }
        .padding(Metrics.trashSheetPadding)
        .frame(width: Metrics.trashSheetWidth)
        .onChange(of: store.isBusy) { _, isBusy in
            if isBusy, result == nil { dismiss() }
        }
    }

    @ViewBuilder
    private var confirmation: some View {
        Text(plan.movable.isEmpty ? "Nothing can be moved" : "Move \(counted(plan.movable.count, "folder")) to the Trash?")
            .font(Typography.statusTitle)
        if !plan.movable.isEmpty {
            caption("These go to the Trash, and you can restore them from there until you empty it. This clears \(counted(plan.movableFindingCount, "finding")).")
        }
        if isFiltered {
            caption("This acts only on the \(counted(plan.findingCount, "finding")) shown by your search or filter. Others in \(title) stay in the list.")
        }
        if plan.otherFindingCount > 0 {
            caption("\(counted(plan.otherFindingCount, "other finding")) in \(title) \(plan.otherFindingCount == 1 ? "needs" : "need") other fixes and stay\(plan.otherFindingCount == 1 ? "s" : "") in the list.")
        }
        pathList {
            if !plan.movable.isEmpty {
                listHeading("Go to the Trash (\(plan.movable.count))")
                ForEach(plan.movable, id: \.path) { pathRow($0.displayPath) }
            }
            if !plan.refused.isEmpty {
                listHeading("Won't be moved (\(plan.refused.count)): protected system location")
                ForEach(plan.refused, id: \.path) { pathRow($0.displayPath) }
            }
        }
        HStack(spacing: Metrics.spaceMedium) {
            Spacer()
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            if !plan.movable.isEmpty {
                Button("Move to Trash", role: .destructive, action: moveAll)
                    .disabled(store.isBusy)
            }
        }
    }

    @ViewBuilder
    private func outcome(_ result: TrashPlan.Result) -> some View {
        Text(result.notMoved.isEmpty ? "Moved \(counted(result.moved.count, "folder")) to the Trash" : "Moved \(result.moved.count) of \(counted(result.moved.count + result.notMoved.count, "folder"))")
            .font(Typography.statusTitle)
        pathList {
            if !result.notMoved.isEmpty {
                listHeading("Couldn't be moved (\(result.notMoved.count))")
                ForEach(result.notMoved) { item in
                    VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                        pathRow(item.path)
                        Text(item.reason)
                            .font(Typography.caption)
                            .foregroundStyle(Palette.notice)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if !result.moved.isEmpty {
                listHeading("In the Trash (\(result.moved.count))")
                ForEach(result.moved, id: \.self) { pathRow($0) }
            }
        }
        HStack {
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
    }

    private func pathList(@ViewBuilder content: () -> some View) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                content()
            }
            .padding(Metrics.spaceMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .overlayScrollers()
        }
        .frame(height: Metrics.trashListHeight)
        .card()
    }

    private func listHeading(_ text: String) -> some View {
        Text(text)
            .font(Typography.captionEmphasis)
            .foregroundStyle(Palette.secondaryText)
            .accessibilityAddTraits(.isHeader)
    }

    private func pathRow(_ path: String) -> some View {
        Text(path)
            .font(Typography.detail)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(Typography.body)
            .foregroundStyle(Palette.secondaryText)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func moveAll() {
        guard let moved = store.moveAllToTrash(plan) else {
            dismiss()
            return
        }
        result = moved
        AccessibilityNotification.Announcement("Moved \(moved.moved.count) to the Trash. \(moved.notMoved.count) couldn't be moved.").post()
    }
}
