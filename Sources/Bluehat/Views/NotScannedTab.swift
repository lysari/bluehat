import BluehatCore
import SwiftUI

struct NotScannedTab: View {
    private static let fullDiskAccessURL = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles")

    let store: ScanStore
    let groups: [NotScannedGroup]
    let isFiltering: Bool
    @Environment(\.openURL) private var openURL

    private var list: NotScannedList {
        store.notScanned
    }

    private var isAccessRelated: Bool {
        list.totalsByReason[.noPermission] != nil || list.totalsByReason[.couldNotRead] != nil
    }

    var body: some View {
        if isFiltering, groups.isEmpty {
            FindingsEmptyView(title: "No Matches", symbol: "magnifyingglass", message: "Nothing here matches your search or filter.") {
                store.filter.reset()
            }
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if !isFiltering {
                        summary
                    }
                    ForEach(groups) { group in
                        groupSection(group)
                    }
                }
                .padding(.horizontal, Metrics.cardPadding)
                .overlayScrollers()
            }
            .contentMargins(.vertical, Metrics.scrollIndicatorInset, for: .scrollIndicators)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .card()
        }
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            Text(list.coverage?.summary ?? (list.isEmpty ? "Nothing was skipped in this scan." : "These items weren't checked in this scan."))
                .font(Typography.body)
                .foregroundStyle(Palette.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
            if list.coverage != nil {
                summaryText(NotScannedList.Coverage.otherVolumesNote)
                if list.isEmpty {
                    summaryText("Nothing else was skipped in this scan.")
                }
            }
            if let exclusions = list.coverage?.exclusionSummary {
                summaryText(exclusions)
            }
            if list.leftOutCount > 0 {
                summaryText("Listing \(list.entries.count.formatted()) of \(list.totalCount.formatted()). \(list.leftOutCount.formatted()) were left out, keeping your home folder first. Raise Not Scanned list size in Settings › Limits to keep more.")
            }
            if isAccessRelated {
                summaryText("Full Disk Access is optional. It may open some of these folders, but not system-only ones, and it gives Bluehat wider access to your private data. It's in System Settings › Privacy & Security › Full Disk Access.")
                Button("Open Full Disk Access Settings") {
                    if let url = Self.fullDiskAccessURL { openURL(url) }
                }
                .controlSize(.small)
            }
            summaryText("This list covers the latest scan only and isn't saved, so it's gone when Bluehat quits.")
        }
        .padding(.vertical, Metrics.spaceMedium)
    }

    private func summaryText(_ text: String) -> some View {
        Text(text)
            .font(Typography.caption)
            .foregroundStyle(Palette.secondaryText)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func groupSection(_ group: NotScannedGroup) -> some View {
        let isExpanded = !store.collapsedNotScannedGroups.contains(group.reason)
        return Section {
            if isExpanded {
                ForEach(group.entries) { entry in
                    NotScannedRow(entry: entry)
                    if entry.id != group.entries.last?.id {
                        Divider()
                    }
                }
                if group.leftOutCount > 0, !isFiltering {
                    summaryText("\(group.leftOutCount.formatted()) more not listed")
                        .padding(.vertical, Metrics.spaceMedium)
                }
            }
        } header: {
            FindingGroupHeader(title: group.reason.title, symbol: group.reason.symbol, count: isFiltering ? group.entries.count : group.totalCount, worstSeverity: nil, isExpanded: isExpanded, noun: "item") {
                store.toggleNotScannedGroup(group.reason)
            } actions: {
                EmptyView()
            }
        }
    }
}
