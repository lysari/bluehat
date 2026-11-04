import BluehatCore
import SwiftUI

struct FindingsControls: View {
    let store: ScanStore
    let shownCount: Int
    let totalCount: Int
    let isFiltering: Bool
    let copiedMessage: String?

    private var tab: Binding<ScanStore.FindingsTab> {
        Binding { store.findingsTab } set: { store.findingsTab = $0 }
    }

    private var search: Binding<String> {
        Binding { store.filter.search } set: { store.filter.search = $0 }
    }

    private var isNotScannedTab: Bool {
        store.findingsTab == .notScanned
    }

    private var shownText: String {
        "\(shownCount.formatted()) of \(totalCount.formatted()) shown"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            tabBar
                .frame(height: Metrics.findingsTabBarHeight)
            HStack(spacing: Metrics.spaceSmall) {
                FindingsSearchField(text: search, prompt: isNotScannedTab ? "Search paths and reasons" : "Search findings")
                FindingsFilterMenu(store: store)
            }
            if isFiltering || copiedMessage != nil {
                statusLine
                    .transition(.opacity)
            }
        }
        .animation(Motion.feedback, value: isFiltering)
        .animation(Motion.feedback, value: copiedMessage)
        .onChange(of: shownCount) {
            if isFiltering { announceResults() }
        }
        .onChange(of: isFiltering) {
            if isFiltering { announceResults() }
        }
    }

    @ViewBuilder
    private var tabBar: some View {
        if store.showsNotScanned {
            Picker("Findings list", selection: tab) {
                Text("Findings (\(store.visibleFindings.count.formatted()))")
                    .tag(ScanStore.FindingsTab.findings)
                Text("Not Scanned (\(store.notScanned.totalCount.formatted()))")
                    .tag(ScanStore.FindingsTab.notScanned)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: .infinity)
        } else {
            Text("FINDINGS (\(store.visibleFindings.count.formatted()))")
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.secondaryText)
                .padding(.leading, Metrics.spaceTight)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityAddTraits(.isHeader)
        }
    }

    private var statusLine: some View {
        HStack(spacing: Metrics.spaceSmall) {
            if isFiltering {
                Text(shownText)
                    .foregroundStyle(Palette.secondaryText)
                Button("Reset") { store.filter.reset() }
                    .buttonStyle(.link)
                    .accessibilityLabel("Reset search and filters")
            }
            Spacer(minLength: 0)
            if let copiedMessage {
                Label(copiedMessage, systemImage: "checkmark")
                    .foregroundStyle(Palette.secondaryText)
                    .lineLimit(1)
            }
        }
        .font(Typography.caption)
        .padding(.leading, Metrics.spaceTight)
    }

    private func announceResults() {
        AccessibilityNotification.Announcement(shownCount == 0 ? "No matches" : shownText).post()
    }
}
