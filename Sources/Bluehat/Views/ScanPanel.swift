import AppKit
import BluehatCore
import SwiftUI

struct ScanPanel: View {
    private static let deepScanBlockedMessage = "The Deep Scan didn't start because another scan began. You can start it when this scan finishes."
    private static let statusSubtitleReservedLines = " \n \n "
    private static let scanAgainTitle = "Scan Again"
    private static let scanningTitle = "Scanning…"
    private static let deepScanReadyTitle = "Deep Scan"
    private static let cancellingTitle = "Cancelling…"
    private static let copiedMessageDuration = Duration.seconds(3)
    private static let checkAnnouncementDelay = Duration.seconds(2)

    private struct TrashReview: Identifiable {
        let id = UUID()
        let title: String
        let plan: TrashPlan
        let isFiltered: Bool
    }

    let store: ScanStore
    @State private var selectedFindingID: Finding.ID?
    @State private var isConfirmingDeepScan = false
    @State private var wasDeepScanBlocked = false
    @State private var groupToIgnore: FindingGroup?
    @State private var trashReview: TrashReview?
    @State private var copiedMessage: String?
    @Environment(\.openSettings) private var openSettings
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var selectedFinding: Finding? {
        store.visibleFindings.first { $0.id == selectedFindingID }
    }

    private var showsFindingsColumn: Bool {
        !store.visibleFindings.isEmpty || store.showsNotScanned
    }

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            overview
            ZStack(alignment: .topLeading) {
                if showsFindingsColumn {
                    findingsColumn
                        .padding(.leading, Metrics.spaceSection)
                        .transition(.opacity)
                }
            }
            .animation(Motion.standard, value: showsFindingsColumn)
            .frame(maxHeight: .infinity, alignment: .topLeading)
            .modifier(ColumnReveal(width: showsFindingsColumn ? Metrics.spaceSection + Metrics.findingsColumnWidth : 0))
            .animation(reduceMotion ? nil : Motion.standard, value: showsFindingsColumn)
        }
        .padding(Metrics.panelPadding)
        .animation(Motion.standard, value: store.phase)
        .confirmationDialog(ignoreAllTitle, isPresented: isConfirmingIgnoreAll, titleVisibility: .visible, presenting: groupToIgnore) { group in
            Button("Ignore All (\(group.findings.count))", role: .destructive) {
                store.settings.ignore(group.findings)
            }
        } message: { group in
            let scope = store.filter.isFilteringFindings ? "This acts only on the \(counted(group.findings.count, "finding")) shown by your search or filter. Others in this group stay in the list.\n\n" : ""
            Text(scope + "This also hides real threats: ignored findings leave this list, the ring and the menu bar count, even if they are malware. You can undo it in Settings › Ignored.\n\nNew findings of this type still appear, because ignoring matches each exact finding.")
        }
        .sheet(item: $trashReview) { review in
            GroupTrashSheet(title: review.title, plan: review.plan, isFiltered: review.isFiltered, store: store)
        }
        .onChange(of: store.isBusy) { _, isBusy in
            if isBusy { groupToIgnore = nil }
        }
    }

    private var ignoreAllTitle: String {
        guard let groupToIgnore else { return "" }
        return "Ignore \(counted(groupToIgnore.findings.count, "finding")) in \(groupToIgnore.check.title)?"
    }

    private var isConfirmingIgnoreAll: Binding<Bool> {
        Binding {
            groupToIgnore != nil
        } set: { isPresented in
            if !isPresented { groupToIgnore = nil }
        }
    }

    private var findingsColumn: some View {
        ZStack(alignment: .top) {
            if let selectedFinding {
                ScrollView {
                    FindingDetailView(finding: selectedFinding, store: store) {
                        selectedFindingID = nil
                    } onIgnore: {
                        store.settings.ignore([selectedFinding])
                        selectedFindingID = nil
                    }
                    .overlayScrollers()
                }
                .scrollClipDisabled()
                .id(selectedFinding.id)
                .transition(.move(edge: .trailing).combined(with: .opacity))
            } else {
                findingsSection
                    .transition(.move(edge: .leading).combined(with: .opacity))
            }
        }
        .frame(width: Metrics.findingsColumnWidth)
        .frame(minHeight: 0, idealHeight: 0, maxHeight: .infinity, alignment: .top)
        .clipShape(Rectangle().inset(by: -Metrics.cardStrokeWidth))
        .animation(Motion.standard, value: selectedFinding?.id)
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSection) {
            header
            statusCard
            if wasDeepScanBlocked {
                Label(Self.deepScanBlockedMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let notice = store.notice {
                Label(notice, systemImage: "exclamationmark.triangle.fill")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if store.rulesExpireSoon, let expires = store.rulebook?.expires {
                Label("Rules expire \(expires.formatted(.relative(presentation: .named))), on \(expires.formatted(date: .abbreviated, time: .omitted)). Check for updates in Settings › Rules.", systemImage: "clock.badge.exclamationmark")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
            checksSection
            footer
        }
        .frame(width: Metrics.overviewColumnWidth)
        .fixedSize(horizontal: false, vertical: true)
        .task(id: runningCheckTitle) {
            guard let runningCheckTitle, (try? await Task.sleep(for: Self.checkAnnouncementDelay)) != nil, isPanelVisible else { return }
            AccessibilityNotification.Announcement("Checking \(runningCheckTitle)").post()
        }
    }

    private var runningCheckTitle: String? {
        store.isWalkingDisk ? CheckDetails.diskWalkTitle : store.currentArea?.title
    }

    private var isPanelVisible: Bool {
        NSApplication.shared.windows.contains { $0 is MenuBarPanel && $0.isVisible }
    }

    private var header: some View {
        HStack(spacing: Metrics.spaceMedium) {
            ShieldEmblem(tint: Palette.brand, face: nil, size: Metrics.appIcon, isFloating: false)
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text("Bluehat")
                    .font(Typography.appTitle)
                Text("Threat scanner for macOS")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            Spacer()
            Menu {
                Button("Settings…") {
                    openSettings()
                    NSApplication.shared.activate()
                }
                .keyboardShortcut(",")
                Divider()
                Button("Quit Bluehat") { NSApplication.shared.terminate(nil) }
                    .keyboardShortcut("q")
            } label: {
                Image(systemName: "ellipsis.circle")
                    .font(Typography.headerAction)
                    .foregroundStyle(Palette.secondaryText)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("More")
        }
    }

    private var statusCard: some View {
        VStack(spacing: Metrics.spaceLarge) {
            ScanRing(store: store, tint: statusTint, face: emblemFace)
                .padding(.top, Metrics.heroTopPadding)
            ZStack(alignment: .top) {
                VStack(spacing: Metrics.spaceTight) {
                    Text(statusTitle)
                        .font(Typography.statusTitle)
                    Text(Self.statusSubtitleReservedLines)
                        .font(Typography.caption)
                }
                .hidden()
                VStack(spacing: Metrics.spaceTight) {
                    VStack(spacing: Metrics.spaceTight) {
                        Text(statusTitle)
                            .font(Typography.statusTitle)
                        Text(statusSubtitle)
                            .font(Typography.caption)
                            .foregroundStyle(Palette.secondaryText)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                    if store.showsNotScanned, let line = store.notScanned.summaryLine {
                        notScannedLine(line)
                    }
                }
            }
            HStack(spacing: 0) {
                Button {
                    Task { await store.scan() }
                } label: {
                    scanSegmentLabel
                }
                .buttonStyle(ScanPillSegmentStyle(edge: .leading, fill: Palette.scanPillFill))
                .disabled(!store.canStartScan)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel(buttonTitle)
                deepScanSegment
                    .overlay(alignment: .leading) {
                        Rectangle()
                            .fill((isDeepSegmentEnabled ? Palette.onBrand : Palette.scanPillDisabledText).opacity(Palette.scanPillDividerOpacity))
                            .frame(width: Metrics.scanPillDividerWidth)
                            .offset(x: -Metrics.scanPillDividerWidth / 2)
                            .allowsHitTesting(false)
                    }
            }
            .frame(height: Metrics.scanPillHeight)
            .focusEffectDisabled()
            .animation(reduceMotion ? nil : Motion.standard, value: deepScanTitle)
            .confirmationDialog("Start a Deep Scan?", isPresented: $isConfirmingDeepScan, titleVisibility: .visible) {
                Button("Start Deep Scan", action: startDeepScan)
            } message: {
                Text("Bluehat runs the normal scan, then looks for npm packages and project config files across your startup disk and opens only those. It runs at low priority, so it can take a long time, and you can cancel at any time. macOS may ask for access to more folders, and folders listed in Settings › General are skipped.\n\nA clean result doesn't mean there is no malware anywhere on your Mac: programs outside the normal scan's folders aren't checked.")
            }
            .onChange(of: store.canStartScan) { _, canStart in
                if canStart {
                    wasDeepScanBlocked = false
                } else if isConfirmingDeepScan {
                    isConfirmingDeepScan = false
                    if store.isBusy, store.scanKind == .normal { reportDeepScanBlocked() }
                }
            }
        }
        .padding(Metrics.cardPadding)
        .frame(maxWidth: .infinity)
        .card(wash: statusTint)
    }

    private func notScannedLine(_ line: String) -> some View {
        Button {
            selectedFindingID = nil
            store.findingsTab = .notScanned
        } label: {
            HStack(spacing: Metrics.spaceTight) {
                Text(line)
                Image(systemName: "chevron.right")
                    .foregroundStyle(Palette.tertiaryText)
                    .accessibilityHidden(true)
            }
            .font(Typography.caption)
            .foregroundStyle(Palette.secondaryText)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityHint("Opens the Not Scanned list")
    }

    private var scanSegmentLabel: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Image(systemName: "magnifyingglass")
            ZStack(alignment: .leading) {
                Text(Self.scanAgainTitle)
                    .hidden()
                Text(Self.scanningTitle)
                    .hidden()
                Text(buttonTitle)
                    .contentTransition(.opacity)
            }
        }
    }

    private var deepScanSegment: some View {
        Button {
            if isDeepScanRunning {
                store.cancelScan()
            } else {
                isConfirmingDeepScan = true
            }
        } label: {
            HStack(spacing: Metrics.spaceSmall) {
                if !isDeepScanRunning {
                    Image(systemName: CheckDetails.diskWalkSymbol)
                }
                Text(deepScanTitle)
                    .contentTransition(.opacity)
            }
        }
        .buttonStyle(ScanPillSegmentStyle(edge: .trailing, fill: isDeepScanRunning ? Palette.scanPillCancelFill : Palette.scanPillDeepFill, fitsLabel: isDeepScanRunning))
        .disabled(!isDeepSegmentEnabled)
        .help(deepScanFullTitle)
        .accessibilityLabel(deepScanFullTitle)
        .accessibilityHint(isDeepScanRunning ? "" : "Runs the normal scan, then checks npm packages and project config files across your startup disk.")
    }

    private var isDeepScanRunning: Bool {
        store.isBusy && store.scanKind == .deep
    }

    private var isDeepSegmentEnabled: Bool {
        isDeepScanRunning ? !store.isCancelling : store.canStartScan
    }

    private var deepScanTitle: String {
        guard isDeepScanRunning else { return Self.deepScanReadyTitle }
        return store.isCancelling ? Self.cancellingTitle : "Cancel"
    }

    private var deepScanFullTitle: String {
        guard isDeepScanRunning else { return "Deep Scan" }
        return store.isCancelling ? "Cancelling Deep Scan" : "Cancel Deep Scan"
    }

    private func startDeepScan() {
        guard store.canStartScan else {
            if store.isBusy { reportDeepScanBlocked() }
            return
        }
        Task { await store.scan(kind: .deep) }
    }

    private func reportDeepScanBlocked() {
        wasDeepScanBlocked = true
        AccessibilityNotification.Announcement(Self.deepScanBlockedMessage).post()
    }

    private var emblemFace: ShieldEmblem.Face {
        if store.failure != nil { return .symbol("xmark") }
        switch store.phase {
        case .idle: return .symbol("magnifyingglass")
        case .scanning: return .text("\(Int(store.progress * 100))%")
        case .finished: return store.issues.isEmpty ? .symbol("checkmark") : .text("\(store.issues.count)")
        }
    }

    private var statusTint: Color {
        if store.failure != nil { return Palette.failure }
        switch store.phase {
        case .idle, .scanning: return Palette.idle
        case .finished: return store.issues.map(\.rule.severity).max().map(Palette.severity) ?? Palette.safe
        }
    }

    private var statusTitle: String {
        if store.failure != nil { return "Couldn't load rules" }
        switch store.phase {
        case .idle: return "Ready to scan"
        case .scanning:
            if store.isCancelling { return "Cancelling Deep Scan…" }
            return store.scanKind == .deep ? "Deep Scan running…" : "Scanning your Mac…"
        case .finished:
            if store.issues.isEmpty { return "Your Mac looks safe" }
            return store.issues.count == 1 ? "1 issue needs attention" : "\(store.issues.count) issues need attention"
        }
    }

    private var statusSubtitle: String {
        if store.appUpdate.isUpdating { return "Scanning is unavailable while Bluehat updates." }
        if let failure = store.failure {
            return failure.contains("Settings › Rules") ? failure : "\(failure) Check for updates in Settings › Rules, or reinstall Bluehat."
        }
        let ruleCount = store.rulebook?.rules.count ?? 0
        switch store.phase {
        case .idle: return "Checks for remote code execution, malware, worms, backdoors and weak settings."
        case .scanning:
            return store.scanKind == .deep ? deepScanProgress : currentCheckProgress
        case .finished:
            let time = store.lastScanAt?.formatted(date: .omitted, time: .shortened) ?? ""
            let isDeepScan = store.scanKind == .deep
            let duration = store.scanDuration?.formatted(isDeepScan ?.units(allowed: [.hours, .minutes, .seconds], width: .narrow, maximumUnitCount: 2) : .units(allowed: [.seconds, .milliseconds], width: .narrow, maximumUnitCount: 1)) ?? ""
            let notes = store.notes.isEmpty ? "" : " · \(counted(store.notes.count, "note"))"
            let ignored = store.ignoredCount == 0 ? "" : " · \(store.ignoredCount) ignored"
            let newCount = store.history.latestChanges?.new.count ?? 0
            let resolvedCount = store.history.latestChanges?.resolved.count ?? 0
            let newText = newCount == 0 ? "" : " · \(newCount) new"
            let resolvedText = resolvedCount == 0 ? "" : " · \(resolvedCount) resolved"
            return "\(isDeepScan ? "Deep Scan · " : "")\(counted(ruleCount, "check")) in \(duration) · \(time)\(notes)\(ignored)\(newText)\(resolvedText)"
        }
    }

    private var deepScanProgress: String {
        if store.isCancelling { return "Waiting for the current check to stop. Nothing from this scan is saved." }
        guard store.isWalkingDisk else { return currentCheckProgress }
        let items = store.walkedItemCount == 0 ? "" : " \(store.walkedItemCount.formatted()) items so far."
        return "Looking for npm packages and project config files across your disk…\(items) This runs at low priority and can take a long time. You can close this panel."
    }

    private var currentCheckProgress: String {
        store.isLoadingRules ? "Loading rules…" : "Checking \(store.currentArea?.inlineTitle ?? "results")…"
    }

    private var buttonTitle: String {
        switch store.phase {
        case .idle: "Scan Now"
        case .scanning: Self.scanningTitle
        case .finished: Self.scanAgainTitle
        }
    }

    private var findingsSection: some View {
        let isNotScannedTab = store.showsNotScanned && store.findingsTab == .notScanned
        let shownFindings = isNotScannedTab ? [] : store.filter.findings(from: store.visibleFindings)
        let notScannedGroups = isNotScannedTab ? store.notScanned.groups(matching: store.filter) : []
        let isFiltering = isNotScannedTab ? store.filter.isFilteringNotScanned : store.filter.isFilteringFindings
        return VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            FindingsControls(
                store: store,
                shownCount: isNotScannedTab ? notScannedGroups.reduce(0) { $0 + $1.entries.count } : shownFindings.count,
                totalCount: isNotScannedTab ? store.notScanned.totalCount : store.visibleFindings.count,
                isFiltering: isFiltering,
                copiedMessage: copiedMessage
            )
            .task(id: copiedMessage) {
                guard copiedMessage != nil, (try? await Task.sleep(for: Self.copiedMessageDuration)) != nil else { return }
                copiedMessage = nil
            }
            if isNotScannedTab {
                NotScannedTab(store: store, groups: notScannedGroups, isFiltering: isFiltering)
            } else if shownFindings.isEmpty {
                findingsEmptyState(isFiltering: isFiltering)
            } else {
                ScrollView {
                    findingRows(shownFindings, isFiltering: isFiltering)
                        .padding(.horizontal, Metrics.cardPadding)
                        .overlayScrollers()
                        .animation(Motion.standard, value: store.settings.findingsLayout)
                }
                .contentMargins(.vertical, Metrics.scrollIndicatorInset, for: .scrollIndicators)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .card()
            }
        }
        .animation(Motion.standard, value: isNotScannedTab)
    }

    @ViewBuilder
    private func findingsEmptyState(isFiltering: Bool) -> some View {
        if isFiltering {
            FindingsEmptyView(title: "No Matches", symbol: "magnifyingglass", message: "Nothing here matches your search or filter.") {
                store.filter.reset()
            }
        } else {
            FindingsEmptyView(title: "No Findings", symbol: "checkmark.shield", message: store.ignoredCount == 0 ? "This scan found nothing to list." : "This scan has nothing to list. \(store.ignoredCount) ignored.")
        }
    }

    @ViewBuilder
    private func findingRows(_ shown: [Finding], isFiltering: Bool) -> some View {
        switch store.settings.findingsLayout {
        case .normal:
            LazyVStack(spacing: 0) {
                rows(shown)
            }
        case .grouped:
            LazyVStack(spacing: 0) {
                ForEach(FindingGroup.groups(of: shown)) { group in
                    let isExpanded = !store.collapsedGroups.contains(group.check)
                    Section {
                        if isExpanded {
                            rows(group.findings)
                        }
                    } header: {
                        FindingGroupHeader(title: group.check.title, symbol: group.check.symbol, count: group.findings.count, worstSeverity: group.worstSeverity, isExpanded: isExpanded) {
                            store.toggleGroup(group.check)
                        } actions: {
                            FindingGroupMenu(group: group, store: store, isFiltered: isFiltering) {
                                copyFixSteps(of: group, isFiltered: isFiltering)
                            } onIgnoreAll: {
                                groupToIgnore = group
                            } onMoveAllToTrash: {
                                reviewTrash(of: group, isFiltered: isFiltering)
                            }
                        }
                    }
                }
            }
        }
    }

    private func copyFixSteps(of group: FindingGroup, isFiltered: Bool) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(group.fixSteps(title: group.check.title, defaultFix: group.check.fixHint), forType: .string)
        let message = isFiltered ? "Copied fix steps for \(group.findings.count) shown in \(group.check.inlineTitle)" : "Copied fix steps for \(group.check.inlineTitle)"
        copiedMessage = message
        AccessibilityNotification.Announcement(message).post()
    }

    private func reviewTrash(of group: FindingGroup, isFiltered: Bool) {
        guard !store.isBusy else { return }
        trashReview = TrashReview(title: group.check.inlineTitle, plan: store.trashPlan(for: group), isFiltered: isFiltered)
    }

    private func rows(_ findings: [Finding]) -> some View {
        ForEach(findings) { finding in
            FindingRow(finding: finding) { selectedFindingID = finding.id }
            if finding.id != findings.last?.id {
                Divider()
            }
        }
    }

    private var checksSection: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            HStack {
                sectionTitle("What Bluehat checks")
                Spacer(minLength: Metrics.spaceSmall)
                Text("Click one for details")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                    .padding(.trailing, Metrics.spaceTight)
                    .accessibilityHidden(true)
            }
            ChecksGrid(progress: store.checkProgress, findings: store.findings, visibleFindings: store.visibleFindings, walkedItemCount: store.walkedItemCount, walkFindingIDs: store.walkFindingIDs)
        }
    }

    private var footer: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Image(systemName: store.rulebook == nil ? "seal" : "checkmark.seal.fill")
                .foregroundStyle(store.rulebook == nil ? Palette.tertiaryText : Palette.safe)
                .accessibilityHidden(true)
            Text(store.rulebook.map { "Signed rules v" + String($0.version) } ?? "Rules are verified before every scan")
                .foregroundStyle(Palette.secondaryText)
        }
        .font(Typography.caption)
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title.uppercased())
            .font(Typography.sectionTitle)
            .foregroundStyle(Palette.secondaryText)
            .padding(.leading, Metrics.spaceTight)
            .accessibilityAddTraits(.isHeader)
    }
}

@Animatable
private struct ColumnReveal: ViewModifier {
    var width: CGFloat

    func body(content: Content) -> some View {
        content
            .frame(width: max(width, 0), alignment: .leading)
            .clipShape(Rectangle().inset(by: -Metrics.cardStrokeWidth))
    }
}
