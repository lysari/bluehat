import BluehatCore
import Foundation
import Observation
import UserNotifications

@MainActor
@Observable
final class ScanStore {
    enum Phase {
        case idle, scanning, finished
    }

    enum Trigger {
        case manual, scheduled
    }

    enum MenuBarState {
        case ready, scanning(progress: Double), safe, stoppedEarly, issues(count: Int), failed
    }

    enum FindingsTab {
        case findings, notScanned
    }

    enum InstallationError: LocalizedError {
        case changedSinceScan

        var errorDescription: String? {
            "This copy changed since the scan. Scan again, then try once more."
        }
    }

    private enum Key {
        static let lastScanAt = "lastScanAt"
    }

    private static let scheduleCheckInterval = Duration.seconds(60)

    let settings: SettingsStore
    let rulesReview = FeedReview<Rulebook>(feed: .rulebook)
    let malwareFeedReview = FeedReview<MalwareFeed>(feed: .malwareFeed)
    let appUpdate = AppUpdateReview()
    private(set) var phase = Phase.idle
    private(set) var findings: [Finding] = []
    private(set) var notScanned = NotScannedList()
    private(set) var collapsedGroups: Set<CheckKind> = []
    private(set) var collapsedNotScannedGroups: Set<NotScannedReason> = []
    var findingsTab = FindingsTab.findings
    var filter = FindingsFilter()
    private(set) var finishedAreas: Set<CheckKind> = []
    private(set) var rulebook: Rulebook?
    private(set) var notice: String?
    private(set) var failure: String?
    private(set) var scanDuration: Duration?
    private(set) var scanKind = ScanKind.normal
    private(set) var isCancelling = false
    private(set) var walkedItemCount = 0
    private(set) var walkFindingIDs: Set<Finding.ID> = []
    private(set) var isLoadingRules = false
    private(set) var runningCustomScanAt: Date?
    private(set) var history: ScanHistory
    private(set) var lastScanAt: Date? {
        didSet { UserDefaults.standard.set(lastScanAt, forKey: Key.lastScanAt) }
    }

    @ObservationIgnored private var scheduleTask: Task<Void, Never>?
    @ObservationIgnored private var cancellation: ScanCancellation?

    init(settings: SettingsStore) {
        self.settings = settings
        history = ScanHistory(limits: settings.scanLimits)
        lastScanAt = (UserDefaults.standard.object(forKey: Key.lastScanAt) as? Date).flatMap { $0 <= .now ? $0 : nil }
        scheduleTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.runScheduledScanIfDue()
                try? await Task.sleep(for: Self.scheduleCheckInterval)
            }
        }
    }

    isolated deinit {
        scheduleTask?.cancel()
    }

    var isBusy: Bool {
        phase == .scanning
    }

    var canStartScan: Bool {
        !isBusy && !appUpdate.isUpdating
    }

    var areas: [CheckKind] {
        rulebook?.areas ?? CheckKind.allCases
    }

    var checkProgress: CheckProgress {
        CheckProgress(stage: checkStage, kind: scanKind, areas: areas, finishedAreas: finishedAreas, wasStoppedAtMemoryLimit: wasStoppedAtMemoryLimit)
    }

    var wasStoppedAtMemoryLimit: Bool {
        notScanned.coverage?.wasStoppedAtMemoryLimit == true
    }

    var currentArea: CheckKind? {
        checkProgress.currentArea
    }

    var isWalkingDisk: Bool {
        checkProgress.isWalkingDisk
    }

    private var checkStage: CheckProgress.Stage {
        switch phase {
        case .idle: .idle
        case .scanning: isLoadingRules ? .loadingRules : .checking
        case .finished: .finished
        }
    }

    var progress: Double {
        let steps = areas.count + (scanKind == .deep ? 1 : 0)
        return steps == 0 ? 0 : Double(finishedAreas.count) / Double(steps)
    }

    var visibleFindings: [Finding] {
        findings.filter { !settings.isIgnored($0) }
    }

    var ignoredCount: Int {
        findings.count - visibleFindings.count
    }

    var issues: [Finding] {
        visibleFindings.filter { $0.rule.severity > .info }
    }

    var notes: [Finding] {
        visibleFindings.filter { $0.rule.severity == .info }
    }

    var showsNotScanned: Bool {
        phase == .finished && (!notScanned.isEmpty || scanKind == .deep)
    }

    var rulesExpireSoon: Bool {
        rulebook?.expiresSoon(now: .now) ?? false
    }

    var nextScheduledScan: Date? {
        settings.schedule.nextScan(after: lastScanAt, customScanAt: settings.customScanAt, now: .now)
    }

    var menuBarState: MenuBarState {
        if failure != nil { return .failed }
        switch phase {
        case .idle: return .ready
        case .scanning: return .scanning(progress: progress)
        case .finished:
            guard issues.isEmpty else { return .issues(count: issues.count) }
            return wasStoppedAtMemoryLimit ? .stoppedEarly : .safe
        }
    }

    func startAppUpdate() {
        guard !isBusy else { return }
        appUpdate.startUpdate()
    }

    func cancelScan() {
        guard isBusy, scanKind == .deep else { return }
        isCancelling = true
        cancellation?.cancel()
    }

    func scan(trigger: Trigger = .manual, kind: ScanKind = .normal) async {
        guard canStartScan else { return }
        let previous = (phase, scanKind, findings, notScanned, finishedAreas, notice, failure, scanDuration, walkFindingIDs)
        let limits = settings.scanLimits
        let cancellation = ScanCancellation()
        let activity = kind == .deep ? ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep, reason: "Deep Scan") : nil
        defer {
            activity.map(ProcessInfo.processInfo.endActivity)
            self.cancellation = nil
            isCancelling = false
            isLoadingRules = false
            runningCustomScanAt = nil
        }
        self.cancellation = cancellation
        runningCustomScanAt = trigger == .scheduled && settings.schedule == .custom ? settings.customScanAt : nil
        isLoadingRules = true
        phase = .scanning
        scanKind = kind
        resetFindingsView()
        notScanned = NotScannedList()
        walkedItemCount = 0
        walkFindingIDs = []
        failure = nil
        notice = nil
        finishedAreas = []
        do {
            async let loadedFeed = Self.loadMalwareFeed()
            let loaded = try await Self.loadRules()
            let feedResult = await loadedFeed
            let rulebook = loaded.payload.appending((try? feedResult.get().payload.rules) ?? [])
            self.rulebook = rulebook
            isLoadingRules = false
            let unsupported = loaded.payload.unsupportedRuleCount
            var messages = [
                loaded.storedError.map { "The saved rules failed verification, so the rules built into Bluehat were used. \($0.localizedDescription)" },
                Self.feedNotice(feedResult),
                unsupported == 0 ? nil : unsupported == 1 ? "1 rule needs a newer version of Bluehat and was skipped." : "\(unsupported) rules need a newer version of Bluehat and were skipped.",
                settings.scanLimitsProblem,
            ].compactMap { $0 }
            notice = messages.isEmpty ? nil : messages.joined(separator: " ")
            findings = []
            let clock = ContinuousClock()
            let start = clock.now
            let projectFolders = settings.projectFolders
            let excludedFolders = settings.excludedFolders
            let excludedPatterns = settings.excludedPatterns
            let result = await Task.detached(priority: .userInitiated) {
                Scanner(projectFolders: projectFolders, kind: kind, excludedFolders: excludedFolders, excludedPatterns: excludedPatterns, limits: limits, cancellation: cancellation).scan(rulebook) { area, areaFindings in
                    Task { @MainActor in
                        if !cancellation.isCancelled { self.finishArea(area, areaFindings) }
                    }
                } onItemsWalked: { count in
                    Task { @MainActor in self.walkedItemCount = count }
                }
            }.value
            resetFindingsView()
            if cancellation.isCancelled {
                (phase, scanKind, findings, notScanned, finishedAreas, notice, failure, scanDuration, walkFindingIDs) = previous
                let cancelled = phase == .finished ? "Deep Scan cancelled. These results are from the last finished scan." : "Deep Scan cancelled."
                notice = [notice, cancelled].compactMap { $0 }.joined(separator: " ")
                return
            }
            findings = result.findings
            walkFindingIDs = result.walkFindingIDs
            notScanned = result.notScanned
            messages += result.notices
            notice = messages.isEmpty ? nil : messages.joined(separator: " ")
            finishedAreas = Set(areas)
            scanDuration = clock.now - start
            let finishedAt = Date.now
            lastScanAt = finishedAt
            if let runningCustomScanAt {
                settings.finishCustomScan(scheduledAt: runningCustomScanAt, finishedAt: finishedAt)
            }
            phase = .finished
            recordScan(rulesVersion: rulebook.version, limits: limits, notify: trigger == .scheduled && settings.notifiesNewIssues)
        } catch {
            failure = error.localizedDescription
            phase = .idle
        }
    }

    func moveToTrash(_ installation: Installation) throws {
        guard installation.isTrashable, Scanner.installation(at: installation.path, in: Scanner.installedSoftware(limits: settings.scanLimits)) == installation else { throw InstallationError.changedSinceScan }
        try FileManager.default.trashItem(at: URL(fileURLWithPath: installation.path, isDirectory: true), resultingItemURL: nil)
        findings.removeAll { $0.rule.check == .softwareVersion && $0.path == installation.path }
    }

    func trashPlan(for group: FindingGroup) -> TrashPlan {
        TrashPlan(findings: group.findings, installs: Scanner.installedSoftware(limits: settings.scanLimits))
    }

    func moveAllToTrash(_ plan: TrashPlan) -> TrashPlan.Result? {
        guard !isBusy else { return nil }
        return plan.run { try moveToTrash($0) }
    }

    func toggleGroup(_ check: CheckKind) {
        if collapsedGroups.remove(check) == nil {
            collapsedGroups.insert(check)
        }
    }

    func toggleNotScannedGroup(_ reason: NotScannedReason) {
        if collapsedNotScannedGroups.remove(reason) == nil {
            collapsedNotScannedGroups.insert(reason)
        }
    }

    private func resetFindingsView() {
        collapsedGroups = []
        collapsedNotScannedGroups = []
        findingsTab = .findings
        filter.reset()
    }

    nonisolated private static func loadRules() async throws(RuleFeedError) -> LoadedFeed<Rulebook> {
        try RuleFeed.rulebook.load(Rulebook.self)
    }

    nonisolated private static func loadMalwareFeed() async -> Result<LoadedFeed<MalwareFeed>, RuleFeedError> {
        do {
            return .success(try RuleFeed.malwareFeed.load(MalwareFeed.self))
        } catch {
            return .failure(error)
        }
    }

    private static func feedNotice(_ result: Result<LoadedFeed<MalwareFeed>, RuleFeedError>) -> String? {
        switch result {
        case .success(let loaded):
            loaded.storedError.map { "The saved malware fingerprints failed verification, so the copy built into Bluehat was used. \($0.localizedDescription)" }
        case .failure(let error):
            "Malware fingerprints unavailable, scanning with the rules only. \(error.localizedDescription)"
        }
    }

    private func runScheduledScanIfDue() async {
        guard !isBusy, settings.schedule.isDue(lastScan: lastScanAt, customScanAt: settings.customScanAt, now: .now) else { return }
        await scan(trigger: .scheduled)
    }

    private func finishArea(_ area: CheckKind, _ areaFindings: [Finding]) {
        guard phase == .scanning else { return }
        finishedAreas.insert(area)
        findings += areaFindings
        walkedItemCount = 0
    }

    private func recordScan(rulesVersion: Int, limits: ScanLimits, notify: Bool) {
        let record = ScanRecord(date: lastScanAt ?? .now, rulesVersion: rulesVersion, duration: scanDuration.map { $0 / .seconds(1) } ?? 0, findings: visibleFindings, kind: scanKind, wasStoppedAtMemoryLimit: wasStoppedAtMemoryLimit)
        do {
            try history.append(record, limits: limits)
        } catch {
            notice = [notice, "Couldn't save scan history: \(error.localizedDescription)"].compactMap { $0 }.joined(separator: " ")
        }
        let newIssues = history.latestChanges?.new.filter { $0.severity > .info } ?? []
        guard notify, !newIssues.isEmpty else { return }
        let content = UNMutableNotificationContent()
        content.title = newIssues.count == 1 ? "Bluehat found a new issue" : "Bluehat found \(newIssues.count) new issues"
        content.body = newIssues.map(\.title).joined(separator: "\n")
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }
}
