import BluehatCore
import Foundation
import Observation
import UserNotifications

@MainActor
@Observable
final class ScanStore {
    enum Phase {
        case idle, loadingRules, scanning, finished
    }

    enum Trigger {
        case manual, scheduled
    }

    enum MenuBarState {
        case ready, scanning(progress: Double), safe, issues(count: Int), failed
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
    private(set) var phase = Phase.idle
    private(set) var findings: [Finding] = []
    private(set) var finishedAreas: Set<CheckKind> = []
    private(set) var rulebook: Rulebook?
    private(set) var malwareFeed: MalwareFeed?
    private(set) var notice: String?
    private(set) var failure: String?
    private(set) var scanDuration: Duration?
    private(set) var history = ScanHistory()
    private(set) var lastScanAt: Date? {
        didSet { UserDefaults.standard.set(lastScanAt, forKey: Key.lastScanAt) }
    }

    @ObservationIgnored private var scheduleTask: Task<Void, Never>?

    init(settings: SettingsStore) {
        self.settings = settings
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
        phase == .loadingRules || phase == .scanning
    }

    var areas: [CheckKind] {
        rulebook?.areas ?? CheckKind.allCases
    }

    var currentArea: CheckKind? {
        phase == .scanning ? areas.first { !finishedAreas.contains($0) } : nil
    }

    var progress: Double {
        areas.isEmpty ? 0 : Double(finishedAreas.count) / Double(areas.count)
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

    var rulesExpireSoon: Bool {
        rulebook?.expiresSoon(now: .now) ?? false
    }

    var nextScheduledScan: Date? {
        settings.schedule.nextScan(after: lastScanAt, now: .now)
    }

    var menuBarState: MenuBarState {
        if failure != nil { return .failed }
        switch phase {
        case .idle: return .ready
        case .loadingRules: return .scanning(progress: 0)
        case .scanning: return .scanning(progress: progress)
        case .finished: return issues.isEmpty ? .safe : .issues(count: issues.count)
        }
    }

    func scan(trigger: Trigger = .manual) async {
        guard !isBusy else { return }
        phase = .loadingRules
        failure = nil
        notice = nil
        do {
            async let loadedFeed = Self.loadMalwareFeed()
            let loaded = try await RuleFeed.rulebook.load(Rulebook.self)
            let feedResult = await loadedFeed
            malwareFeed = try? feedResult.get().payload
            let rulebook = loaded.payload.appending(malwareFeed?.rules ?? [])
            self.rulebook = rulebook
            let unsupported = loaded.payload.unsupportedRuleCount
            var messages = [
                loaded.remoteError.map { "Using last verified rules. \($0.localizedDescription)" },
                Self.feedNotice(feedResult),
                unsupported == 0 ? nil : unsupported == 1 ? "1 rule needs a newer version of Bluehat and was skipped." : "\(unsupported) rules need a newer version of Bluehat and were skipped.",
            ].compactMap { $0 }
            notice = messages.isEmpty ? nil : messages.joined(separator: " ")
            findings = []
            finishedAreas = []
            phase = .scanning
            let clock = ContinuousClock()
            let start = clock.now
            let projectFolders = settings.projectFolders
            let result = await Task.detached(priority: .userInitiated) {
                Scanner(projectFolders: projectFolders).scan(rulebook) { area, areaFindings in
                    Task { @MainActor in self.finishArea(area, areaFindings) }
                }
            }.value
            findings = result.findings
            messages += result.notices
            notice = messages.isEmpty ? nil : messages.joined(separator: " ")
            finishedAreas = Set(areas)
            scanDuration = clock.now - start
            lastScanAt = .now
            phase = .finished
            recordScan(rulesVersion: rulebook.version, notify: trigger == .scheduled && settings.notifiesNewIssues)
        } catch {
            failure = error.localizedDescription
            phase = .idle
        }
    }

    func moveToTrash(_ installation: Installation) throws {
        guard installation.isTrashable, Scanner.installation(at: installation.path) == installation else { throw InstallationError.changedSinceScan }
        try FileManager.default.trashItem(at: URL(fileURLWithPath: installation.path, isDirectory: true), resultingItemURL: nil)
        findings.removeAll { $0.rule.check == .softwareVersion && $0.path == installation.path }
    }

    nonisolated private static func loadMalwareFeed() async -> Result<LoadedFeed<MalwareFeed>, RuleFeedError> {
        do {
            return .success(try await RuleFeed.malwareFeed.load(MalwareFeed.self))
        } catch {
            return .failure(error)
        }
    }

    private static func feedNotice(_ result: Result<LoadedFeed<MalwareFeed>, RuleFeedError>) -> String? {
        switch result {
        case .success(let loaded):
            loaded.remoteError.map { "Using last verified malware fingerprints. \($0.localizedDescription)" }
        case .failure(let error):
            "Malware fingerprints unavailable, scanning with the rules only. \(error.localizedDescription)"
        }
    }

    private func runScheduledScanIfDue() async {
        guard !isBusy, settings.schedule.isDue(lastScan: lastScanAt, now: .now) else { return }
        await scan(trigger: .scheduled)
    }

    private func finishArea(_ area: CheckKind, _ areaFindings: [Finding]) {
        guard phase == .scanning else { return }
        finishedAreas.insert(area)
        findings += areaFindings
    }

    private func recordScan(rulesVersion: Int, notify: Bool) {
        let record = ScanRecord(date: lastScanAt ?? .now, rulesVersion: rulesVersion, duration: scanDuration.map { $0 / .seconds(1) } ?? 0, findings: visibleFindings)
        do {
            try history.append(record)
        } catch {
            notice = "Couldn't save scan history: \(error.localizedDescription)"
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
