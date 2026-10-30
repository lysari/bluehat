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

    private enum Key {
        static let lastScanAt = "lastScanAt"
    }

    private static let scheduleCheckInterval = Duration.seconds(60)

    let settings: SettingsStore
    private(set) var phase = Phase.idle
    private(set) var findings: [Finding] = []
    private(set) var finishedAreas: Set<CheckKind> = []
    private(set) var rulebook: Rulebook?
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
        lastScanAt = UserDefaults.standard.object(forKey: Key.lastScanAt) as? Date
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
        guard let rulebook else { return CheckKind.allCases }
        return CheckKind.allCases.filter { area in rulebook.rules.contains { $0.check == area } }
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

    var rulesAreStale: Bool {
        rulebook?.isStale(now: .now) ?? false
    }

    var nextScheduledScan: Date? {
        settings.schedule.nextScan(after: lastScanAt, now: .now)
    }

    var menuBarSymbol: String {
        issues.contains { $0.rule.severity >= .medium } ? "exclamationmark.shield.fill" : "shield.lefthalf.filled"
    }

    func scan(trigger: Trigger = .manual) async {
        guard !isBusy else { return }
        phase = .loadingRules
        failure = nil
        notice = nil
        do {
            let loaded = try await RuleFeed().load()
            rulebook = loaded.rulebook
            let unsupported = loaded.rulebook.unsupportedRuleCount
            let messages = [
                loaded.remoteError.map { "Using last verified rules. \($0.localizedDescription)" },
                unsupported == 0 ? nil : unsupported == 1 ? "1 rule needs a newer version of Bluehat and was skipped." : "\(unsupported) rules need a newer version of Bluehat and were skipped.",
            ].compactMap { $0 }
            notice = messages.isEmpty ? nil : messages.joined(separator: " ")
            findings = []
            finishedAreas = []
            phase = .scanning
            let rulebook = loaded.rulebook
            let clock = ContinuousClock()
            let start = clock.now
            let sortedFindings = await Task.detached(priority: .userInitiated) {
                Scanner().scan(rulebook) { area, areaFindings in
                    Task { @MainActor in self.finishArea(area, areaFindings) }
                }
            }.value
            findings = sortedFindings
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
