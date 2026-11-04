import BluehatCore
import Foundation
import Observation
import ServiceManagement
import UserNotifications

@MainActor
@Observable
final class SettingsStore {
    private enum Key {
        static let schedule = "schedule"
        static let customScanAt = "customScanAt"
        static let lastCustomScanAt = "lastCustomScanAt"
        static let notifiesNewIssues = "notifiesNewIssues"
        static let hasSeenWelcome = "hasSeenWelcome"
        static let ignored = "ignoredFindings"
        static let projectFolders = "projectFolders"
        static let excludedFolders = "fullScanExcludedFolders"
        static let excludedPatterns = "fullScanExcludedPatterns"
        static let findingsLayout = "findingsLayout"
        static let keepsPanelOnTop = "keepsPanelOnTop"
        static let scanLimits = "scanLimits"
    }

    private let defaults: UserDefaults

    var schedule: ScanSchedule {
        didSet {
            defaults.set(schedule.rawValue, forKey: Key.schedule)
            guard schedule != oldValue else { return }
            customScanAt = schedule == .custom ? ScanSchedule.defaultCustomScan(after: .now) : nil
        }
    }

    private(set) var customScanAt: Date? {
        didSet { defaults.set(customScanAt, forKey: Key.customScanAt) }
    }

    private(set) var lastCustomScanAt: Date? {
        didSet { defaults.set(lastCustomScanAt, forKey: Key.lastCustomScanAt) }
    }

    var notifiesNewIssues: Bool {
        didSet {
            defaults.set(notifiesNewIssues, forKey: Key.notifiesNewIssues)
            if notifiesNewIssues { requestNotificationPermission() }
        }
    }

    var hasSeenWelcome: Bool {
        didSet { defaults.set(hasSeenWelcome, forKey: Key.hasSeenWelcome) }
    }

    var findingsLayout: FindingsLayout {
        didSet { defaults.set(findingsLayout.rawValue, forKey: Key.findingsLayout) }
    }

    var keepsPanelOnTop: Bool {
        didSet { defaults.set(keepsPanelOnTop, forKey: Key.keepsPanelOnTop) }
    }

    private(set) var ignored: [IgnoredFinding] {
        didSet {
            ignoredIDs = Set(ignored.map(\.id))
            defaults.set(try? JSONEncoder().encode(ignored), forKey: Key.ignored)
        }
    }

    private var ignoredIDs: Set<String>

    private(set) var projectFolders: [String] {
        didSet { defaults.set(projectFolders, forKey: Key.projectFolders) }
    }

    private(set) var excludedFolders: [String] {
        didSet { defaults.set(excludedFolders, forKey: Key.excludedFolders) }
    }

    private(set) var excludedPatterns: [String] {
        didSet { defaults.set(excludedPatterns, forKey: Key.excludedPatterns) }
    }

    private(set) var scanLimits: ScanLimits {
        didSet {
            defaults.set(scanLimits.savedValues, forKey: Key.scanLimits)
            scanLimitsProblem = nil
        }
    }

    private(set) var scanLimitsProblem: String?
    private(set) var launchesAtLogin = false
    private(set) var loginItemProblem: String?
    private(set) var notificationProblem: String?

    var isInstalled: Bool {
        Bundle.main.bundleURL.path().hasPrefix("/Applications/")
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let savedCustomScanAt = defaults.object(forKey: Key.customScanAt) as? Date
        customScanAt = savedCustomScanAt
        lastCustomScanAt = defaults.object(forKey: Key.lastCustomScanAt) as? Date
        schedule = ScanSchedule(savedValue: defaults.integer(forKey: Key.schedule), customScanAt: savedCustomScanAt)
        notifiesNewIssues = defaults.bool(forKey: Key.notifiesNewIssues)
        hasSeenWelcome = defaults.bool(forKey: Key.hasSeenWelcome)
        findingsLayout = defaults.string(forKey: Key.findingsLayout).flatMap(FindingsLayout.init(rawValue:)) ?? .normal
        keepsPanelOnTop = defaults.object(forKey: Key.keepsPanelOnTop) as? Bool ?? true
        let savedIgnored = defaults.data(forKey: Key.ignored).flatMap { try? JSONDecoder().decode([IgnoredFinding].self, from: $0) } ?? []
        ignored = savedIgnored
        ignoredIDs = Set(savedIgnored.map(\.id))
        projectFolders = defaults.stringArray(forKey: Key.projectFolders) ?? ProjectFolders.existingDefaults()
        excludedFolders = defaults.stringArray(forKey: Key.excludedFolders) ?? []
        excludedPatterns = (defaults.stringArray(forKey: Key.excludedPatterns) ?? []).filter { (try? ExclusionPattern(parsing: $0)) != nil }
        (scanLimits, scanLimitsProblem) = ScanLimits.load(saved: defaults.object(forKey: Key.scanLimits))
        refreshLoginItem()
    }

    func chooseCustomScan(at date: Date) {
        guard date > .now else { return }
        customScanAt = date
    }

    func finishCustomScan(scheduledAt: Date, finishedAt: Date) {
        lastCustomScanAt = finishedAt
        schedule = schedule.afterCustomScan(for: scheduledAt, customScanAt: customScanAt)
    }

    func isIgnored(_ finding: Finding) -> Bool {
        ignoredIDs.contains(finding.fingerprint)
    }

    func ignore(_ findings: [Finding]) {
        ignored = IgnoredFinding.adding(findings, to: ignored, at: .now)
    }

    func stopIgnoring(_ entry: IgnoredFinding) {
        ignored.removeAll { $0.id == entry.id }
    }

    func stopIgnoring(_ group: IgnoredFindingGroup) {
        ignored = group.removed(from: ignored)
    }

    func fillInIgnored(from rules: [Rule]) {
        let filled = IgnoredFinding.fillingIn(ignored, from: rules)
        if filled != ignored { ignored = filled }
    }

    func addProjectFolder(_ path: String) {
        guard !projectFolders.contains(path) else { return }
        projectFolders.append(path)
    }

    func removeProjectFolder(_ path: String) {
        projectFolders.removeAll { $0 == path }
    }

    func addExcludedFolder(_ path: String) throws(ExclusionPattern.Problem) {
        guard !ExclusionPattern.coversWholeDisk(folder: path) else { throw .wholeDisk }
        guard !excludedFolders.contains(path) else { return }
        excludedFolders.append(path)
    }

    func removeExcludedFolder(_ path: String) {
        excludedFolders.removeAll { $0 == path }
    }

    func addExcludedPattern(_ text: String) throws(ExclusionPattern.Problem) {
        let pattern = try ExclusionPattern(parsing: text)
        guard !pattern.isListed(inFolders: excludedFolders, patterns: excludedPatterns) else { throw .duplicate }
        excludedPatterns.append(pattern.text)
    }

    func removeExcludedPattern(_ text: String) {
        excludedPatterns.removeAll { $0 == text }
    }

    func setScanLimit(_ limit: ScanLimit, to value: Int) -> Bool {
        guard let changed = scanLimits.setting(limit, to: value) else { return false }
        scanLimits = changed
        return true
    }

    func resetScanLimit(_ limit: ScanLimit) {
        scanLimits = scanLimits.resetting(limit)
    }

    func resetAllScanLimits() {
        scanLimits = .defaults
    }

    func setLaunchesAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            loginItemProblem = nil
        } catch {
            loginItemProblem = "macOS refused the login item: \(error.localizedDescription)"
        }
        refreshLoginItem()
    }

    func refreshLoginItem() {
        let status = SMAppService.mainApp.status
        launchesAtLogin = status == .enabled
        if status == .requiresApproval {
            loginItemProblem = "Allow Bluehat in System Settings › General › Login Items."
        }
    }

    private func requestNotificationPermission() {
        Task {
            let isAllowed = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
            notificationProblem = isAllowed ? nil : "Notifications are off for Bluehat. Turn them on in System Settings › Notifications."
        }
    }
}
