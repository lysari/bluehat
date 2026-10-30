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
        static let notifiesNewIssues = "notifiesNewIssues"
        static let hasSeenWelcome = "hasSeenWelcome"
        static let ignored = "ignoredFindings"
    }

    private let defaults: UserDefaults

    var schedule: ScanSchedule {
        didSet { defaults.set(schedule.rawValue, forKey: Key.schedule) }
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

    private(set) var ignored: [IgnoredFinding] {
        didSet { defaults.set(try? JSONEncoder().encode(ignored), forKey: Key.ignored) }
    }

    private(set) var launchesAtLogin = false
    private(set) var loginItemProblem: String?
    private(set) var notificationProblem: String?

    var isInstalled: Bool {
        Bundle.main.bundleURL.path().hasPrefix("/Applications/")
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        schedule = ScanSchedule(rawValue: defaults.integer(forKey: Key.schedule)) ?? .off
        notifiesNewIssues = defaults.bool(forKey: Key.notifiesNewIssues)
        hasSeenWelcome = defaults.bool(forKey: Key.hasSeenWelcome)
        ignored = defaults.data(forKey: Key.ignored).flatMap { try? JSONDecoder().decode([IgnoredFinding].self, from: $0) } ?? []
        refreshLoginItem()
    }

    func isIgnored(_ finding: Finding) -> Bool {
        ignored.contains { $0.id == finding.fingerprint }
    }

    func ignore(_ finding: Finding) {
        guard !isIgnored(finding) else { return }
        ignored.append(IgnoredFinding(finding: finding, ignoredAt: .now))
    }

    func stopIgnoring(_ entry: IgnoredFinding) {
        ignored.removeAll { $0.id == entry.id }
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
