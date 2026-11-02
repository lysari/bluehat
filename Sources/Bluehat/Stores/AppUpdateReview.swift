import AppKit
import BluehatCore
import Foundation
import Observation

@MainActor
@Observable
final class AppUpdateReview {
    enum Status {
        case notChecked, upToDate, available(AppRelease), failed(AppUpdateError)
    }

    enum Activity: Equatable {
        case checking, downloading(received: Int, total: Int), installing, relaunching
    }

    private static let launchSettleTime = Duration.seconds(2)

    let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    private(set) var status = Status.notChecked
    private(set) var activity: Activity?
    private(set) var installRefusal: AppUpdateError?
    private(set) var updateProblem: AppUpdateError?
    @ObservationIgnored private var updateTask: Task<Void, Never>?

    private var runningVersion: SoftwareVersion? {
        currentVersion.flatMap(SoftwareVersion.init(appRelease:))
    }

    var canCheck: Bool {
        activity == nil && runningVersion != nil
    }

    var isUpdating: Bool {
        activity != nil && activity != .checking
    }

    func check() async {
        guard canCheck, let runningVersion else { return }
        activity = .checking
        updateProblem = nil
        installRefusal = nil
        do throws(AppUpdateError) {
            switch try await AppUpdater.standard.check(currentVersion: runningVersion) {
            case .upToDate:
                status = .upToDate
            case .available(let release):
                installRefusal = AppUpdater.standard.installRefusal(for: release, installer: .running(version: runningVersion))
                status = .available(release)
            }
        } catch {
            status = .failed(error)
        }
        activity = nil
    }

    func startUpdate() {
        guard activity == nil, case .available(let release) = status, let runningVersion else { return }
        updateProblem = nil
        activity = .downloading(received: 0, total: 0)
        updateTask = Task { await update(to: release, installer: .running(version: runningVersion)) }
    }

    func cancelDownload() {
        guard case .downloading = activity else { return }
        updateTask?.cancel()
    }

    private func update(to release: AppRelease, installer: AppInstaller) async {
        do throws(AppUpdateError) {
            let replaced = try await AppUpdater.standard.update(release, installer: installer) { phase in
                Task { @MainActor [weak self] in self?.apply(phase) }
            }
            activity = .relaunching
            try await relaunch(replaced)
            NSApp.terminate(nil)
        } catch {
            if error != .cancelled { updateProblem = error }
            activity = nil
        }
    }

    private func apply(_ phase: AppUpdatePhase) {
        guard isUpdating, activity != .relaunching else { return }
        switch phase {
        case .downloading(let received, let total): activity = .downloading(received: received, total: total)
        case .installing: activity = .installing
        }
    }

    private func relaunch(_ replaced: ReplacedApp) async throws(AppUpdateError) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        configuration.addsToRecentItems = false
        let launched = try? await NSWorkspace.shared.openApplication(at: replaced.app, configuration: configuration)
        try? await Task.sleep(for: Self.launchSettleTime)
        guard let launched, !launched.isTerminated else {
            try replaced.rollBack()
            throw .launchFailed
        }
        replaced.commit()
    }
}
