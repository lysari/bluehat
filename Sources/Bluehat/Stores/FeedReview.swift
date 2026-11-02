import AppKit
import BluehatCore
import Foundation
import Observation

@MainActor
@Observable
final class FeedReview<Payload: SignedPayload> {
    enum Status {
        case notChecked, upToDate(remote: Payload), available(FeedUpdate<Payload>), failed(String)
    }

    private let feed: RuleFeed
    private(set) var local: LoadedFeed<Payload>?
    private(set) var localProblem: String?
    private(set) var status = Status.notChecked
    private(set) var isBusy = false
    private(set) var actionProblem: String?
    @ObservationIgnored private var fullFileDirectory: URL?

    init(feed: RuleFeed) {
        self.feed = feed
    }

    var isUpdateAvailable: Bool {
        if case .available = status { true } else { false }
    }

    var isUpToDate: Bool {
        if case .upToDate = status { true } else { false }
    }

    var remote: Payload? {
        switch status {
        case .upToDate(let remote): remote
        case .available(let update): update.payload
        case .notChecked, .failed: nil
        }
    }

    func loadLocal() async {
        let result = await Self.run { [feed] () throws(RuleFeedError) in try feed.localCopy(Payload.self) }
        switch result {
        case .success(let copy):
            local = copy
            localProblem = nil
        case .failure(let error):
            local = nil
            localProblem = error.localizedDescription
        }
    }

    func check() async {
        guard !isBusy else { return }
        isBusy = true
        actionProblem = nil
        removeFullFile()
        do throws(RuleFeedError) {
            switch try await feed.check(Payload.self) {
            case .upToDate(let remote): status = .upToDate(remote: remote)
            case .available(let update): status = .available(update)
            }
        } catch {
            status = .failed(error.localizedDescription)
        }
        await loadLocal()
        isBusy = false
    }

    func accept() async {
        guard !isBusy, case .available(let update) = status else { return }
        isBusy = true
        actionProblem = nil
        let result = await Self.run { [feed] () throws(RuleFeedError) in try feed.accept(update) }
        switch result {
        case .success:
            status = .upToDate(remote: update.payload)
            removeFullFile()
        case .failure(let error):
            actionProblem = error.localizedDescription
        }
        await loadLocal()
        isBusy = false
    }

    func decline() {
        status = .notChecked
        actionProblem = nil
        removeFullFile()
    }

    func openFullFile() async {
        guard !isBusy, case .available(let update) = status else { return }
        isBusy = true
        actionProblem = nil
        removeFullFile()
        let directory = FileManager.default.temporaryDirectory.appending(component: "Bluehat-review-\(UUID().uuidString)")
        let file = directory.appending(component: update.fileName)
        let isWritten = await Task.detached {
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try update.fullFile.write(to: file, options: .atomic)
                return true
            } catch {
                return false
            }
        }.value
        fullFileDirectory = directory
        if !isWritten || !NSWorkspace.shared.open(file) {
            actionProblem = "The full file could not be opened."
        }
        isBusy = false
    }

    private func removeFullFile() {
        guard let fullFileDirectory else { return }
        try? FileManager.default.removeItem(at: fullFileDirectory)
        self.fullFileDirectory = nil
    }

    nonisolated private static func run<Success: Sendable>(_ work: @Sendable () throws(RuleFeedError) -> Success) async -> Result<Success, RuleFeedError> {
        do throws(RuleFeedError) {
            return .success(try work())
        } catch {
            return .failure(error)
        }
    }
}
