import Foundation
import Security
import Synchronization

final class SignatureChecks: Sendable {
    enum Outcome<Value: Sendable>: Sendable {
        case finished(Value?)
        case stuck
        case skipped
    }

    static let cancellationPollInterval: TimeInterval = 0.2
    static let stillBlockedPaths = Mutex<Set<String>>([])

    let openLimit: TimeInterval
    let checkLimit: TimeInterval
    let maxStuckPaths: Int
    let cancellation: ScanCancellation
    private let progress = Mutex<(stuck: Set<String>, skipped: Set<String>)>(([], []))

    init(openLimit: TimeInterval, checkLimit: TimeInterval, maxStuckPaths: Int, cancellation: ScanCancellation = ScanCancellation()) {
        self.openLimit = openLimit
        self.checkLimit = checkLimit
        self.maxStuckPaths = maxStuckPaths
        self.cancellation = cancellation
    }

    convenience init(limits: ScanLimits = .defaults, cancellation: ScanCancellation = ScanCancellation()) {
        self.init(openLimit: TimeInterval(limits[.signatureOpenTimeout]), checkLimit: TimeInterval(limits[.signatureCheckTimeout]), maxStuckPaths: limits[.maxStuckPathsPerScan], cancellation: cancellation)
    }

    var stuckPaths: Set<String> {
        progress.withLock { $0.stuck }
    }

    var skippedPaths: Set<String> {
        progress.withLock { $0.skipped }
    }

    func notScannedEntries(limits: ScanLimits = .defaults) -> [NotScannedEntry] {
        let (stuck, skipped) = progress.withLock { ($0.stuck, $0.skipped) }
        let stoppedAfter = stuck.count == 1 ? "1 item" : "\(stuck.count.formatted()) items"
        return stuck.sorted().map { NotScannedEntry(reason: .timedOut, path: $0, explanation: "Reading it never finished, so its signature and notarization weren't checked", limits: limits) }
            + skipped.sorted().map { NotScannedEntry(reason: .signatureCheckSkipped, path: $0, explanation: "Signature checks stopped after \(stoppedAfter) couldn't be read", limits: limits) }
    }

    func inspect<Value: Sendable>(_ url: URL, _ inspection: @escaping @Sendable (SecStaticCode) -> Value?) -> Outcome<Value> {
        let path = url.path
        if Self.stillBlockedPaths.withLock({ $0.contains(path) }) {
            progress.withLock { _ = $0.stuck.insert(path) }
            return .stuck
        }
        let isPastLimit = progress.withLock { progress in
            guard cancellation.isCancelled || (progress.stuck.count >= maxStuckPaths && !progress.stuck.contains(path)) else { return false }
            progress.skipped.insert(path)
            return true
        }
        if isPastLimit { return .skipped }

        let opened = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let result = Mutex<Value?>(nil)
        let isDone = Mutex(false)
        let thread = Thread {
            var staticCode: SecStaticCode?
            let status = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
            opened.signal()
            if status == errSecSuccess, let staticCode {
                let value = inspection(staticCode)
                result.withLock { $0 = value }
            }
            Self.stillBlockedPaths.withLock { blocked in
                blocked.remove(path)
                isDone.withLock { $0 = true }
            }
            finished.signal()
        }
        thread.qualityOfService = .userInitiated
        thread.start()
        guard wait(for: opened, limit: openLimit), wait(for: finished, limit: checkLimit) else {
            Self.stillBlockedPaths.withLock { blocked in
                if !isDone.withLock({ $0 }) { blocked.insert(path) }
            }
            progress.withLock { _ = $0.stuck.insert(path) }
            return .stuck
        }
        return .finished(result.withLock { $0 })
    }

    private func wait(for semaphore: DispatchSemaphore, limit: TimeInterval) -> Bool {
        let deadline = DispatchTime.now() + limit
        while !cancellation.isCancelled {
            if semaphore.wait(timeout: min(deadline, .now() + Self.cancellationPollInterval)) == .success { return true }
            if DispatchTime.now() >= deadline { return false }
        }
        return false
    }
}
