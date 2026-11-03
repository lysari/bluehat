import Foundation
import Security
import Synchronization

final class SignatureChecks: Sendable {
    enum Outcome<Value: Sendable>: Sendable {
        case finished(Value?)
        case stuck
        case skipped
    }

    static let openTimeout: TimeInterval = 20
    static let checkTimeout: TimeInterval = 300
    static let maxStuckPathsPerScan = 5
    static let stillBlockedPaths = Mutex<Set<String>>([])

    let openLimit: TimeInterval
    let checkLimit: TimeInterval
    let maxStuckPaths: Int
    private let progress = Mutex<(stuck: Set<String>, skipped: Set<String>)>(([], []))

    init(openLimit: TimeInterval = openTimeout, checkLimit: TimeInterval = checkTimeout, maxStuckPaths: Int = maxStuckPathsPerScan) {
        self.openLimit = openLimit
        self.checkLimit = checkLimit
        self.maxStuckPaths = maxStuckPaths
    }

    var stuckPaths: Set<String> {
        progress.withLock { $0.stuck }
    }

    var skippedPaths: Set<String> {
        progress.withLock { $0.skipped }
    }

    var skippedNotice: String? {
        let (stuck, skipped) = progress.withLock { ($0.stuck.count, $0.skipped.count) }
        guard skipped > 0 else { return nil }
        return "Signature checks stopped after \(stuck == 1 ? "1 item" : "\(stuck.formatted()) items") couldn't be read and skipped \(skipped.formatted()) more."
    }

    func inspect<Value: Sendable>(_ url: URL, _ inspection: @escaping @Sendable (SecStaticCode) -> Value?) -> Outcome<Value> {
        let path = url.path
        if Self.stillBlockedPaths.withLock({ $0.contains(path) }) {
            progress.withLock { _ = $0.stuck.insert(path) }
            return .stuck
        }
        let isPastLimit = progress.withLock { progress in
            guard progress.stuck.count >= maxStuckPaths, !progress.stuck.contains(path) else { return false }
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
        guard opened.wait(timeout: .now() + openLimit) == .success, finished.wait(timeout: .now() + checkLimit) == .success else {
            Self.stillBlockedPaths.withLock { blocked in
                if !isDone.withLock({ $0 }) { blocked.insert(path) }
            }
            progress.withLock { _ = $0.stuck.insert(path) }
            return .stuck
        }
        return .finished(result.withLock { $0 })
    }
}
