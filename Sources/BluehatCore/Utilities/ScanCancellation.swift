import Synchronization

public final class ScanCancellation: Sendable {
    private let state = Mutex(false)

    public init() {}

    /// True once `cancel()` was called. A scan that sees it stops early, and its result is incomplete, so don't treat it as finished.
    public var isCancelled: Bool {
        state.withLock { $0 }
    }

    /// Asks the scan holding this object to stop. Safe from any thread; the scan returns at its next check.
    public func cancel() {
        state.withLock { $0 = true }
    }
}
