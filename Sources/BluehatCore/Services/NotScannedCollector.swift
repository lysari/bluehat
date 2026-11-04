import Foundation
import Synchronization

final class NotScannedCollector: Sendable {
    private struct Key: Hashable {
        let reason: NotScannedReason
        let location: String

        init(_ entry: NotScannedEntry) {
            reason = entry.reason
            location = entry.path ?? entry.name
        }
    }

    private struct State {
        var entries: [NotScannedEntry] = []
        var seen = Set<Key>()
        var totals: [NotScannedReason: Int] = [:]
        var coverage: NotScannedList.Coverage?
    }

    private static let bufferMultiple = 2

    private let maxEntries: Int
    private let state = Mutex(State())

    init(limits: ScanLimits = .defaults) {
        maxEntries = limits[.maxNotScannedEntries]
    }

    func add(_ entry: NotScannedEntry) {
        state.withLock { state in
            guard state.seen.insert(Key(entry)).inserted else { return }
            state.totals[entry.reason, default: 0] += 1
            state.entries.append(entry)
            guard state.entries.count >= maxEntries * Self.bufferMultiple else { return }
            state.entries = Self.mostUseful(state.entries, keeping: maxEntries)
            state.seen = Set(state.entries.map(Key.init))
        }
    }

    func add(contentsOf entries: [NotScannedEntry]) {
        entries.forEach(add)
    }

    func record(_ coverage: NotScannedList.Coverage) {
        state.withLock { $0.coverage = coverage }
    }

    func finished() -> NotScannedList {
        state.withLock { state in
            let kept = state.entries.count > maxEntries ? Self.mostUseful(state.entries, keeping: maxEntries) : state.entries
            let ordered = kept.map { (entry: $0, rank: Self.rank(of: $0)) }.sorted {
                ($0.entry.reason.rawValue, $0.rank, $0.entry.name) < ($1.entry.reason.rawValue, $1.rank, $1.entry.name)
            }
            return NotScannedList(entries: ordered.map(\.entry), totalsByReason: state.totals, coverage: state.coverage)
        }
    }

    private static func mostUseful(_ entries: [NotScannedEntry], keeping count: Int) -> [NotScannedEntry] {
        let ranked = entries.map { (entry: $0, rank: rank(of: $0), depth: ($0.path ?? "").utf8.count { $0 == UInt8(ascii: "/") }) }
        let sorted = ranked.sorted { ($0.rank, $0.depth, $0.entry.name) < ($1.rank, $1.depth, $1.entry.name) }
        return sorted.prefix(count).map(\.entry)
    }

    private static func rank(of entry: NotScannedEntry) -> Int {
        guard entry.path != nil else { return 0 }
        return entry.isInHome ? 1 : 2
    }
}
