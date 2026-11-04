import Foundation

public struct NotScannedGroup: Sendable, Identifiable {
    public let reason: NotScannedReason
    public let entries: [NotScannedEntry]
    public let totalCount: Int
    public let leftOutCount: Int

    public var id: NotScannedReason {
        reason
    }
}

public struct NotScannedList: Sendable {
    public struct Coverage: Sendable, Equatable {
        public static let otherVolumesNote = "A Deep Scan stays on the startup disk, so other volumes, such as external drives, aren't scanned."

        public let foldersRead: Int
        public let packageFilesOpened: Int
        public let unreadableFolders: Int
        public let exclusionSummary: String?

        public var summary: String {
            let covered = ["Read \(Self.counted(foldersRead, "folder"))", "opened \(Self.counted(packageFilesOpened, "package file"))"]
            let unread = unreadableFolders == 0 ? [] : ["\(Self.counted(unreadableFolders, "folder")) couldn't be read"]
            return (covered + unread).joined(separator: " · ")
        }

        private static func counted(_ count: Int, _ noun: String) -> String {
            "\(count.formatted()) \(noun)\(count == 1 ? "" : "s")"
        }
    }

    public let entries: [NotScannedEntry]
    public let totalsByReason: [NotScannedReason: Int]
    public let coverage: Coverage?

    public init() {
        self.init(entries: [], totalsByReason: [:], coverage: nil)
    }

    init(entries: [NotScannedEntry], totalsByReason: [NotScannedReason: Int], coverage: Coverage?) {
        self.entries = entries
        self.totalsByReason = totalsByReason
        self.coverage = coverage
    }

    public var totalCount: Int {
        totalsByReason.values.reduce(0, +)
    }

    public var leftOutCount: Int {
        totalCount - entries.count
    }

    public var isEmpty: Bool {
        totalsByReason.isEmpty
    }

    public var reasons: [NotScannedReason] {
        NotScannedReason.allCases.filter { totalsByReason[$0] != nil }
    }

    public var summaryLine: String? {
        guard !isEmpty else { return nil }
        return "\(totalCount.formatted()) \(totalCount == 1 ? "item" : "items") couldn't be scanned"
    }

    public func groups(matching filter: FindingsFilter) -> [NotScannedGroup] {
        let isFiltering = filter.isFilteringNotScanned
        let byReason = Dictionary(grouping: filter.entries(from: entries), by: \.reason)
        return reasons.compactMap { reason in
            let shown = byReason[reason] ?? []
            guard !isFiltering || !shown.isEmpty else { return nil }
            let total = totalsByReason[reason] ?? 0
            let kept = entries.count { $0.reason == reason }
            return NotScannedGroup(reason: reason, entries: shown, totalCount: total, leftOutCount: total - kept)
        }
    }
}
