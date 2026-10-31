import Foundation

public struct ScanRecord: Codable, Sendable, Identifiable, Equatable {
    public struct Entry: Codable, Sendable, Identifiable, Equatable {
        public let ruleID: String
        public let title: String
        public let severity: Severity
        public let detail: String

        public var id: String {
            ruleID + "|" + detail
        }
    }

    public let id: UUID
    public let date: Date
    public let rulesVersion: Int
    public let duration: TimeInterval
    public let entries: [Entry]

    public init(date: Date, rulesVersion: Int, duration: TimeInterval, findings: [Finding]) {
        id = UUID()
        self.date = date
        self.rulesVersion = rulesVersion
        self.duration = duration
        entries = findings.map { Entry(ruleID: $0.rule.id, title: $0.rule.title, severity: $0.rule.severity, detail: $0.detail) }
    }

    public var issues: [Entry] {
        entries.filter { $0.severity > .info }
    }

    public func changes(since previous: ScanRecord?) -> ScanChanges {
        guard let previous else { return ScanChanges(new: [], resolved: []) }
        let previousIDs = Set(previous.entries.map(\.id))
        let currentIDs = Set(entries.map(\.id))
        return ScanChanges(
            new: entries.filter { !previousIDs.contains($0.id) },
            resolved: previous.entries.filter { !currentIDs.contains($0.id) }
        )
    }
}

public struct ScanChanges: Sendable, Equatable {
    public let new: [ScanRecord.Entry]
    public let resolved: [ScanRecord.Entry]

    public var isEmpty: Bool {
        new.isEmpty && resolved.isEmpty
    }
}
