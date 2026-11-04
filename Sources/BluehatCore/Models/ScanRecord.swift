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
    public let kind: ScanKind
    public let wasStoppedAtMemoryLimit: Bool

    public init(date: Date, rulesVersion: Int, duration: TimeInterval, findings: [Finding], kind: ScanKind = .normal, wasStoppedAtMemoryLimit: Bool = false) {
        id = UUID()
        self.kind = kind
        self.wasStoppedAtMemoryLimit = wasStoppedAtMemoryLimit
        self.date = date
        self.rulesVersion = rulesVersion
        self.duration = duration
        entries = findings.map { Entry(ruleID: $0.rule.id, title: $0.rule.title, severity: $0.rule.severity, detail: $0.detail) }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        date = try container.decode(Date.self, forKey: .date)
        rulesVersion = try container.decode(Int.self, forKey: .rulesVersion)
        duration = try container.decode(TimeInterval.self, forKey: .duration)
        entries = try container.decode([Entry].self, forKey: .entries)
        kind = (try? container.decode(ScanKind.self, forKey: .kind)) ?? .normal
        wasStoppedAtMemoryLimit = (try? container.decode(Bool.self, forKey: .wasStoppedAtMemoryLimit)) ?? false
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
            resolved: wasStoppedAtMemoryLimit ? [] : previous.entries.filter { !currentIDs.contains($0.id) }
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
