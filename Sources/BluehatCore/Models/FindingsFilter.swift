import Foundation

public struct FindingsFilter: Sendable, Equatable {
    public var search = ""
    public var severities: Set<Severity> = []
    public var checks: Set<CheckKind> = []
    public var reasons: Set<NotScannedReason> = []

    public init() {}

    public var isFilteringFindings: Bool {
        !searchWords.isEmpty || !severities.isEmpty || !checks.isEmpty
    }

    public var isFilteringNotScanned: Bool {
        !searchWords.isEmpty || !reasons.isEmpty
    }

    public mutating func reset() {
        self = FindingsFilter()
    }

    public func findings(from findings: [Finding]) -> [Finding] {
        guard isFilteringFindings else { return findings }
        let words = searchWords
        return findings.filter { finding in
            (severities.isEmpty || severities.contains(finding.rule.severity))
                && (checks.isEmpty || checks.contains(finding.rule.check))
                && words.allSatisfy { word in
                    Self.contains(finding.rule.title, word) || Self.contains(finding.detail, word) || Self.contains(finding.rule.id, word) || finding.path.map { Self.contains($0, word) } == true
                }
        }
    }

    public func entries(from entries: [NotScannedEntry]) -> [NotScannedEntry] {
        guard isFilteringNotScanned else { return entries }
        let words = searchWords
        return entries.filter { entry in
            (reasons.isEmpty || reasons.contains(entry.reason))
                && words.allSatisfy { word in
                    Self.contains(entry.name, word) || Self.contains(entry.explanation, word) || Self.contains(entry.reason.title, word) || entry.path.map { Self.contains($0, word) } == true
                }
        }
    }

    private var searchWords: [String] {
        search.split(whereSeparator: \.isWhitespace).map { $0.hasPrefix("~") ? NSString(string: String($0)).expandingTildeInPath : String($0) }
    }

    private static func contains(_ text: String, _ word: String) -> Bool {
        text.range(of: word, options: [.caseInsensitive, .diacriticInsensitive]) != nil
    }
}
