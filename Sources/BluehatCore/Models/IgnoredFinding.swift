import Foundation

public struct IgnoredFinding: Codable, Sendable, Identifiable, Equatable {
    public let ruleID: String
    public let title: String
    public let detail: String
    public let fingerprint: String
    public let ignoredAt: Date
    public let check: CheckKind?
    public let severity: Severity?

    public var id: String {
        fingerprint
    }

    public init(finding: Finding, ignoredAt: Date) {
        ruleID = finding.rule.id
        title = finding.rule.title
        detail = finding.detail
        fingerprint = finding.fingerprint
        self.ignoredAt = ignoredAt
        check = finding.rule.check
        severity = finding.rule.severity
    }

    private init(_ entry: IgnoredFinding, rule: Rule) {
        ruleID = entry.ruleID
        title = entry.title
        detail = entry.detail
        fingerprint = entry.fingerprint
        ignoredAt = entry.ignoredAt
        check = rule.check
        severity = rule.severity
    }

    public static func adding(_ findings: [Finding], to entries: [IgnoredFinding], at date: Date) -> [IgnoredFinding] {
        var ids = Set(entries.map(\.id))
        return entries + findings
            .filter { ids.insert($0.fingerprint).inserted }
            .map { IgnoredFinding(finding: $0, ignoredAt: date) }
    }

    public static func fillingIn(_ entries: [IgnoredFinding], from rules: [Rule]) -> [IgnoredFinding] {
        let rulesByID = Dictionary(rules.map { ($0.id, $0) }) { first, _ in first }
        return entries.map { entry in
            guard entry.check == nil || entry.severity == nil, let rule = rulesByID[entry.ruleID] else { return entry }
            return IgnoredFinding(entry, rule: rule)
        }
    }
}
