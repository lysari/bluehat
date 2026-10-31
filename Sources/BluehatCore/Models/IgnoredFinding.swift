import Foundation

public struct IgnoredFinding: Codable, Sendable, Identifiable, Equatable {
    public let ruleID: String
    public let title: String
    public let detail: String
    public let fingerprint: String
    public let ignoredAt: Date

    public var id: String {
        fingerprint
    }

    public init(finding: Finding, ignoredAt: Date) {
        ruleID = finding.rule.id
        title = finding.rule.title
        detail = finding.detail
        fingerprint = finding.fingerprint
        self.ignoredAt = ignoredAt
    }
}
