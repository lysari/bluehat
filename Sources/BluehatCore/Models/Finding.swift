import Foundation

public struct Finding: Sendable, Identifiable {
    public let id = UUID()
    public let rule: Rule
    public let detail: String
    public let path: String?

    public var fingerprint: String {
        Self.fingerprint(ruleID: rule.id, detail: detail)
    }

    public static func fingerprint(ruleID: String, detail: String) -> String {
        ruleID + "|" + detail
    }
}
