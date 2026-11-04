public struct FindingGroup: Sendable, Identifiable {
    public let check: CheckKind
    public let worstSeverity: Severity
    public let findings: [Finding]

    public var id: CheckKind {
        check
    }

    public static func groups(of findings: [Finding]) -> [FindingGroup] {
        ordered(findings, check: \.rule.check, severity: \.rule.severity).map {
            FindingGroup(check: $0.check, worstSeverity: $0.worstSeverity, findings: $0.items)
        }
    }

    static func ordered<Item>(_ items: [Item], check: (Item) -> CheckKind, severity: (Item) -> Severity) -> [(check: CheckKind, worstSeverity: Severity, items: [Item])] {
        let bySeverity = items.sorted { severity($0) > severity($1) }
        let byCheck = Dictionary(grouping: bySeverity, by: check)
        return CheckKind.allCases
            .compactMap { check in
                byCheck[check].map { (check: check, worstSeverity: severity($0[0]), items: $0) }
            }
            .sorted { $0.worstSeverity > $1.worstSeverity }
    }

    public func fixSteps(title: String, defaultFix: String) -> String {
        var fixes: [String] = []
        var findingsByFix: [String: [Finding]] = [:]
        for finding in findings {
            let fix = finding.rule.remedy ?? defaultFix
            if findingsByFix[fix] == nil { fixes.append(fix) }
            findingsByFix[fix, default: []].append(finding)
        }
        let sections = fixes.map { fix in
            let entries = findingsByFix[fix, default: []].map(Self.fixStepsEntry)
            return "How to fix:\n\(fix)\n\n\(entries.joined(separator: "\n"))"
        }
        let heading = "\(title): \(findings.count) \(findings.count == 1 ? "finding" : "findings")"
        return ([heading] + sections).joined(separator: "\n\n")
    }

    private static func fixStepsEntry(_ finding: Finding) -> String {
        var lines = ["- \(finding.rule.severity.rawValue.capitalized): \(finding.rule.title)", "  \(finding.detail)"]
        if let path = finding.path {
            lines.append("  Path: \(Finding.displayable(path))")
        }
        return lines.joined(separator: "\n")
    }
}
