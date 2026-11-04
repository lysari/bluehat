import Foundation
import Testing
@testable import BluehatCore

struct IgnoredFindingGroupTests {
    func finding(_ check: CheckKind, _ severity: Severity, _ detail: String = "x") -> Finding {
        let rule = Rule(id: "\(check.rawValue).\(severity.rawValue)", title: "Test", severity: severity, category: .malware, check: check, patterns: ["x"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: nil)
    }

    func entry(_ check: CheckKind, _ severity: Severity, _ detail: String = "x") -> IgnoredFinding {
        IgnoredFinding(finding: finding(check, severity, detail), ignoredAt: .now)
    }

    func savedBeforeGrouping(_ fingerprint: String) throws -> IgnoredFinding {
        try JSONDecoder().decode(IgnoredFinding.self, from: Data(#"{"ruleID": "gone", "title": "Gone", "detail": "d", "fingerprint": "\#(fingerprint)", "ignoredAt": 0}"#.utf8))
    }

    @Test func noEntriesMakeNoGroups() {
        #expect(IgnoredFindingGroup.groups(of: []).isEmpty)
    }

    @Test func usesTheSameOrderAsFindingGroups() {
        let findings = [
            finding(.notarization, .high, "a"),
            finding(.path, .low, "b"),
            finding(.path, .high, "c"),
            finding(.process, .critical, "d"),
            finding(.sshKey, .high, "e"),
            finding(.sshKey, .medium, "f"),
            finding(.sshKey, .high, "g"),
        ]
        let groups = IgnoredFindingGroup.groups(of: findings.map { IgnoredFinding(finding: $0, ignoredAt: .now) })
        let expected = FindingGroup.groups(of: findings)

        #expect(groups.map(\.check) == expected.map(\.check))
        #expect(groups.map(\.worstSeverity) == expected.map(\.worstSeverity))
        #expect(groups.map { $0.entries.map(\.detail) } == expected.map { $0.findings.map(\.detail) })
    }

    @Test func putsEntriesSavedBeforeGroupingLastInTheirSavedOrder() throws {
        let groups = IgnoredFindingGroup.groups(of: [try savedBeforeGrouping("old-1"), entry(.path, .info), try savedBeforeGrouping("old-2")])

        #expect(groups.map(\.check) == [.path, nil])
        #expect(groups[1].worstSeverity == nil)
        #expect(groups[1].entries.map(\.id) == ["old-1", "old-2"])
    }

    @Test func removingAGroupLeavesEveryOtherEntryInOrder() throws {
        let entries = [entry(.path, .high, "a"), entry(.process, .high, "b"), entry(.path, .low, "c"), entry(.sshKey, .low, "d")]
        let paths = try #require(IgnoredFindingGroup.groups(of: entries).first { $0.check == .path })

        #expect(paths.removed(from: entries).map(\.detail) == ["b", "d"])
    }

    @Test func removingTheOtherGroupLeavesKnownEntries() throws {
        let known = entry(.path, .high)
        let entries = [try savedBeforeGrouping("old"), known]
        let other = try #require(IgnoredFindingGroup.groups(of: entries).first { $0.check == nil })

        #expect(other.removed(from: entries).map(\.id) == [known.id])
    }
}
