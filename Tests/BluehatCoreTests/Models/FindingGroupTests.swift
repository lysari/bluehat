import Testing
@testable import BluehatCore

struct FindingGroupTests {
    func finding(_ check: CheckKind, _ severity: Severity, _ detail: String = "x", path: String? = nil, remedy: String? = nil) -> Finding {
        let rule = Rule(id: "\(check.rawValue).\(severity.rawValue)", title: "Test", severity: severity, category: .malware, check: check, patterns: ["x"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: remedy, references: nil)
        return Finding(rule: rule, detail: detail, path: path)
    }

    @Test func fixStepsListEveryFindingWithItsPathAndFix() throws {
        let group = try #require(FindingGroup.groups(of: [
            finding(.path, .critical, "first file", path: "/Users/test/Downloads/first"),
            finding(.path, .low, "no path here"),
        ]).first)

        #expect(group.fixSteps(title: "Malware files", defaultFix: "Move it to the Trash.") == """
            Malware files: 2 findings

            How to fix:
            Move it to the Trash.

            - Critical: Test
              first file
              Path: /Users/test/Downloads/first
            - Low: Test
              no path here
            """)
    }

    @Test func fixStepsSayOneFindingInTheSingular() throws {
        let group = try #require(FindingGroup.groups(of: [finding(.process, .high)]).first)
        #expect(group.fixSteps(title: "Processes", defaultFix: "Quit it.").hasPrefix("Processes: 1 finding\n"))
    }

    @Test func fixStepsPreferEachRulesOwnRemedyAndKeepFixesInFindingOrder() throws {
        let group = try #require(FindingGroup.groups(of: [
            finding(.process, .critical, "a", remedy: "Own remedy."),
            finding(.process, .high, "b"),
            finding(.process, .medium, "c", remedy: "Own remedy."),
        ]).first)

        #expect(group.fixSteps(title: "Processes", defaultFix: "Default fix.") == """
            Processes: 3 findings

            How to fix:
            Own remedy.

            - Critical: Test
              a
            - Medium: Test
              c

            How to fix:
            Default fix.

            - High: Test
              b
            """)
    }

    @Test func fixStepsKeepAFullPathOnOneLine() throws {
        let long = "/Users/test/" + String(repeating: "folder/", count: 60) + "file"
        let group = try #require(FindingGroup.groups(of: [finding(.path, .high, path: long + "\nrm -rf ~\u{202E}")]).first)
        let text = group.fixSteps(title: "Malware files", defaultFix: "Fix.")

        #expect(text.contains("  Path: \(long) rm -rf ~"))
        #expect(!text.contains("\u{202E}"))
        #expect(!text.contains("\nrm"))
    }

    @Test func noFindingsMakeNoGroups() {
        #expect(FindingGroup.groups(of: []).isEmpty)
    }

    @Test func putsEveryFindingInTheGroupOfItsCheck() {
        let groups = FindingGroup.groups(of: [finding(.process, .high, "a"), finding(.sshKey, .high, "b"), finding(.process, .low, "c")])
        #expect(groups.map(\.findings.count) == [2, 1])
        #expect(groups[0].check == .process)
        #expect(groups[0].findings.allSatisfy { $0.rule.check == .process })
        #expect(groups[1].check == .sshKey)
        #expect(groups[1].findings.map(\.detail) == ["b"])
    }

    @Test func ordersGroupsByTheirMostSevereFinding() {
        let groups = FindingGroup.groups(of: [
            finding(.path, .low),
            finding(.process, .critical),
            finding(.sshKey, .medium),
            finding(.sshKey, .info),
        ])
        #expect(groups.map(\.check) == [.process, .sshKey, .path])
        #expect(groups.map(\.worstSeverity) == [.critical, .medium, .low])
    }

    @Test func breaksSeverityTiesInCheckKindOrder() {
        let groups = FindingGroup.groups(of: [finding(.notarization, .high), finding(.path, .high), finding(.sshKey, .high)])
        #expect(groups.map(\.check) == [.path, .sshKey, .notarization])
    }

    @Test func ordersFindingsInsideAGroupBySeverity() {
        let groups = FindingGroup.groups(of: [finding(.process, .low), finding(.process, .critical), finding(.process, .medium)])
        #expect(groups[0].findings.map(\.rule.severity) == [.critical, .medium, .low])
    }

    @Test func keepsDetectionOrderForEqualSeverity() {
        let groups = FindingGroup.groups(of: [finding(.process, .high, "first"), finding(.process, .critical, "top"), finding(.process, .high, "second")])
        #expect(groups[0].findings.map(\.detail) == ["top", "first", "second"])
    }
}
