import Foundation
import Testing
@testable import BluehatCore

struct FindingsFilterTests {
    func finding(_ id: String = "rule.one", title: String = "Hidden code", severity: Severity = .high, check: CheckKind = .projectFile, detail: String = "Line 1", path: String? = nil) -> Finding {
        let rule = Rule(id: id, title: title, severity: severity, category: .malware, check: check, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: path)
    }

    func filter(search: String = "", severities: Set<Severity> = [], checks: Set<CheckKind> = [], reasons: Set<NotScannedReason> = []) -> FindingsFilter {
        var filter = FindingsFilter()
        filter.search = search
        filter.severities = severities
        filter.checks = checks
        filter.reasons = reasons
        return filter
    }

    @Test func anEmptyFilterShowsEverything() {
        let findings = [finding(), finding("rule.two")]
        #expect(FindingsFilter().findings(from: findings).count == 2)
        #expect(!FindingsFilter().isFilteringFindings)
        #expect(!FindingsFilter().isFilteringNotScanned)
    }

    @Test func blankSearchIsNotASearch() {
        #expect(!filter(search: "   \n").isFilteringFindings)
        #expect(filter(search: "   ").findings(from: [finding()]).count == 1)
    }

    @Test(arguments: [
        ("HIDDEN", true),
        ("line 1", true),
        ("rule.ONE", true),
        ("/tmp/app", true),
        ("hidden line", true),
        ("nothing-like-this", false),
        ("hidden nothing-like-this", false),
    ])
    func searchLooksAtTitleDetailRuleNameAndPath(search: String, matches: Bool) {
        let found = filter(search: search).findings(from: [finding(path: "/tmp/app/config.js")])
        #expect(found.count == (matches ? 1 : 0))
    }

    @Test(arguments: ["cafe", "CAFE", "café", "CAFÉ", "cafe\u{301}"])
    func searchIgnoresCaseAndDiacritics(search: String) {
        #expect(filter(search: search).findings(from: [finding(title: "Café payload")]).count == 1)
        #expect(filter(search: search).findings(from: [finding(title: "Cafe\u{301} payload")]).count == 1)
        #expect(filter(search: search).entries(from: [NotScannedEntry(reason: .noPermission, path: "/tmp/Café")]).count == 1)
    }

    @Test func searchFindsTextInOtherScripts() {
        #expect(filter(search: "ឯកសារ").entries(from: [NotScannedEntry(reason: .noPermission, path: "/tmp/ឯកសារ")]).count == 1)
    }

    @Test func aTildeInTheSearchFindsPathsInHome() {
        let inHome = NotScannedEntry(reason: .noPermission, path: NSHomeDirectory() + "/Library/Mail")
        let elsewhere = NotScannedEntry(reason: .noPermission, path: "/Library/Mail")
        #expect(filter(search: "~/Library").entries(from: [inHome, elsewhere]).map(\.path) == [inHome.path])
        #expect(filter(search: "~/Library").findings(from: [finding(path: NSHomeDirectory() + "/Library/x")]).count == 1)
    }

    @Test func notScannedSearchLooksAtPathAndReason() {
        let entries = [
            NotScannedEntry(reason: .noPermission, path: "/Library/Bluetooth"),
            NotScannedEntry.oversized(path: "/tmp/package.json", size: 1_091_575, limit: 1_000_000),
            NotScannedEntry(reason: .filePatternNotOpened, summary: "*.config.toml"),
        ]
        #expect(filter(search: "bluetooth").entries(from: entries).count == 1)
        #expect(filter(search: "permission").entries(from: entries).count == 1)
        #expect(filter(search: "size limit").entries(from: entries).count == 1)
        #expect(filter(search: "1.09").entries(from: entries).count == 1)
        #expect(filter(search: "toml").entries(from: entries).count == 1)
    }

    @Test func severityAndCheckFiltersCombineWithSearch() {
        let findings = [
            finding("a", title: "Alpha", severity: .critical, check: .path),
            finding("b", title: "Beta", severity: .low, check: .path),
            finding("c", title: "Alpha again", severity: .critical, check: .outbound),
            finding("d", title: "Alpha low", severity: .low, check: .outbound),
        ]
        #expect(filter(severities: [.critical]).findings(from: findings).map(\.rule.id) == ["a", "c"])
        #expect(filter(checks: [.path]).findings(from: findings).map(\.rule.id) == ["a", "b"])
        #expect(filter(severities: [.critical, .low], checks: [.outbound]).findings(from: findings).map(\.rule.id) == ["c", "d"])
        #expect(filter(search: "alpha", severities: [.low]).findings(from: findings).map(\.rule.id) == ["d"])
        #expect(filter(search: "alpha", severities: [.low], checks: [.path]).findings(from: findings).isEmpty)
    }

    @Test func aFilterForOneTabDoesNotCountOnTheOther() {
        #expect(filter(reasons: [.noPermission]).isFilteringNotScanned)
        #expect(!filter(reasons: [.noPermission]).isFilteringFindings)
        #expect(filter(severities: [.low]).isFilteringFindings)
        #expect(!filter(severities: [.low]).isFilteringNotScanned)
        #expect(filter(search: "x").isFilteringFindings && filter(search: "x").isFilteringNotScanned)
    }

    @Test func aReasonFilterCombinesWithSearchAndGroupsKeepTheirTotals() {
        let collector = NotScannedCollector()
        collector.add(NotScannedEntry(reason: .noPermission, path: "/Library/Bluetooth"))
        collector.add(NotScannedEntry(reason: .noPermission, path: "/Library/Trial"))
        collector.add(NotScannedEntry(reason: .couldNotRead, path: "/Library/Bluetooth/deep"))
        let list = collector.finished()

        let groups = list.groups(matching: filter(search: "bluetooth", reasons: [.noPermission]))

        #expect(groups.map(\.reason) == [.noPermission])
        #expect(groups[0].entries.compactMap(\.path) == ["/Library/Bluetooth"])
        #expect(groups[0].totalCount == 2)
        #expect(list.totalCount == 3)
        #expect(list.groups(matching: filter(search: "nothing-like-this")).isEmpty)
    }

    @Test func resetClearsEverythingSoAStaleFilterCannotHideANewThreat() {
        var stale = filter(search: "old", severities: [.low], checks: [.path], reasons: [.cloudOnly])
        let newThreat = finding("new", title: "New threat", severity: .critical, check: .outbound)
        #expect(stale.findings(from: [newThreat]).isEmpty)

        stale.reset()

        #expect(stale == FindingsFilter())
        #expect(!stale.isFilteringFindings)
        #expect(!stale.isFilteringNotScanned)
        #expect(stale.findings(from: [newThreat]).map(\.rule.id) == ["new"])
    }

    @Test func groupActionsOnAFilteredListSeeOnlyTheShownFindings() {
        let findings = [
            finding("a", title: "Alpha", check: .path, detail: "one"),
            finding("b", title: "Beta", check: .path, detail: "two"),
            finding("c", title: "Alpha", check: .outbound, detail: "three"),
        ]
        let groups = FindingGroup.groups(of: filter(search: "alpha").findings(from: findings))
        let path = groups.first { $0.check == .path }
        #expect(path?.findings.map(\.rule.id) == ["a"])
        #expect(path?.fixSteps(title: "Malware files", defaultFix: "Fix").hasPrefix("Malware files: 1 finding") == true)
    }

    @Test func filteringNeverChangesTheFindingsItWasGiven() {
        let findings = [finding("a", severity: .critical), finding("b", severity: .low)]
        _ = filter(severities: [.low]).findings(from: findings)
        #expect(findings.map(\.rule.id) == ["a", "b"])
        #expect(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: findings, kind: .normal).issues.count == 2)
    }

    @Test func filteringTenThousandEntriesStaysResponsive() {
        let collector = NotScannedCollector()
        for index in 0..<10_000 {
            collector.add(NotScannedEntry(reason: index % 3 == 0 ? .noPermission : .couldNotRead, path: "/Library/Application Support/Some App/folder \(index)/inner"))
        }
        let list = collector.finished()
        let clock = ContinuousClock()
        var shown = 0
        let elapsed = clock.measure {
            shown = list.groups(matching: filter(search: "folder 99")).reduce(0) { $0 + $1.entries.count }
        }
        #expect(shown == 280)
        #expect(elapsed < .seconds(1))
    }

    @Test func aSixThousandEntryListKeepsEveryEntryInItsGroup() {
        let collector = NotScannedCollector()
        for index in 0..<6_000 {
            collector.add(NotScannedEntry(reason: NotScannedReason.allCases[index % 3], path: "/tmp/stub/\(index)"))
        }
        let groups = collector.finished().groups(matching: FindingsFilter())
        #expect(groups.count == 3)
        #expect(groups.reduce(0) { $0 + $1.entries.count } == 6_000)
    }
}
