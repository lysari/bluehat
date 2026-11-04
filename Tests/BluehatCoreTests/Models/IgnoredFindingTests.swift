import Foundation
import Testing
@testable import BluehatCore

struct IgnoredFindingTests {
    func finding(detail: String, path: String? = nil) -> Finding {
        let rule = Rule(id: "port.remote-access", title: "Remote access", severity: .info, category: .hardening, check: .listeningPort, patterns: nil, paths: nil, ports: [22], hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: path)
    }

    @Test func matchesSameRuleAndDetailAcrossScans() {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: .now)
        #expect(ignored.id == finding(detail: "Port 22 open by launchd").fingerprint)
    }

    @Test func doesNotMatchNewDetail() {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: .now)
        #expect(ignored.id != finding(detail: "Port 22 open by sshd-evil").fingerprint)
    }

    @Test func doesNotMatchSameCommandInAnotherLaunchItem() {
        let ignored = IgnoredFinding(finding: finding(detail: "/usr/bin/python3 -c x", path: "/Library/LaunchAgents/com.vendor.updater.plist"), ignoredAt: .now)
        #expect(ignored.id != finding(detail: "/usr/bin/python3 -c x", path: "/Library/LaunchAgents/com.evil.plist").fingerprint)
    }

    @Test func doesNotMatchDetailThatDiffersOnlyPastTheClip() {
        let prefix = String(repeating: "a", count: ScanLimits.defaults[.maxDetailLength])
        let known = finding(detail: prefix + " --known")
        let other = finding(detail: prefix + " --evil")
        #expect(known.detail == other.detail)
        #expect(IgnoredFinding(finding: known, ignoredAt: .now).id != other.fingerprint)
    }

    @Test func entriesSavedWithoutAFingerprintAreDiscarded() {
        let saved = Data(#"[{"ruleID": "port.remote-access", "title": "Remote access", "detail": "Port 22 open by launchd", "ignoredAt": 0}]"#.utf8)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode([IgnoredFinding].self, from: saved) }
    }

    @Test func survivesEncoding() throws {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: Date(timeIntervalSinceReferenceDate: 0))
        let decoded = try JSONDecoder().decode(IgnoredFinding.self, from: JSONEncoder().encode(ignored))
        #expect(decoded == ignored)
        #expect(decoded.check == .listeningPort)
        #expect(decoded.severity == .info)
    }

    @Test func entriesSavedBeforeGroupingStillLoad() throws {
        let saved = Data(#"[{"ruleID": "port.remote-access", "title": "Remote access", "detail": "Port 22 open by launchd", "fingerprint": "port.remote-access|abc", "ignoredAt": 0}]"#.utf8)
        let entries = try JSONDecoder().decode([IgnoredFinding].self, from: saved)

        #expect(entries.map(\.id) == ["port.remote-access|abc"])
        #expect(entries[0].check == nil)
        #expect(entries[0].severity == nil)
    }

    @Test func fillsInEntriesSavedBeforeGroupingFromTheirRule() throws {
        let saved = Data(#"[{"ruleID": "port.remote-access", "title": "Remote access", "detail": "d", "fingerprint": "a", "ignoredAt": 0}, {"ruleID": "gone", "title": "Gone", "detail": "d", "fingerprint": "b", "ignoredAt": 0}]"#.utf8)
        let entries = try JSONDecoder().decode([IgnoredFinding].self, from: saved)
        let filled = IgnoredFinding.fillingIn(entries, from: [finding(detail: "x").rule])

        #expect(filled.map(\.id) == ["a", "b"])
        #expect(filled[0].check == .listeningPort)
        #expect(filled[0].severity == .info)
        #expect(filled[0].ignoredAt == entries[0].ignoredAt)
        #expect(filled[1].check == nil)
    }

    @Test func addingSkipsEntriesAlreadyIgnoredAndRepeatsInTheBatch() {
        let known = finding(detail: "known")
        let existing = [IgnoredFinding(finding: known, ignoredAt: Date(timeIntervalSinceReferenceDate: 0))]
        let added = IgnoredFinding.adding([known, finding(detail: "new"), finding(detail: "new")], to: existing, at: Date(timeIntervalSinceReferenceDate: 1))

        #expect(added.map(\.detail) == ["known", "new"])
        #expect(added[0].ignoredAt == existing[0].ignoredAt)
        #expect(added[1].ignoredAt == Date(timeIntervalSinceReferenceDate: 1))
    }
}
