import Foundation
import Testing
@testable import BluehatCore

struct IgnoredFindingTests {
    func finding(detail: String, path: String? = nil) -> Finding {
        let rule = Rule(id: "port.remote-access", title: "Remote access", severity: .info, category: .hardening, check: .listeningPort, patterns: nil, paths: nil, ports: [22], hashes: nil, setting: nil, summary: nil, remedy: nil, references: nil)
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
        let prefix = String(repeating: "a", count: Finding.maxDetailLength)
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
    }
}
