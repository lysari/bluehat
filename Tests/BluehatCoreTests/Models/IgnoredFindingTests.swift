import Foundation
import Testing
@testable import BluehatCore

struct IgnoredFindingTests {
    func finding(detail: String) -> Finding {
        let rule = Rule(id: "port.remote-access", title: "Remote access", severity: .info, category: .hardening, check: .listeningPort, patterns: nil, paths: nil, ports: [22], hashes: nil, setting: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: nil)
    }

    @Test func matchesSameRuleAndDetailAcrossScans() {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: .now)
        #expect(ignored.id == finding(detail: "Port 22 open by launchd").fingerprint)
    }

    @Test func doesNotMatchNewDetail() {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: .now)
        #expect(ignored.id != finding(detail: "Port 22 open by sshd-evil").fingerprint)
    }

    @Test func survivesEncoding() throws {
        let ignored = IgnoredFinding(finding: finding(detail: "Port 22 open by launchd"), ignoredAt: Date(timeIntervalSinceReferenceDate: 0))
        let decoded = try JSONDecoder().decode(IgnoredFinding.self, from: JSONEncoder().encode(ignored))
        #expect(decoded == ignored)
    }
}
