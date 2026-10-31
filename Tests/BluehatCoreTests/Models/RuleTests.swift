import Foundation
import Testing
@testable import BluehatCore

struct RuleTests {
    func rulebookJSON(_ rules: String, version: Int = 1, schema: Int = 1) -> Data {
        Data(#"{"schema": \#(schema), "version": \#(version), "rules": [\#(rules)]}"#.utf8)
    }

    func rule(check: String, _ fields: String, id: String = "test.rule") -> String {
        #"{"id": "\#(id)", "title": "Test", "severity": "high", "category": "malware", "check": "\#(check)", \#(fields)}"#
    }

    @Test func decodesValidRulebook() throws {
        let data = rulebookJSON(rule(check: "path", #""paths": ["~/Library/evil"]"#))
        let rulebook = try Rulebook.decode(from: data)
        #expect(rulebook.rules.first?.paths == ["~/Library/evil"])
    }

    @Test func skipsAndCountsUnknownCheckType() throws {
        let data = rulebookJSON(rule(check: "futureCheck", #""patterns": ["x"]"#, id: "future.rule") + "," + rule(check: "setting", #""setting": "sip""#))
        let rulebook = try Rulebook.decode(from: data)
        #expect(rulebook.rules.map(\.id) == ["test.rule"])
        #expect(rulebook.unsupportedRuleCount == 1)
    }

    @Test func rejectsMalformedKnownCheckType() {
        let data = rulebookJSON(rule(check: "setting", #""setting": "notASetting""#))
        #expect(throws: RulebookError.malformed) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsUnsupportedSchema() {
        let data = rulebookJSON(rule(check: "setting", #""setting": "sip""#), schema: 2)
        #expect(throws: RulebookError.unsupportedSchema(2)) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsDuplicateIDs() {
        let setting = rule(check: "setting", #""setting": "sip""#)
        #expect(throws: RulebookError.duplicateID("test.rule")) { try Rulebook.decode(from: rulebookJSON(setting + "," + setting)) }
    }

    @Test(arguments: ["relative/path", "~/../../etc/passwd", "/tmp/../etc"])
    func rejectsUnsafePaths(path: String) {
        let data = rulebookJSON(rule(check: "path", #""paths": ["\#(path)"]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsInvalidRegex() {
        let data = rulebookJSON(rule(check: "process", #""patterns": ["(unclosed"]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsMissingField() {
        let data = rulebookJSON(rule(check: "listeningPort", #""patterns": ["x"]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsOutOfRangePort() {
        let data = rulebookJSON(rule(check: "listeningPort", #""ports": [70000]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsUppercaseHash() {
        let hash = String(repeating: "A", count: 64)
        let data = rulebookJSON(rule(check: "fileHash", #""hashes": ["\#(hash)"]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func acceptsExplanationFields() throws {
        let fields = #""setting": "sip", "summary": "Why", "remedy": "Fix", "references": ["https://example.com/report"]"#
        let rulebook = try Rulebook.decode(from: rulebookJSON(rule(check: "setting", fields)))
        #expect(rulebook.rules.first?.remedy == "Fix")
    }

    @Test(arguments: ["http://example.com/report", "javascript:alert(1)", "file:///etc/passwd"])
    func rejectsNonHTTPSReferences(reference: String) {
        let data = rulebookJSON(rule(check: "setting", #""setting": "sip", "references": ["\#(reference)"]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func rejectsOverlongSummary() {
        let summary = String(repeating: "a", count: Rulebook.maxExplanationLength + 1)
        let data = rulebookJSON(rule(check: "setting", #""setting": "sip", "summary": "\#(summary)""#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func decodesSoftwareVersionRule() throws {
        let fields = #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "20.0.0", "fixed": "20.11.1"}, {"introduced": "0", "lastAffected": "18.19.0"}, {"introduced": "21.0.0"}]"#
        let rule = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "softwareVersion", fields))).rules.first)
        #expect(rule.product == .node)
        #expect(rule.advisory == "CVE-2024-21892")
        #expect(rule.ranges?.map(\.fixed) == ["20.11.1", nil, nil])
        #expect(rule.ranges?[1].lastAffected == "18.19.0")
    }

    @Test(arguments: [
        #""advisory": "CVE-2024-21892", "ranges": [{"introduced": "0", "fixed": "1.0"}]"#,
        #""product": "java", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "0", "fixed": "1.0"}]"#,
        #""product": "node", "ranges": [{"introduced": "0", "fixed": "1.0"}]"#,
        #""product": "node", "advisory": "cve-2024-21892", "ranges": [{"introduced": "0", "fixed": "1.0"}]"#,
        #""product": "node", "advisory": "CVE 2024 21892", "ranges": [{"introduced": "0", "fixed": "1.0"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892""#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": []"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"fixed": "1.0"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "0", "fixed": "1.0", "lastAffected": "0.9"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "20.11.1", "fixed": "20.11.1"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "21.0.0", "lastAffected": "20.11.1"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "0", "fixed": "20.11.1-rc.1"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "0", "fixed": "1.1.1w"}]"#,
        #""product": "node", "advisory": "CVE-2024-21892", "ranges": [{"introduced": "latest"}]"#,
    ])
    func rejectsInvalidSoftwareVersionRule(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "softwareVersion", fields))) }
    }

    @Test func acceptsLetterReleasesOnlyForOpenSSL() throws {
        let fields = #""product": "openssl", "advisory": "CVE-2023-5678", "ranges": [{"introduced": "1.1.1", "fixed": "1.1.1x"}]"#
        #expect(try Rulebook.decode(from: rulebookJSON(rule(check: "softwareVersion", fields))).rules.count == 1)
    }

    @Test func rejectsTooManyRanges() {
        let ranges = Array(repeating: #"{"introduced": "0", "fixed": "1.0"}"#, count: Rulebook.maxEntriesPerRule + 1).joined(separator: ",")
        let data = rulebookJSON(rule(check: "softwareVersion", #""product": "node", "advisory": "CVE-2024-21892", "ranges": [\#(ranges)]"#))
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }

    @Test func signedRulesAreValidForAYearAndWarnInTheLast30Days() throws {
        let data = Data(#"{"schema": 1, "version": 1, "issued": "2026-10-01T00:00:00Z", "expires": "2027-10-01T00:00:00Z", "rules": []}"#.utf8)
        let rulebook = try Rulebook.decode(from: data)
        let issued = try #require(rulebook.issued)
        let expires = try #require(rulebook.expires)
        let day: TimeInterval = 24 * 3600
        #expect(Rulebook.validity == 365 * day)
        #expect(Rulebook.expiryWarning == 30 * day)
        #expect(expires == issued.addingTimeInterval(Rulebook.validity))
        #expect(!rulebook.expiresSoon(now: issued))
        #expect(!rulebook.expiresSoon(now: issued.addingTimeInterval(334 * day)))
        #expect(!rulebook.expiresSoon(now: expires.addingTimeInterval(-Rulebook.expiryWarning - 60)))
        #expect(rulebook.expiresSoon(now: expires.addingTimeInterval(-Rulebook.expiryWarning + 60)))
        #expect(rulebook.expiresSoon(now: expires.addingTimeInterval(-60)))
    }

    @Test func rulesWithoutExpiryNeverWarn() throws {
        let rulebook = try Rulebook.decode(from: rulebookJSON(""))
        #expect(!rulebook.expiresSoon(now: .distantFuture))
    }

    @Test func appendingKeepsRulebookMetadata() throws {
        let data = Data(#"{"schema": 1, "version": 7, "expires": "2027-10-01T00:00:00Z", "rules": [\#(rule(check: "setting", #""setting": "sip""#))]}"#.utf8)
        let rulebook = try Rulebook.decode(from: data)
        let extra = try Rulebook.decode(from: rulebookJSON(rule(check: "path", #""paths": ["/x"]"#, id: "extra.rule"))).rules
        let merged = rulebook.appending(extra)
        #expect(merged.rules.map(\.id) == ["test.rule", "extra.rule"])
        #expect(merged.version == 7)
        #expect(merged.expires == rulebook.expires)
    }

    @Test func publishedStarterRulesAreValid() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(components: "rules", "rules.json")
        let rulebook = try Rulebook.decode(from: Data(contentsOf: url))
        #expect(!rulebook.rules.isEmpty)
    }
}
