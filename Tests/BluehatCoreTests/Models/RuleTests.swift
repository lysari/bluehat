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

    @Test func listsOnlyAreasWithRulesInCheckOrder() throws {
        let data = rulebookJSON(rule(check: "setting", #""setting": "sip""#) + "," + rule(check: "path", #""paths": ["~/Library/evil"]"#, id: "path.rule"))
        let rulebook = try Rulebook.decode(from: data)
        #expect(rulebook.areas == [.path, .setting])
        #expect(!rulebook.areas.contains(.outbound))
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

    @Test func decodesNpmPackageRule() throws {
        let fields = #""packages": [{"name": "chalk", "versions": ["5.6.1"], "advisory": "MAL-2025-46969"}, {"name": "@scope/evil", "versions": "*", "advisory": "MAL-2025-1"}]"#
        let rule = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "npmPackage", fields))).rules.first)
        #expect(rule.check == .npmPackage)
        #expect(rule.packages == [
            MaliciousPackage(name: "chalk", versions: .only(["5.6.1"]), advisory: "MAL-2025-46969"),
            MaliciousPackage(name: "@scope/evil", versions: .every, advisory: "MAL-2025-1"),
        ])
    }

    @Test(arguments: [
        #""packages": []"#,
        #""patterns": ["x"]"#,
        #""packages": [{"name": "Chalk", "versions": ["5.6.1"], "advisory": "MAL-2025-46969"}]"#,
        #""packages": [{"name": "chalk", "versions": ["5.6.1"], "advisory": "mal-2025-46969"}]"#,
        #""packages": [{"name": "chalk", "versions": [], "advisory": "MAL-2025-46969"}]"#,
        #""packages": [{"name": "chalk", "versions": ["latest"], "advisory": "MAL-2025-46969"}]"#,
        #""packages": [{"name": "chalk", "versions": "5.6.1", "advisory": "MAL-2025-46969"}]"#,
        #""packages": [{"name": "chalk", "versions": ["5.6.1"]}]"#,
    ])
    func rejectsInvalidNpmPackageRule(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "npmPackage", fields))) }
    }

    @Test func rejectsTooManyPackagesOrVersions() {
        let packages = Array(repeating: #"{"name": "chalk", "versions": "*", "advisory": "MAL-2025-1"}"#, count: Rulebook.maxEntriesPerRule + 1).joined(separator: ",")
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "npmPackage", #""packages": [\#(packages)]"#))) }
        let versions = (0...NpmPackage.maxVersionsPerPackage).map { #""1.0.\#($0)""# }.joined(separator: ",")
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "npmPackage", #""packages": [{"name": "chalk", "versions": [\#(versions)], "advisory": "MAL-2025-1"}]"#))) }
    }

    @Test func decodesProjectFileRule() throws {
        let fields = #""files": ["*.config.js", ".eslintrc.js", "package.json", "next.config.*"], "patterns": ["\\S[ \\t]{150,}\\S"]"#
        let rule = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "projectFile", fields))).rules.first)
        #expect(rule.check == .projectFile)
        #expect(rule.files == ["*.config.js", ".eslintrc.js", "package.json", "next.config.*"])
        #expect(rule.patterns == [#"\S[ \t]{150,}\S"#])
    }

    @Test(arguments: [
        #""patterns": ["x"]"#,
        #""files": [], "patterns": ["x"]"#,
        #""files": [""], "patterns": ["x"]"#,
        #""files": ["*"], "patterns": ["x"]"#,
        #""files": ["*.*"], "patterns": ["x"]"#,
        #""files": ["src/tailwind.config.js"], "patterns": ["x"]"#,
        #""files": ["/etc/passwd"], "patterns": ["x"]"#,
        #""files": ["..config.js"], "patterns": ["x"]"#,
        #""files": [".."], "patterns": ["x"]"#,
        #""files": ["?.config.js"], "patterns": ["x"]"#,
        #""files": ["[ab].config.js"], "patterns": ["x"]"#,
        #""files": ["*.config.{js,ts}"], "patterns": ["x"]"#,
        #""files": ["a\\b.js"], "patterns": ["x"]"#,
        #""files": ["vite config.js"], "patterns": ["x"]"#,
        #""files": ["*.config.js"]"#,
        #""files": ["*.config.js"], "patterns": []"#,
        #""files": ["*.config.js"], "patterns": ["(unclosed"]"#,
    ])
    func rejectsInvalidProjectFileRule(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "projectFile", fields))) }
    }

    @Test func rejectsTooManyOrOverlongFileNames() {
        let tooMany = (0...Rulebook.maxFileNames).map { #""f\#($0).js""# }.joined(separator: ",")
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "projectFile", #""files": [\#(tooMany)], "patterns": ["x"]"#))) }
        let overlong = String(repeating: "a", count: 65)
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "projectFile", #""files": ["\#(overlong)"], "patterns": ["x"]"#))) }
        let most = (1...Rulebook.maxFileNames).map { #""f\#($0).js""# }.joined(separator: ",")
        #expect(throws: Never.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "projectFile", #""files": [\#(most)], "patterns": ["x"]"#))) }
    }

    @Test func decodesSystemExtensionRule() throws {
        let fields = #""teams": ["W5364U7YZB", "UBF8T346G9"], "bundles": ["io.macfuse", "org.virtualbox"]"#
        let rule = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "systemExtension", fields))).rules.first)
        #expect(rule.check == .systemExtension)
        #expect(rule.teams == ["W5364U7YZB", "UBF8T346G9"])
        #expect(rule.bundles == ["io.macfuse", "org.virtualbox"])
    }

    @Test func acceptsSystemExtensionRuleWithoutVendors() throws {
        #expect(try Rulebook.decode(from: rulebookJSON(rule(check: "systemExtension", #""summary": "Every one""#))).rules.count == 1)
    }

    @Test(arguments: [
        #""teams": []"#,
        #""teams": ["w5364u7yzb"]"#,
        #""teams": ["W5364U7YZ"]"#,
        #""teams": ["W5364U7YZBX"]"#,
        #""teams": ["W5364-7YZB"]"#,
        #""bundles": []"#,
        #""bundles": ["io"]"#,
        #""bundles": ["io.macfuse."]"#,
        #""bundles": [".io.macfuse"]"#,
        #""bundles": ["io..macfuse"]"#,
        #""bundles": ["io.mac fuse"]"#,
        #""bundles": ["io.macfuse.*"]"#,
        #""bundles": ["a.b.c.d.e.f.g.h.i"]"#,
    ])
    func rejectsInvalidSystemExtensionRule(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "systemExtension", fields))) }
    }

    @Test func rejectsTooManyTeams() {
        let teams = Array(repeating: #""W5364U7YZB""#, count: Rulebook.maxEntriesPerRule + 1).joined(separator: ",")
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "systemExtension", #""teams": [\#(teams)]"#))) }
    }

    @Test func decodesXProtectRule() throws {
        let rule = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "xprotect", #""minimumVersion": 5360"#))).rules.first)
        #expect(rule.check == .xprotect)
        #expect(rule.minimumVersion == 5360)
    }

    @Test(arguments: [#""summary": "No minimum""#, #""minimumVersion": 0"#, #""minimumVersion": -1"#, #""patterns": ["x"]"#])
    func rejectsXProtectRuleWithoutPositiveMinimum(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "xprotect", fields))) }
    }

    @Test func rejectsNonIntegerXProtectMinimum() {
        #expect(throws: RulebookError.malformed) { try Rulebook.decode(from: rulebookJSON(rule(check: "xprotect", #""minimumVersion": "5360""#))) }
    }

    @Test func decodesOutboundRules() throws {
        let hosts = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "outbound", #""hosts": ["203.0.113.5:443", "198.51.100.0/24", "[2001:db8::1]:8443"]"#))).rules.first)
        #expect(hosts.check == .outbound)
        #expect(hosts.hosts == ["203.0.113.5:443", "198.51.100.0/24", "[2001:db8::1]:8443"])
        let ports = try #require(try Rulebook.decode(from: rulebookJSON(rule(check: "outbound", #""ports": [4444]"#))).rules.first)
        #expect(ports.ports == [4444])
    }

    @Test(arguments: [
        #""summary": "Nothing to match""#,
        #""hosts": ["203.0.113.5"], "ports": [443]"#,
        #""hosts": []"#,
        #""hosts": ["c2.example.com"]"#,
        #""hosts": ["127.0.0.1:4444"]"#,
        #""hosts": ["10.0.0.0/8"]"#,
        #""hosts": ["203.0.113.5:70000"]"#,
        #""ports": [0]"#,
        #""ports": []"#,
    ])
    func rejectsInvalidOutboundRule(fields: String) {
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "outbound", fields))) }
    }

    @Test func rejectsTooManyOutboundHosts() {
        let hosts = Array(repeating: #""203.0.113.5""#, count: Rulebook.maxEntriesPerRule + 1).joined(separator: ",")
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: rulebookJSON(rule(check: "outbound", #""hosts": [\#(hosts)]"#))) }
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
