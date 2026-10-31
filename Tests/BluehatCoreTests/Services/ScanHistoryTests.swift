import Foundation
import Testing
@testable import BluehatCore

struct ScanHistoryTests {
    let fileURL = FileManager.default.temporaryDirectory.appending(path: "bluehat-history-\(UUID().uuidString).json")

    func finding(_ id: String, severity: Severity = .high, detail: String = "detail") -> Finding {
        let rule = Rule(id: id, title: id, severity: severity, category: .malware, check: .path, patterns: nil, paths: ["/x"], ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: nil)
    }

    func record(_ findings: [Finding]) -> ScanRecord {
        ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: findings)
    }

    @Test func reportsNewAndResolvedFindings() {
        let previous = record([finding("a"), finding("b")])
        let current = record([finding("b"), finding("c")])
        let changes = current.changes(since: previous)
        #expect(changes.new.map(\.ruleID) == ["c"])
        #expect(changes.resolved.map(\.ruleID) == ["a"])
    }

    @Test func firstScanHasNoChanges() {
        #expect(record([finding("a")]).changes(since: nil).isEmpty)
    }

    @Test func changedDetailCountsAsNew() {
        let changes = record([finding("a", detail: "new path")]).changes(since: record([finding("a", detail: "old path")]))
        #expect(changes.new.count == 1)
        #expect(changes.resolved.count == 1)
    }

    @Test func persistsNewestFirstAndKeepsLimit() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        for index in 0..<(ScanHistory.maxRecords + 5) {
            try history.append(ScanRecord(date: .now, rulesVersion: index, duration: 1, findings: []))
        }
        let reloaded = ScanHistory(fileURL: fileURL)
        #expect(reloaded.records.count == ScanHistory.maxRecords)
        #expect(reloaded.records.first?.rulesVersion == ScanHistory.maxRecords + 4)
    }

    @Test func latestChangesComparesTwoNewestScans() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        try history.append(record([finding("a")]))
        try history.append(record([finding("a"), finding("b")]))
        #expect(history.latestChanges?.new.map(\.ruleID) == ["b"])
        #expect(history.changes(for: history.records[1]).isEmpty)
    }
}
