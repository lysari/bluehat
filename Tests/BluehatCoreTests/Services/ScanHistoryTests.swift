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
        for index in 0..<(ScanLimits.defaults[.maxHistoryRecords] + 5) {
            try history.append(ScanRecord(date: .now, rulesVersion: index, duration: 1, findings: []))
        }
        let reloaded = ScanHistory(fileURL: fileURL)
        #expect(reloaded.records.count == ScanLimits.defaults[.maxHistoryRecords])
        #expect(reloaded.records.first?.rulesVersion == ScanLimits.defaults[.maxHistoryRecords] + 4)
    }

    @Test func latestChangesComparesTwoNewestScans() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        try history.append(record([finding("a")]))
        try history.append(record([finding("a"), finding("b")]))
        #expect(history.latestChanges?.new.map(\.ruleID) == ["b"])
        #expect(history.changes(for: history.records[1]).isEmpty)
    }

    @Test func recordsDecodeWithoutAKindAsNormalScans() throws {
        let saved = Data(#"[{"id":"7D8F2B60-0D5C-4F6E-9A55-1C7A1F3B9E10","date":"2026-11-01T10:00:00Z","rulesVersion":3,"duration":1.5,"entries":[]}]"#.utf8)
        try saved.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let history = ScanHistory(fileURL: fileURL)
        #expect(history.records.map(\.rulesVersion) == [3])
        #expect(history.records.first?.kind == .normal)
    }

    @Test func recordsWithAnUnknownKindStillDecode() throws {
        let saved = Data(#"[{"id":"7D8F2B60-0D5C-4F6E-9A55-1C7A1F3B9E10","date":"2026-11-01T10:00:00Z","rulesVersion":3,"duration":1.5,"entries":[],"kind":"later"}]"#.utf8)
        try saved.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        #expect(ScanHistory(fileURL: fileURL).records.first?.kind == .normal)
    }

    @Test func savesAndReloadsTheKind() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        try history.append(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: [], kind: .deep))
        #expect(ScanHistory(fileURL: fileURL).records.first?.kind == .deep)
    }

    @Test func recordsSavedAsFullScansDecodeAsDeepScans() throws {
        let saved = Data(#"[{"id":"7D8F2B60-0D5C-4F6E-9A55-1C7A1F3B9E10","date":"2026-11-01T10:00:00Z","rulesVersion":3,"duration":1.5,"entries":[],"kind":"full"}]"#.utf8)
        try saved.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        #expect(ScanHistory(fileURL: fileURL).records.first?.kind == .deep)
    }

    @Test func eachKindOfScanComparesWithTheLastScanOfItsKind() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        try history.append(record([finding("usual")]))
        try history.append(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: [finding("usual"), finding("deep")], kind: .deep))
        #expect(history.latestChanges?.isEmpty == true)
        try history.append(record([finding("usual")]))
        #expect(history.latestChanges?.isEmpty == true)
        try history.append(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: [finding("usual")], kind: .deep))
        #expect(history.latestChanges?.resolved.map(\.ruleID) == ["deep"])
    }

    @Test func dropsTheOldestScansWhenTheFileWouldNoLongerLoad() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var history = ScanHistory(fileURL: fileURL)
        let findings = Array(repeating: finding("big", detail: String(repeating: "x", count: ScanLimits.defaults[.maxDetailLength])), count: ScanLimits.defaults[.maxHistoryFileBytes] / ScanLimits.defaults[.maxDetailLength] / 3)
        for version in 1...4 {
            try history.append(ScanRecord(date: .now, rulesVersion: version, duration: 1, findings: findings, kind: .deep))
        }
        let reloaded = ScanHistory(fileURL: fileURL)
        #expect(reloaded.records.first?.rulesVersion == 4)
        #expect(reloaded.records.count == history.records.count)
        #expect(reloaded.records.count < 4)
    }
}
