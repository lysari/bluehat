import Foundation
import Synchronization
import Testing
@testable import BluehatCore

@Suite(.serialized)
struct DeepScanMemoryLimitTests {
    static let limit = ScanLimit.maxDeepScanMemoryBytes.defaultValue
    static let underLimit = limit - 1
    static let folderCount = VolumeWalk.memoryCheckInterval * 3

    let temporaryRoot = FileManager.default.temporaryDirectory.appending(path: "bluehat-memory-limit-\(UUID().uuidString)")

    var root: String {
        VolumeWalk.canonical(temporaryRoot.path) ?? temporaryRoot.path
    }

    init() throws {
        try FileManager.default.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
    }

    func cleanUp() {
        try? FileManager.default.removeItem(at: temporaryRoot)
    }

    func write(_ text: String, to relativePath: String) throws {
        let url = temporaryRoot.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func writeFolders() throws {
        for index in 0..<Self.folderCount {
            #expect(mkdir("\(root)/folder\(index)", 0o755) == 0)
        }
    }

    func rule(severity: Severity = .high) -> Rule {
        Rule(id: "limit.file", title: "Test", severity: severity, category: .malware, check: .projectFile, patterns: ["evil"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: ["*.config.js"], teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func footprint(over: @escaping @Sendable (Int) -> Bool) -> @Sendable () -> Int? {
        let calls = Mutex(0)
        return {
            let call = calls.withLock { calls in
                calls += 1
                return calls
            }
            return over(call) ? Self.limit : Self.underLimit
        }
    }

    func walk(footprint: @escaping @Sendable () -> Int?, cancellation: ScanCancellation = ScanCancellation()) -> (walk: VolumeWalk, findings: [Finding], notices: [String], list: NotScannedList) {
        let walk = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"], cancellation: cancellation, memoryFootprint: footprint)
        let result = walk.packageFileFindings(rules: [rule()], reported: [])
        return (walk, result.findings, result.notices, walk.notScanned.finished())
    }

    @Test func aWalkUnderTheLimitFinishesAndSaysNothing() throws {
        defer { cleanUp() }
        try writeFolders()
        try write("evil", to: "a.config.js")
        let result = walk(footprint: { Self.underLimit })
        #expect(!result.walk.wasStoppedAtMemoryLimit)
        #expect(result.walk.foldersRead == Self.folderCount + 1)
        #expect(result.findings.count == 1)
        #expect(result.notices.isEmpty)
        #expect(result.list.isEmpty)
        #expect(result.list.coverage?.wasStoppedAtMemoryLimit == false)
    }

    @Test func aFootprintAlreadyOverTheLimitStopsTheWalkBeforeItReadsAFolder() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let result = walk(footprint: { Self.limit })
        #expect(result.walk.wasStoppedAtMemoryLimit)
        #expect(result.walk.foldersRead == 0)
        #expect(result.walk.packageFilesOpened == 0)
        #expect(result.findings.isEmpty)
    }

    @Test func theWalkStopsPartWayThroughAtTheCheckThatSeesTheLimit() throws {
        defer { cleanUp() }
        try writeFolders()
        let stopAtSecondCheck = footprint { $0 > 1 }
        let result = walk(footprint: stopAtSecondCheck)
        #expect(result.walk.wasStoppedAtMemoryLimit)
        #expect(result.walk.foldersRead < Self.folderCount)
    }

    @Test func aCheckAfterEachOpenedFileStopsTheNextFileBeingOpened() throws {
        defer { cleanUp() }
        for index in 0..<5 {
            try write("evil", to: "project\(index)/a.config.js")
        }
        let stopAfterFirstFile = footprint { $0 > 1 }
        let result = walk(footprint: stopAfterFirstFile)
        #expect(result.walk.wasStoppedAtMemoryLimit)
        #expect(result.walk.packageFilesOpened == 1)
        #expect(result.findings.count == 1)
    }

    @Test func aStoppedWalkKeepsItsFindingsAndSaysWhatItDidNotCheck() throws {
        defer { cleanUp() }
        for index in 0..<5 {
            try write("evil", to: "project\(index)/a.config.js")
        }
        let stopAfterSecondFile = footprint { $0 > 2 }
        let result = walk(footprint: stopAfterSecondFile)
        #expect(result.findings.count == 2)

        let notice = try #require(result.notices.first)
        #expect(notice.contains("Deep Scan stopped at its \(ScanLimit.maxDeepScanMemoryBytes.text(for: Self.limit)) memory limit"))
        #expect(notice.contains("after reading \(result.walk.foldersRead) folders"))
        #expect(notice.contains("the rest of the disk wasn't checked"))
        #expect(notice.contains("Settings › Limits"))
        #expect(notice.contains("exclude large folders in Settings › General"))

        #expect(result.list.reasons == [.memoryLimit])
        let entry = try #require(result.list.entries.first)
        #expect(entry.path == nil)
        #expect(entry.name == "The rest of the startup disk")
        #expect(entry.explanation.contains("\(result.walk.foldersRead) folders"))
        #expect(result.list.summaryLine == "1 item couldn't be scanned")

        let coverage = try #require(result.list.coverage)
        #expect(coverage.wasStoppedAtMemoryLimit)
        #expect(coverage.summary.hasPrefix("Stopped at the memory limit, so the rest of the disk wasn't checked. Read \(result.walk.foldersRead) folders"))
    }

    @Test func aChangedLimitIsTheOneTheWalkObeys() throws {
        defer { cleanUp() }
        try write("{}", to: "a.config.js")
        let lowered = try #require(ScanLimits.defaults.setting(.maxDeepScanMemoryBytes, to: ScanLimit.maxDeepScanMemoryBytes.range.lowerBound))
        let stopped = VolumeWalk(roots: [root], limits: lowered, memoryFootprint: { lowered[.maxDeepScanMemoryBytes] })
        stopped.walk { _, _ in }
        #expect(stopped.wasStoppedAtMemoryLimit)
        let running = VolumeWalk(roots: [root], limits: lowered, memoryFootprint: { lowered[.maxDeepScanMemoryBytes] - 1 })
        running.walk { _, _ in }
        #expect(!running.wasStoppedAtMemoryLimit)
        #expect(lowered.changedNotice?.contains("Deep Scan memory limit") == true)
    }

    @Test func aFootprintThatCannotBeReadDoesNotStopTheWalk() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let result = walk(footprint: { nil })
        #expect(!result.walk.wasStoppedAtMemoryLimit)
        #expect(result.findings.count == 1)
    }

    @Test func cancellingStaysACancelAndIsNotReportedAsTheMemoryLimit() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let cancellation = ScanCancellation()
        cancellation.cancel()
        let result = walk(footprint: { Self.underLimit }, cancellation: cancellation)
        #expect(!result.walk.wasStoppedAtMemoryLimit)
        #expect(result.walk.foldersRead == 0)
        #expect(result.notices.isEmpty)
        #expect(result.list.reasons.isEmpty)
    }

    @Test func aFullScanKeepsTheNormalStageResultsWhenItsWalkStops() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let pathRule = Rule(id: "limit.path", title: "Test", severity: .critical, category: .malware, check: .path, patterns: nil, paths: [root], ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        let rulebook = Rulebook(schema: 1, version: 1, rules: [pathRule, rule()], issued: nil, expires: nil)
        let result = Scanner(kind: .deep, walkRoots: [root], memoryFootprint: { Self.limit }).scan(rulebook)
        #expect(result.findings.map(\.rule.id) == ["limit.path"])
        #expect(result.walkFindingIDs.isEmpty)
        #expect(result.notScanned.coverage?.wasStoppedAtMemoryLimit == true)
        #expect(result.notScanned.reasons == [.memoryLimit])
        #expect(result.notices.contains { $0.contains("memory limit") })
    }

    @Test func aNormalScanNeverReadsTheFootprint() throws {
        defer { cleanUp() }
        let rulebook = Rulebook(schema: 1, version: 1, rules: [rule()], issued: nil, expires: nil)
        let reads = Mutex(0)
        let result = Scanner(kind: .normal, walkRoots: [root], memoryFootprint: {
            reads.withLock { $0 += 1 }
            return Self.limit
        }).scan(rulebook)
        #expect(reads.withLock { $0 } == 0)
        #expect(result.notScanned.coverage == nil)
    }
}
