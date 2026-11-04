import Foundation
import Testing
@testable import BluehatCore

struct NotScannedCollectorTests {
    static let home = "/Users/someone"

    func entry(_ path: String, reason: NotScannedReason = .noPermission) -> NotScannedEntry {
        NotScannedEntry(reason: reason, path: path, home: Self.home)
    }

    func collector(keeping count: Int) -> NotScannedCollector {
        NotScannedCollector(limits: ScanLimits(unchecked: [.maxNotScannedEntries: count]))
    }

    @Test func homePathsComeFirstWithinEachReason() {
        let collector = NotScannedCollector()
        collector.add(entry("/Library/Trial"))
        collector.add(entry("\(Self.home)/Library/Mail"))
        collector.add(entry("/usr/sbin/authserver"))
        collector.add(entry("\(Self.home)/Documents/old", reason: .couldNotRead))
        collector.add(entry("/Library/Bluetooth", reason: .couldNotRead))
        collector.add(entry("\(Self.home)/a/package.json", reason: .overSizeLimit))
        let paths = collector.finished().entries.compactMap(\.path)
        #expect(paths == [
            "\(Self.home)/Library/Mail",
            "/Library/Trial",
            "/usr/sbin/authserver",
            "\(Self.home)/Documents/old",
            "/Library/Bluetooth",
            "\(Self.home)/a/package.json",
        ])
    }

    @Test func aHomePathOnTheDataVolumeCountsAsHome() {
        #expect(entry("/System/Volumes/Data\(Self.home)/Library").isInHome)
        #expect(entry(Self.home).isInHome)
        #expect(!entry("\(Self.home)-other/Library").isInHome)
        #expect(!entry("/Users/other/Library").isInHome)
    }

    @Test func theBoundKeepsTheTrueTotalAndPrefersHomePaths() {
        let collector = collector(keeping: 4)
        for index in 0..<6 {
            collector.add(entry("/Library/other\(index)"))
        }
        for index in 0..<3 {
            collector.add(entry("\(Self.home)/mine\(index)"))
        }
        let list = collector.finished()
        #expect(list.entries.count == 4)
        #expect(list.totalCount == 9)
        #expect(list.leftOutCount == 5)
        #expect(list.entries.filter(\.isInHome).count == 3)
        #expect(list.entries.prefix(3).allSatisfy { $0.isInHome })
        #expect(list.totalsByReason[.noPermission] == 9)
    }

    @Test func aHomePathArrivingAfterTheBufferFilledStillGetsIn() {
        let collector = collector(keeping: 2)
        for index in 0..<50 {
            collector.add(entry("/Library/other\(index)"))
        }
        collector.add(entry("\(Self.home)/mine"))
        let list = collector.finished()
        #expect(list.entries.count == 2)
        #expect(list.entries.first?.path == "\(Self.home)/mine")
        #expect(list.totalCount == 51)
    }

    @Test func aSummaryRowIsNeverDroppedForAPath() {
        let collector = collector(keeping: 2)
        collector.add(NotScannedEntry(reason: .filePatternNotOpened, summary: "*.config.toml"))
        for index in 0..<5 {
            collector.add(entry("\(Self.home)/mine\(index)"))
        }
        let list = collector.finished()
        #expect(list.entries.contains { $0.name == "*.config.toml" })
        #expect(list.totalCount == 6)
    }

    @Test func theShallowestPathsAreKeptWithinARank() {
        let collector = collector(keeping: 2)
        collector.add(entry("/a/b/c/d/deep"))
        collector.add(entry("/shallow"))
        collector.add(entry("/a/middle"))
        #expect(collector.finished().entries.compactMap(\.path) == ["/a/middle", "/shallow"])
    }

    @Test func theSamePathAndReasonCountOnceButAnotherReasonCountsToo() {
        let collector = NotScannedCollector()
        collector.add(entry("/a"))
        collector.add(entry("/a"))
        collector.add(entry("/a", reason: .overSizeLimit))
        let list = collector.finished()
        #expect(list.totalCount == 2)
        #expect(list.entries.map(\.reason) == [.noPermission, .overSizeLimit])
    }

    @Test func aReasonWithEveryEntryLeftOutStillShowsItsTotal() {
        let collector = collector(keeping: 1)
        collector.add(entry("\(Self.home)/mine"))
        collector.add(entry("/other", reason: .overSizeLimit))
        let groups = collector.finished().groups(matching: FindingsFilter())
        #expect(groups.map(\.reason) == [.noPermission, .overSizeLimit])
        #expect(groups[1].entries.isEmpty)
        #expect(groups[1].totalCount == 1)
        #expect(groups[1].leftOutCount == 1)
    }

    @Test func coverageIsReportedCalmly() {
        let coverage = NotScannedList.Coverage(foldersRead: 827_282, packageFilesOpened: 48_685, unreadableFolders: 849, exclusionSummary: nil, wasStoppedAtMemoryLimit: false)
        #expect(coverage.summary == "Read \(827_282.formatted()) folders · opened \(48_685.formatted()) package files · 849 folders couldn't be read")
    }

    @Test func aMemoryLimitEntryIsNeverDroppedForAPath() {
        let collector = NotScannedCollector(limits: ScanLimits(unchecked: [.maxNotScannedEntries: ScanLimit.maxNotScannedEntries.range.lowerBound]))
        for index in 0..<(ScanLimit.maxNotScannedEntries.range.lowerBound * 3) {
            collector.add(entry("/folder\(index)"))
        }
        collector.add(NotScannedEntry(reason: .memoryLimit, summary: "The rest of the startup disk"))
        let list = collector.finished()
        #expect(list.reasons.first == .memoryLimit)
        #expect(list.entries.first?.reason == .memoryLimit)
    }

    @Test func theSummaryLineCountsEverythingAndIsAbsentWhenEmpty() {
        #expect(NotScannedList().summaryLine == nil)
        let collector = NotScannedCollector()
        for index in 0..<850 {
            collector.add(entry("/folder\(index)"))
        }
        #expect(collector.finished().summaryLine == "850 items couldn't be scanned")
    }

    @Test func aDeepScanListsALockedFolderButNotAnExcludedOneAndKeepsTheStatus() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(path: "bluehat-not-scanned-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        let root = try #require(VolumeWalk.canonical(temporary.path))
        let locked = "\(root)/locked"
        let excluded = "\(root)/excluded"
        let matched = "\(root)/matched"
        for path in [locked, excluded, matched] {
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        }
        defer {
            for path in [locked, excluded, matched] { chmod(path, 0o700) }
            try? FileManager.default.removeItem(atPath: root)
        }
        try Data("clean".utf8).write(to: URL(fileURLWithPath: "\(root)/a.config.js"))
        for path in [locked, excluded, matched] {
            #expect(chmod(path, 0) == 0)
        }
        let rule = Rule(id: "list.file", title: "Test", severity: .high, category: .malware, check: .projectFile, patterns: ["evil"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: ["*.config.js"], teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        let rulebook = Rulebook(schema: 1, version: 1, rules: [rule], issued: nil, expires: nil)

        let result = Scanner(kind: .deep, excludedFolders: [excluded], excludedPatterns: ["matched/"], walkRoots: [root]).scan(rulebook)

        #expect(result.findings.isEmpty)
        #expect(result.notices.isEmpty)
        #expect(result.notScanned.entries.compactMap(\.path) == [locked])
        #expect(result.notScanned.entries.map(\.reason) == [.noPermission])
        #expect(result.notScanned.coverage?.exclusionSummary == "2 excludes from Settings applied: folders \(Scanner.pathList([excluded])); patterns matched.")
        #expect(result.notScanned.coverage?.unreadableFolders == 1)
    }
}
