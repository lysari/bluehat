import Foundation
import Testing
@testable import BluehatCore

@Suite(.serialized)
struct ScanMemoryTests {
    static let sparseFileCount = 40
    static let sparseFileBytes = 25_000_000
    static let allowedGrowthBytes = 300 << 20

    let temporaryRoot = FileManager.default.temporaryDirectory.appending(path: "bluehat-memory-\(UUID().uuidString)")

    var root: String {
        VolumeWalk.canonical(temporaryRoot.path) ?? temporaryRoot.path
    }

    init() throws {
        try FileManager.default.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
    }

    func cleanUp() {
        try? FileManager.default.removeItem(at: temporaryRoot)
    }

    func writeSparseFiles(named name: (Int) -> String) throws {
        for index in 0..<Self.sparseFileCount {
            let url = temporaryRoot.appending(path: name(index))
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data().write(to: url)
            #expect(truncate(url.path, off_t(Self.sparseFileBytes)) == 0)
        }
    }

    func liveBytes() -> Int {
        var statistics = malloc_statistics_t()
        malloc_zone_statistics(nil, &statistics)
        return statistics.size_in_use
    }

    func growth(during work: () -> Void) -> Int {
        autoreleasepool {
            let before = liveBytes()
            work()
            return liveBytes() - before
        }
    }

    @Test func hashingDoesNotKeepTheFilesItRead() throws {
        defer { cleanUp() }
        try writeSparseFiles { "file\($0).bin" }
        let grown = growth {
            #expect(Scanner.hashedFiles(in: [root], limits: ScanLimits(unchecked: [.maxHashedFilesPerDirectory: Self.sparseFileCount])).hashes.count == Self.sparseFileCount)
        }
        #expect(grown < Self.allowedGrowthBytes)
    }

    @Test func npmCheckDoesNotKeepTheLockfilesItRead() throws {
        defer { cleanUp() }
        try writeSparseFiles { "project\($0)/package-lock.json" }
        let projects = (0..<Self.sparseFileCount).map { (path: "\(root)/project\($0)", files: Set([NpmInventory.manifestName, "package-lock.json"])) }
        let grown = growth {
            #expect(NpmInventory.packages(inProjects: projects, moduleDirectories: []).packages.isEmpty)
        }
        #expect(grown < Self.allowedGrowthBytes)
    }

    @Test func diskWalkDoesNotKeepTheLockfilesItRead() throws {
        defer { cleanUp() }
        try writeSparseFiles { "project\($0)/package-lock.json" }
        let rule = Rule(id: "memory.package", title: "Test", severity: .critical, category: .malware, check: .npmPackage, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: [MaliciousPackage(name: "chalk", versions: .only(["5.6.1"]), advisory: "MAL-1")], files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        let grown = growth {
            #expect(VolumeWalk(roots: [root]).packageFileFindings(rules: [rule], reported: []).findings.isEmpty)
        }
        #expect(grown < Self.allowedGrowthBytes)
    }

    @Test func manyUnreadableFoldersKeepTheListBounded() throws {
        let limit = ScanLimit.maxNotScannedEntries.range.lowerBound
        let folders = limit * 3 + 7
        let locked = (0..<folders).map { "\(root)/locked\($0)" }
        defer {
            for path in locked { chmod(path, 0o700) }
            cleanUp()
        }
        for path in locked {
            #expect(mkdir(path, 0o000) == 0)
        }
        try Data("{}".utf8).write(to: temporaryRoot.appending(path: "a.config.js"))
        let rule = Rule(id: "memory.file", title: "Test", severity: .critical, category: .malware, check: .projectFile, patterns: ["evil"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: ["*.config.js"], teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        let limits = ScanLimits(unchecked: [.maxNotScannedEntries: limit])
        var list = NotScannedList()
        let grown = growth {
            let walk = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"], limits: limits)
            _ = walk.packageFileFindings(rules: [rule], reported: [])
            #expect(walk.unreadableFolders == folders)
            list = walk.notScanned.finished()
        }
        #expect(list.entries.count == limit)
        #expect(list.totalCount == folders)
        #expect(list.leftOutCount == folders - limit)
        #expect(grown < Self.allowedGrowthBytes)
    }
}
