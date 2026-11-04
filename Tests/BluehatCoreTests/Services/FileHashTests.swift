import Foundation
import Testing
@testable import BluehatCore

struct FileHashTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-hash-\(UUID().uuidString)")
    let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    func write(_ text: String, to relativePath: String, modified: Date = .now) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
        try FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: url.path)
    }

    func budget(_ files: Int) -> ScanLimits {
        ScanLimits(unchecked: [.maxHashedFilesPerDirectory: files])
    }

    func hashesByName(_ hashes: [String: String]) -> [String: String] {
        Dictionary(uniqueKeysWithValues: hashes.map { (URL(fileURLWithPath: $0.key).lastPathComponent, $0.value) })
    }

    @Test func fullEarlierFolderDoesNotStarveLaterFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        for index in 0..<3 {
            try write("filler \(index)", to: "first/filler-\(index).txt")
        }
        try write("abc", to: "second/deep/er/match.bin", modified: .distantPast)

        let hashed = Scanner.hashedFiles(in: [root.appending(path: "first").path, root.appending(path: "second").path], limits: budget(2))

        #expect(hashesByName(hashed.hashes)["match.bin"] == abcHash)
        #expect(hashed.hashes.count == 3)
    }

    @Test func prefersNewestArrivalsOverBudget() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("old", to: "old.txt")
        try write("newer", to: "newer.txt", modified: .now - 3_600)
        try write("abc", to: "newest.txt", modified: .distantPast)

        let hashed = Scanner.hashedFiles(in: [root.path], limits: budget(2))

        #expect(Set(hashesByName(hashed.hashes).keys) == ["newer.txt", "newest.txt"])
    }

    @Test func futureDatedDecoysDoNotCrowdOutANewFile() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let future = Date.now.addingTimeInterval(365 * 24 * 3600)
        for index in 0..<5 {
            try write("decoy \(index)", to: "decoy-\(index).txt", modified: future)
            try FileManager.default.setAttributes([.creationDate: future], ofItemAtPath: root.appending(path: "decoy-\(index).txt").path)
        }
        try write("abc", to: "match.bin", modified: .now - 3_600)

        let hashed = Scanner.hashedFiles(in: [root.path], limits: budget(1))

        #expect(hashesByName(hashed.hashes) == ["match.bin": abcHash])
    }

    @Test func skipsSymlinksAndFifos() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "real.bin")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "link.bin").path, withDestinationPath: root.appending(path: "real.bin").path)
        #expect(mkfifo(root.appending(path: "pipe").path, 0o600) == 0)

        let hashed = Scanner.hashedFiles(in: [root.path], limits: budget(10))

        #expect(hashesByName(hashed.hashes) == ["real.bin": abcHash])
        #expect(Scanner.sha256(of: root.appending(path: "link.bin"), maxBytes: ScanLimits.defaults[.maxHashedFileBytes]) == nil)
    }

    @Test func reportsSkippedFilesPerFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("old", to: "old.txt", modified: .now - 3_600)
        try write("abc", to: "newest.txt")

        let hashed = Scanner.hashedFiles(in: [root.path], limits: budget(1))

        #expect(hashed.notScanned.map(\.path) == [root.path])
        #expect(hashed.notScanned.map(\.reason) == [.overCountLimit])
        #expect(hashed.notScanned.map(\.explanation) == ["Fingerprint check covered only the 1 newest files here and skipped 1"])
    }

    @Test func aFileOverTheSizeLimitIsListedAndNotHashed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "big.bin")
        let big = root.appending(path: "big.bin").path
        #expect(truncate(big, off_t(ScanLimits.defaults[.maxHashedFileBytes] + 1)) == 0)

        let hashed = Scanner.hashedFiles(in: [root.path])

        #expect(hashed.hashes.isEmpty)
        #expect(hashed.notScanned.first?.path?.hasSuffix("/big.bin") == true)
        #expect(hashed.notScanned.map(\.reason) == [.overSizeLimit])
        #expect(hashed.notScanned.first?.explanation.hasPrefix("Over the size limit (50") == true)
        #expect(hashed.notScanned.first?.explanation.hasSuffix("limit 50 MB)") == true)
    }

    @Test func aFolderPastTheDepthLimitIsListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let deep = (1...(ScanLimits.defaults[.maxHashDepth] + 1)).map { "d\($0)" }.joined(separator: "/")
        try write("abc", to: "\(deep)/inner/file.bin")

        let hashed = Scanner.hashedFiles(in: [root.path])

        #expect(hashed.hashes.isEmpty)
        #expect(hashed.notScanned.map(\.reason) == [.overDepthLimit])
        #expect(hashed.notScanned.first?.path?.hasSuffix("/\(deep)") == true)
    }

    @Test func aFolderThatCannotBeListedIsListedWithNoPermission() throws {
        let locked = root.appending(path: "locked")
        defer {
            chmod(locked.path, 0o700)
            try? FileManager.default.removeItem(at: root)
        }
        try write("abc", to: "locked/file.bin")
        #expect(chmod(locked.path, 0) == 0)

        let hashed = Scanner.hashedFiles(in: [root.path])

        #expect(hashed.hashes.isEmpty)
        #expect(hashed.notScanned.map(\.reason) == [.noPermission])
        #expect(hashed.notScanned.first?.path?.hasSuffix("/locked") == true)
    }

    func rule(_ id: String, check: CheckKind) -> Rule {
        Rule(id: id, title: id, severity: .critical, category: .malware, check: check, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    @Test func feedFileFindingIsDroppedWhenAHandWrittenRuleReportedTheSameFile() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "real/agent.sh")
        try write("abc", to: "other.bin")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "link").path, withDestinationPath: root.appending(path: "real").path)
        let linked = root.appending(path: "link/agent.sh").path
        let real = root.appending(path: "real/agent.sh").path
        let other = root.appending(path: "other.bin").path
        let pathFinding = Finding(rule: rule("malware.silver-sparrow", check: .path), detail: linked, path: linked)
        let hashFindings = [
            Finding(rule: rule("hash.test", check: .fileHash), detail: real, path: real),
            Finding(rule: rule("feed.amos", check: .fileHash), detail: real, path: real),
            Finding(rule: rule("feed.amos", check: .fileHash), detail: other, path: other),
        ]

        let kept = Scanner.withoutFeedFileDuplicates(hashFindings, reported: [pathFinding])

        #expect(kept.map { "\($0.rule.id) \(URL(fileURLWithPath: $0.detail).lastPathComponent)" } == ["hash.test agent.sh", "feed.amos other.bin"])
        #expect(Scanner.withoutFeedFileDuplicates(hashFindings, reported: []).map(\.fingerprint) == kept.map(\.fingerprint))
        #expect(Scanner.withoutFeedFileDuplicates(Array(hashFindings.dropFirst()), reported: []).count == 2)
    }

    @Test func reportsNothingWithinLimits() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "newest.txt")

        let hashed = Scanner.hashedFiles(in: [root.path], limits: budget(1))

        #expect(hashed.notScanned.isEmpty)
    }
}
