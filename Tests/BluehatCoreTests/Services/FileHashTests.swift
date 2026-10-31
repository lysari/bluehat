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

    func hashesByName(_ hashes: [String: String]) -> [String: String] {
        Dictionary(uniqueKeysWithValues: hashes.map { (URL(fileURLWithPath: $0.key).lastPathComponent, $0.value) })
    }

    @Test func fullEarlierFolderDoesNotStarveLaterFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        for index in 0..<3 {
            try write("filler \(index)", to: "first/filler-\(index).txt")
        }
        try write("abc", to: "second/deep/er/match.bin", modified: .distantPast)

        let hashed = Scanner.hashedFiles(in: [root.appending(path: "first").path, root.appending(path: "second").path], budget: 2)

        #expect(hashesByName(hashed.hashes)["match.bin"] == abcHash)
        #expect(hashed.hashes.count == 3)
    }

    @Test func prefersNewestArrivalsOverBudget() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("old", to: "old.txt")
        try write("newer", to: "newer.txt", modified: .now - 3_600)
        try write("abc", to: "newest.txt", modified: .distantPast)

        let hashed = Scanner.hashedFiles(in: [root.path], budget: 2)

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

        let hashed = Scanner.hashedFiles(in: [root.path], budget: 1)

        #expect(hashesByName(hashed.hashes) == ["match.bin": abcHash])
    }

    @Test func skipsSymlinksAndFifos() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "real.bin")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "link.bin").path, withDestinationPath: root.appending(path: "real.bin").path)
        #expect(mkfifo(root.appending(path: "pipe").path, 0o600) == 0)

        let hashed = Scanner.hashedFiles(in: [root.path], budget: 10)

        #expect(hashesByName(hashed.hashes) == ["real.bin": abcHash])
        #expect(Scanner.sha256(of: root.appending(path: "link.bin")) == nil)
    }

    @Test func reportsSkippedFilesPerFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("old", to: "old.txt", modified: .now - 3_600)
        try write("abc", to: "newest.txt")

        let hashed = Scanner.hashedFiles(in: [root.path], budget: 1)

        #expect(hashed.notice == "Fingerprint check covered only the 1 newest files per folder and skipped 1 in \(root.path).")
    }

    @Test func reportsNothingWithinLimits() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("abc", to: "newest.txt")

        let hashed = Scanner.hashedFiles(in: [root.path], budget: 1)

        #expect(hashed.notice == nil)
    }
}
