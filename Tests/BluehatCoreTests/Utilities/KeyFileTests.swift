import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct KeyFileTests {
    let directory: URL
    let projectRoot: URL

    init() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(path: "bluehat-key-file-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        directory = try Self.realURL(temporary)
        projectRoot = try Self.realURL(URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent())
    }

    static func realURL(_ url: URL) throws -> URL {
        let resolved = try #require(realpath(url.path, nil))
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved))
    }

    func makeRepository(marker: String = ".git") throws -> URL {
        let repository = directory.appending(component: "repository")
        try FileManager.default.createDirectory(at: repository.appending(path: "nested/deep"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: repository.appending(component: "linked"), withIntermediateDirectories: true)
        #expect(FileManager.default.createFile(atPath: repository.appending(component: marker).path, contents: Data()))
        return repository
    }

    @Test func createsAnOwnerOnlyFileHoldingAKeyThatReadsBack() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "backup.key")
        let key = try KeyFile.create(atPath: file.path)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect(attributes[.posixPermissions] as? Int == 0o600)
        #expect(attributes[.type] as? FileAttributeType == .typeRegular)
        #expect(KeyFile.read(atPath: file.path)?.rawRepresentation == key.rawRepresentation)
    }

    @Test func createsADifferentKeyEachTime() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try KeyFile.create(atPath: directory.appending(component: "first.key").path)
        let second = try KeyFile.create(atPath: directory.appending(component: "second.key").path)
        #expect(first.rawRepresentation != second.rawRepresentation)
    }

    @Test func refusesToOverwriteAnExistingFile() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "backup.key")
        let original = try KeyFile.create(atPath: file.path)
        #expect(throws: KeyFileError.alreadyExists(file.path)) { try KeyFile.create(atPath: file.path) }
        #expect(KeyFile.read(atPath: file.path)?.rawRepresentation == original.rawRepresentation)
    }

    @Test func refusesASymlinkAtThePathWhetherOrNotItsTargetExists() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let missing = directory.appending(component: "missing.key")
        let dangling = directory.appending(component: "dangling.key")
        try FileManager.default.createSymbolicLink(atPath: dangling.path, withDestinationPath: missing.path)
        #expect(throws: KeyFileError.alreadyExists(dangling.path)) { try KeyFile.create(atPath: dangling.path) }
        #expect(!FileManager.default.fileExists(atPath: missing.path))

        let existing = directory.appending(component: "existing")
        try Data("keep".utf8).write(to: existing)
        let link = directory.appending(component: "link.key")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: existing.path)
        #expect(throws: KeyFileError.alreadyExists(link.path)) { try KeyFile.create(atPath: link.path) }
        #expect(try Data(contentsOf: existing) == Data("keep".utf8))
    }

    @Test func refusesAnExistingFolder() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: KeyFileError.alreadyExists(directory.path)) { try KeyFile.create(atPath: directory.path) }
    }

    @Test(arguments: [".git", "Package.swift"])
    func refusesAPathInsideARepository(marker: String) throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = try makeRepository(marker: marker)
        for file in [repository.appending(component: "backup.key"), repository.appending(path: "nested/deep/backup.key")] {
            #expect(throws: KeyFileError.insideRepository(repository.path)) { try KeyFile.create(atPath: file.path) }
            #expect(!FileManager.default.fileExists(atPath: file.path))
        }
    }

    @Test func refusesARepositoryReachedThroughASymlinkedFolder() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = try makeRepository()
        let link = directory.appending(component: "innocent")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: repository.appending(path: "nested/deep").path)
        #expect(throws: KeyFileError.insideRepository(repository.path)) { try KeyFile.create(atPath: link.path + "/backup.key") }
        #expect(!FileManager.default.fileExists(atPath: repository.appending(path: "nested/deep/backup.key").path))
    }

    @Test func resolvesDotDotAfterASymlinkTheWayTheFileSystemDoes() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = try makeRepository()
        let link = directory.appending(component: "innocent")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: repository.appending(path: "nested/deep").path)
        #expect(throws: KeyFileError.insideRepository(repository.path)) { try KeyFile.create(atPath: link.path + "/../backup.key") }
        #expect(!FileManager.default.fileExists(atPath: directory.appending(component: "backup.key").path))
        #expect(!FileManager.default.fileExists(atPath: repository.appending(path: "nested/backup.key").path))
    }

    @Test func refusesADotDotPathLeadingBackIntoARepository() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = try makeRepository()
        let outside = directory.appending(component: "outside")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let path = outside.path + "/../repository/backup.key"
        #expect(throws: KeyFileError.insideRepository(repository.path)) { try KeyFile.create(atPath: path) }
    }

    @Test func refusesEveryFolderOfThisProject() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        for folder in ["", "Sources/BluehatCore", "Tests/BluehatCoreTests", "scripts"] {
            let file = projectRoot.appending(path: folder).appending(component: "bluehat-test-\(UUID().uuidString).key")
            #expect(throws: KeyFileError.insideRepository(projectRoot.path)) { try KeyFile.create(atPath: file.path) }
            #expect(!FileManager.default.fileExists(atPath: file.path))
        }
        let link = directory.appending(component: "project")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: projectRoot.path)
        let linked = link.path + "/bluehat-test-\(UUID().uuidString).key"
        #expect(throws: KeyFileError.insideRepository(projectRoot.path)) { try KeyFile.create(atPath: linked) }
        #expect(!FileManager.default.fileExists(atPath: linked))
    }

    @Test(arguments: ["", ".", "..", "/", "backup/", "backup/.", "backup/.."])
    func refusesAPathThatNamesNoFile(path: String) {
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: KeyFileError.noFileName(path)) { try KeyFile.create(atPath: path) }
    }

    @Test func refusesAMissingFolder() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(path: "missing/backup.key")
        #expect(throws: KeyFileError.folderNotFound(file.path)) { try KeyFile.create(atPath: file.path) }
    }

    @Test func readRefusesAFileThatHoldsNoKey() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "garbage.key")
        try Data("not a key".utf8).write(to: file)
        #expect(KeyFile.read(atPath: file.path) == nil)
        try Data(Data(count: 7).base64EncodedString().utf8).write(to: file)
        #expect(KeyFile.read(atPath: file.path) == nil)
        #expect(KeyFile.read(atPath: directory.appending(component: "missing.key").path) == nil)
    }
}
