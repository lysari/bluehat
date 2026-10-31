import Foundation
import Synchronization
import Testing
@testable import BluehatCore

struct RegularFileTests {
    let directory = FileManager.default.temporaryDirectory.appending(path: "bluehat-file-\(UUID().uuidString)")

    init() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func finishes(within seconds: Double, _ work: @escaping @Sendable () -> Void) -> Bool {
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            work()
            done.signal()
        }
        return done.wait(timeout: .now() + seconds) == .success
    }

    @Test func fifoAtAProfilePathDoesNotHang() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let fifo = directory.appending(path: ".zshrc").path
        #expect(mkfifo(fifo, 0o600) == 0)
        let results = Mutex<(text: String?, hash: String??)>((nil, nil))
        let finished = finishes(within: 5) {
            let text = Scanner.readText(fifo)
            let hash = Scanner.sha256(of: URL(fileURLWithPath: fifo))
            results.withLock { $0 = (text, hash) }
        }
        #expect(finished)
        #expect(results.withLock { $0.text } == "")
        #expect(results.withLock { $0.hash } == .some(nil))
    }

    @Test func devicesAreRefused() {
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(RegularFile.read(atPath: "/dev/zero", maxBytes: 10, followingSymlinks: true) == nil)
    }

    @Test func oversizedSparseFileIsRefusedWithoutReading() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appending(path: "huge").path
        #expect(FileManager.default.createFile(atPath: path, contents: nil))
        #expect(truncate(path, 8 << 30) == 0)
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(RegularFile.read(atPath: path, maxBytes: Scanner.maxReadBytes, followingSymlinks: true) == nil)
            #expect(Scanner.readText(path) == "")
        }
        #expect(elapsed < .milliseconds(500))
    }

    @Test func readsAFileUpToTheLimit() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appending(path: "small").path
        try Data("abc".utf8).write(to: URL(fileURLWithPath: path))
        #expect(RegularFile.read(atPath: path, maxBytes: 3, followingSymlinks: false) == Data("abc".utf8))
        #expect(RegularFile.read(atPath: path, maxBytes: 2, followingSymlinks: false) == nil)
        #expect(RegularFile.read(atPath: directory.path, maxBytes: 10, followingSymlinks: false) == nil)
    }

    @Test func symlinksAreFollowedOnlyWhenAsked() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appending(path: "target").path
        let link = directory.appending(path: "link").path
        try Data("abc".utf8).write(to: URL(fileURLWithPath: target))
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(RegularFile.read(atPath: link, maxBytes: 10, followingSymlinks: true) == Data("abc".utf8))
        #expect(RegularFile.read(atPath: link, maxBytes: 10, followingSymlinks: false) == nil)
    }
}
