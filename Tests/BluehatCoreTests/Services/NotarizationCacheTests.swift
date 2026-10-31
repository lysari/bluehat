import Foundation
import Testing
@testable import BluehatCore

struct NotarizationCacheTests {
    let fileURL = FileManager.default.temporaryDirectory.appending(path: "bluehat-notarization-\(UUID().uuidString).json")

    @Test func persistsVerdictsAcrossLoads() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var cache = NotarizationCache(fileURL: fileURL)
        cache.record(true, path: "/Applications/Stats.app", cdhash: "373e7d3b")
        cache.record(false, path: "/Applications/Old.app", cdhash: "9a6e0b67")
        try cache.save()
        let reloaded = NotarizationCache(fileURL: fileURL)
        #expect(reloaded.isNotarized(path: "/Applications/Stats.app", cdhash: "373e7d3b") == true)
        #expect(reloaded.isNotarized(path: "/Applications/Old.app", cdhash: "9a6e0b67") == false)
    }

    @Test func missesWhenTheCodeHashChanged() {
        var cache = NotarizationCache(fileURL: fileURL)
        cache.record(false, path: "/Applications/Old.app", cdhash: "9a6e0b67")
        #expect(cache.isNotarized(path: "/Applications/Old.app", cdhash: "c4964b25") == nil)
        #expect(cache.isNotarized(path: "/Applications/Other.app", cdhash: "9a6e0b67") == nil)
    }

    @Test func keepsOnlyListedPaths() {
        var cache = NotarizationCache(fileURL: fileURL)
        cache.record(true, path: "/Applications/Stats.app", cdhash: "373e7d3b")
        cache.record(false, path: "/Applications/Removed.app", cdhash: "9a6e0b67")
        cache.keep(paths: ["/Applications/Stats.app"])
        #expect(Array(cache.verdicts.keys) == ["/Applications/Stats.app"])
    }

    @Test func startsEmptyWithoutAReadableFile() throws {
        defer { try? FileManager.default.removeItem(at: fileURL) }
        #expect(NotarizationCache(fileURL: fileURL).verdicts.isEmpty)
        try Data("not json".utf8).write(to: fileURL)
        #expect(NotarizationCache(fileURL: fileURL).verdicts.isEmpty)
    }
}
