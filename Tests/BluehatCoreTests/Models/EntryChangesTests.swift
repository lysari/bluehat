import Foundation
import Testing
@testable import BluehatCore

struct EntryChangesTests {
    func rulebook(_ rules: String...) throws -> Rulebook {
        try Rulebook.decode(from: Data(#"{"schema": 1, "version": 1, "rules": [\#(rules.joined(separator: ","))]}"#.utf8))
    }

    func rule(id: String, title: String = "Test", severity: String = "high", path: String = "~/Library/evil") -> String {
        #"{"id": "\#(id)", "title": "\#(title)", "severity": "\#(severity)", "category": "malware", "check": "path", "paths": ["\#(path)"]}"#
    }

    func feed(hashes: [(String, String)] = [("a", "AMOS")], packages: String = "", hosts: String = "") throws -> MalwareFeed {
        let hashEntries = hashes.map { #"{"sha256": "\#(String(repeating: $0.0, count: 64))", "family": "\#($0.1)", "firstSeen": "2026-10-30"}"# }.joined(separator: ",")
        return try MalwareFeed.decode(from: Data(#"{"schema": 1, "version": 1, "source": "test", "hashes": [\#(hashEntries)], "packages": [\#(packages)], "hosts": [\#(hosts)]}"#.utf8))
    }

    func package(_ name: String, version: String = "1.0.0") -> String {
        #"{"family": "", "name": "\#(name)", "versions": ["\#(version)"], "advisory": "MAL-2026-1"}"#
    }

    func host(_ address: String, family: String = "AMOS") -> String {
        #"{"host": "\#(address)", "family": "\#(family)", "firstSeen": "2026-10-30"}"#
    }

    @Test func findsAddedChangedAndRemovedRulesByID() throws {
        let local = try rulebook(rule(id: "kept"), rule(id: "edited"), rule(id: "dropped"))
        let remote = try rulebook(rule(id: "fresh"), rule(id: "kept"), rule(id: "edited", title: "New title"))
        let changes = remote.changes(from: local)
        #expect(changes.added.map(\.id) == ["fresh"])
        #expect(changes.changed.map(\.id) == ["edited"])
        #expect(changes.changed.map(\.title) == ["New title"])
        #expect(changes.removed.map(\.id) == ["dropped"])
        #expect(!changes.isEmpty)
    }

    @Test(arguments: [
        #"{"id": "a", "title": "Test", "severity": "critical", "category": "malware", "check": "path", "paths": ["~/Library/evil"]}"#,
        #"{"id": "a", "title": "Test", "severity": "high", "category": "malware", "check": "path", "paths": ["~/Library/other"]}"#,
        #"{"id": "a", "title": "Test", "severity": "high", "category": "malware", "check": "path", "paths": ["~/Library/evil"], "summary": "Why"}"#,
    ])
    func anyChangedFieldCountsAsChanged(edited: String) throws {
        let changes = try rulebook(edited).changes(from: rulebook(rule(id: "a")))
        #expect(changes.changed.map(\.id) == ["a"])
        #expect(changes.added.isEmpty)
        #expect(changes.removed.isEmpty)
    }

    @Test func identicalRulesHaveNoChanges() throws {
        let rules = try rulebook(rule(id: "a"), rule(id: "b"))
        #expect(rules.changes(from: rules).isEmpty)
    }

    @Test func reorderedRulesHaveNoChanges() throws {
        let changes = try rulebook(rule(id: "b"), rule(id: "a")).changes(from: rulebook(rule(id: "a"), rule(id: "b")))
        #expect(changes.isEmpty)
    }

    @Test func everyRuleIsAddedWithoutALocalCopy() throws {
        let changes = try rulebook(rule(id: "a"), rule(id: "b")).changes(from: nil)
        #expect(changes.added.map(\.id) == ["a", "b"])
        #expect(changes.changed.isEmpty)
        #expect(changes.removed.isEmpty)
    }

    @Test func emptyRemoteRemovesEverything() throws {
        let changes = try rulebook().changes(from: rulebook(rule(id: "a")))
        #expect(changes.removed.map(\.id) == ["a"])
        #expect(changes.added.isEmpty)
    }

    @Test func aRuleThisAppCannotReadIsLeftOutAndCounted() throws {
        let future = #"{"id": "future", "title": "Future", "severity": "high", "category": "malware", "check": "futureCheck"}"#
        let remote = try rulebook(rule(id: "a"), future)
        #expect(remote.changes(from: try rulebook(rule(id: "a"))).isEmpty)
        #expect(remote.unsupportedRuleCount == 1)
    }

    @Test func countsFeedChangesPerList() throws {
        let local = try feed(hashes: [("a", "AMOS"), ("b", "AMOS")], packages: package("kept") + "," + package("old"), hosts: host("203.0.113.5:443") + "," + host("203.0.113.6:443"))
        let remote = try feed(hashes: [("a", "Poseidon"), ("c", "AMOS")], packages: package("kept", version: "2.0.0") + "," + package("fresh"), hosts: host("203.0.113.5:443"))
        let changes = remote.changes(from: local)
        #expect(changes.hashes.added.count == 1)
        #expect(changes.hashes.changed.count == 1)
        #expect(changes.hashes.removed.count == 1)
        #expect(changes.packages.added.map(\.package.name) == ["fresh"])
        #expect(changes.packages.changed.map(\.package.name) == ["kept"])
        #expect(changes.packages.removed.map(\.package.name) == ["old"])
        #expect(changes.hosts.added.isEmpty)
        #expect(changes.hosts.changed.isEmpty)
        #expect(changes.hosts.removed.map(\.host) == ["203.0.113.6:443"])
    }

    @Test func identicalFeedsHaveNoChanges() throws {
        let local = try feed(packages: package("a"), hosts: host("203.0.113.5:443"))
        let changes = local.changes(from: local)
        #expect(changes.hashes.isEmpty)
        #expect(changes.packages.isEmpty)
        #expect(changes.hosts.isEmpty)
    }

    @Test func repeatedFeedEntriesCountOnce() throws {
        let local = try feed(hosts: host("203.0.113.5:443") + "," + host("203.0.113.5:443"))
        let remote = try feed(hosts: host("203.0.113.6:443") + "," + host("203.0.113.6:443"))
        let changes = remote.changes(from: local)
        #expect(changes.hosts.added.count == 1)
        #expect(changes.hosts.removed.count == 1)
    }
}
