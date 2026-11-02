import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct RuleFeedTests {
    let key = Curve25519.Signing.PrivateKey()
    let backupKey = Curve25519.Signing.PrivateKey()
    let feedKey = Curve25519.Signing.PrivateKey()
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let dataDirectory = FileManager.default.temporaryDirectory.appending(path: "bluehat-feed-\(UUID().uuidString)")
    let day: TimeInterval = 24 * 3600

    func dateFields(issued: Date?, expires: Date?) -> String {
        let formatter = ISO8601DateFormatter()
        let issuedField = issued.map { #", "issued": "\#(formatter.string(from: $0))""# } ?? ""
        let expiresField = expires.map { #", "expires": "\#(formatter.string(from: $0))""# } ?? ""
        return issuedField + expiresField
    }

    func payload(version: Int = 5, issued: Date? = nil, expires: Date? = nil, omitting missing: String? = nil, schema: Int = 1, rules: String = "") -> Data {
        let issued = missing == "issued" ? nil : issued ?? now
        let expires = missing == "expires" ? nil : expires ?? now.addingTimeInterval(30 * day)
        return Data(#"{"schema": \#(schema), "version": \#(version)\#(dateFields(issued: issued, expires: expires)), "rules": [\#(rules)]}"#.utf8)
    }

    func envelope(_ payload: Data, signedBy signer: Curve25519.Signing.PrivateKey) throws -> Data {
        let signature = try signer.signature(for: payload)
        return try JSONEncoder().encode(SignedEnvelope(rules: payload.base64EncodedString(), signature: signature.base64EncodedString()))
    }

    func open(_ envelope: Data, minimumVersion: Int = 0) throws(RuleFeedError) -> Rulebook {
        try RuleFeed.open(envelope: envelope, publicKeys: [key.publicKey, backupKey.publicKey], minimumVersion: minimumVersion, now: now)
    }

    func feedPayload(version: Int = 1, issued: Date? = nil, expires: Date? = nil, omitting missing: String? = nil) -> Data {
        let issued = missing == "issued" ? nil : issued ?? now
        let expires = missing == "expires" ? nil : expires ?? now.addingTimeInterval(7 * day)
        let hash = String(repeating: "a", count: 64)
        return Data(#"{"schema": 1, "version": \#(version)\#(dateFields(issued: issued, expires: expires)), "source": "MalwareBazaar", "hashes": [{"sha256": "\#(hash)", "family": "AMOS", "firstSeen": "2026-10-30"}]}"#.utf8)
    }

    func openFeed(_ payload: Data) throws(RuleFeedError) -> MalwareFeed {
        try RuleFeed.open(envelope: try! envelope(payload, signedBy: feedKey), publicKeys: [feedKey.publicKey], minimumVersion: 0, now: now)
    }

    func version(_ date: Date, format: String) -> Int {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .gmt
        formatter.dateFormat = format
        return Int(formatter.string(from: date))!
    }

    func openPublished<Payload: SignedPayload>(_ name: String, from feed: RuleFeed, as type: Payload.Type) throws -> Payload {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(components: "rules", name)
        let data = try Data(contentsOf: url)
        let signed = try JSONDecoder().decode(SignedEnvelope.self, from: data)
        let payload = try #require(Data(base64Encoded: signed.rules))
        let issued = try #require(try Payload.decodePayload(payload).issued)
        return try RuleFeed.open(envelope: data, publicKeys: feed.publicKeys, minimumVersion: feed.minimumVersion, now: issued)
    }

    func rulesFeed() -> RuleFeed {
        RuleFeed(sourceURL: RuleFeed.rulebook.sourceURL, publicKeys: [key.publicKey, backupKey.publicKey], minimumVersion: 0, maxEnvelopeBytes: RuleFeed.rulebook.maxEnvelopeBytes, storedURL: storedRules, bundledURL: bundledRules)
    }

    func malwareFeed() -> RuleFeed {
        RuleFeed(sourceURL: RuleFeed.malwareFeed.sourceURL, publicKeys: [feedKey.publicKey, key.publicKey, backupKey.publicKey], minimumVersion: 0, maxEnvelopeBytes: RuleFeed.malwareFeed.maxEnvelopeBytes, storedURL: dataDirectory.appending(path: "feed.signed.json"), bundledURL: dataDirectory.appending(path: "bundled/feed.signed.json"))
    }

    var storedRules: URL {
        dataDirectory.appending(path: "rules.signed.json")
    }

    var bundledRules: URL {
        dataDirectory.appending(path: "bundled/rules.signed.json")
    }

    func place(_ data: Data, at url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
    }

    func placeRules(version: Int, at url: URL, issued: Date? = nil, expires: Date? = nil, rules: String = "") throws {
        try place(envelope(payload(version: version, issued: issued, expires: expires, rules: rules), signedBy: key), at: url)
    }

    func rule(id: String, title: String = "Test rule", path: String = "~/Library/evil") -> String {
        #"{"id": "\#(id)", "title": "\#(title)", "severity": "high", "category": "malware", "check": "path", "paths": ["\#(path)"]}"#
    }

    func availableUpdate(_ check: FeedCheck<Rulebook>) throws -> FeedUpdate<Rulebook> {
        guard case .available(let update) = check else { throw RuleFeedError.badResponse }
        return update
    }

    @Test func opensEnvelopeSignedByTrustedKey() throws {
        #expect(try open(envelope(payload(), signedBy: key)).version == 5)
    }

    @Test func opensEnvelopeSignedByBackupKey() throws {
        #expect(try open(envelope(payload(), signedBy: backupKey)).version == 5)
    }

    @Test func rejectsEnvelopeSignedByOtherKey() throws {
        let data = try envelope(payload(), signedBy: Curve25519.Signing.PrivateKey())
        #expect(throws: RuleFeedError.badSignature) { try open(data) }
    }

    @Test func rejectsTamperedPayload() throws {
        let signature = try key.signature(for: payload())
        let data = try JSONEncoder().encode(SignedEnvelope(rules: payload(version: 9).base64EncodedString(), signature: signature.base64EncodedString()))
        #expect(throws: RuleFeedError.badSignature) { try open(data) }
    }

    @Test func rejectsPlainRulesWithoutEnvelope() {
        #expect(throws: RuleFeedError.badSignature) { try open(payload()) }
    }

    @Test func rejectsSignedButInvalidRules() throws {
        let data = try envelope(payload(schema: 3), signedBy: key)
        #expect(throws: RuleFeedError.invalidRules(.unsupportedSchema(3))) { try open(data) }
    }

    @Test func rejectsVersionsBelowMinimum() throws {
        let data = try envelope(payload(version: 5), signedBy: key)
        #expect(throws: RuleFeedError.outdated(5)) { try open(data, minimumVersion: 6) }
    }

    @Test func rejectsExpiredRules() throws {
        let expires = now.addingTimeInterval(-60)
        let data = try envelope(payload(issued: now.addingTimeInterval(-day), expires: expires), signedBy: key)
        #expect(throws: RuleFeedError.expired(expires)) { try open(data) }
    }

    @Test func acceptsRulesBeforeTheyExpire() throws {
        #expect(try open(envelope(payload(expires: now.addingTimeInterval(60)), signedBy: key)).expires != nil)
    }

    @Test(arguments: ["issued", "expires"])
    func rejectsRulesAndFeedWithoutDates(missing: String) throws {
        #expect(throws: RuleFeedError.missingDates) { try open(envelope(payload(omitting: missing), signedBy: key)) }
        #expect(throws: RuleFeedError.missingDates) { try openFeed(feedPayload(omitting: missing)) }
    }

    @Test func rejectsFilesIssuedMoreThanADayAhead() throws {
        let tomorrow = now.addingTimeInterval(day - 60)
        let ahead = now.addingTimeInterval(day + 60)
        #expect(try open(envelope(payload(issued: tomorrow), signedBy: key)).version == 5)
        #expect(throws: RuleFeedError.issuedInFuture(ahead)) { try open(envelope(payload(issued: ahead), signedBy: key)) }
        #expect(throws: RuleFeedError.issuedInFuture(ahead)) { try openFeed(feedPayload(issued: ahead)) }
    }

    @Test func rejectsRulesValidForMoreThan400Days() throws {
        #expect(try open(envelope(payload(expires: now.addingTimeInterval(Rulebook.maxValidity)), signedBy: key)).version == 5)
        #expect(throws: RuleFeedError.validityTooLong) { try open(envelope(payload(expires: now.addingTimeInterval(Rulebook.maxValidity + 60)), signedBy: key)) }
        #expect(Rulebook.maxValidity == 400 * day)
    }

    @Test func rejectsFeedValidForMoreThan8Days() throws {
        #expect(try openFeed(feedPayload(expires: now.addingTimeInterval(MalwareFeed.maxValidity))).hashes.count == 1)
        #expect(throws: RuleFeedError.validityTooLong) { try openFeed(feedPayload(expires: now.addingTimeInterval(MalwareFeed.maxValidity + 60))) }
        #expect(MalwareFeed.maxValidity == 8 * day)
    }

    @Test func rejectsRulesVersionAheadOfTheIssueDate() throws {
        let latest = version(now.addingTimeInterval(day), format: "yyyyMMdd") * 100 + 99
        #expect(try open(envelope(payload(version: latest), signedBy: key)).version == latest)
        #expect(throws: RuleFeedError.versionAheadOfIssueDate(latest + 1)) { try open(envelope(payload(version: latest + 1), signedBy: key)) }
        #expect(throws: RuleFeedError.versionAheadOfIssueDate(9_999_999_999)) { try open(envelope(payload(version: 9_999_999_999), signedBy: key)) }
    }

    @Test func rejectsFeedVersionAheadOfTheIssueDate() throws {
        let latest = version(now.addingTimeInterval(day), format: "yyyyMMddHHmm")
        #expect(try openFeed(feedPayload(version: latest)).version == latest)
        #expect(throws: RuleFeedError.versionAheadOfIssueDate(latest + 1)) { try openFeed(feedPayload(version: latest + 1)) }
    }

    @Test func publishedRulesAndFeedPassTheChecks() throws {
        let rules = try openPublished("rules.signed.json", from: .rulebook, as: Rulebook.self)
        let feed = try openPublished("feed.signed.json", from: .malwareFeed, as: MalwareFeed.self)
        #expect(rules.version >= RuleFeed.minimumVersion)
        #expect(!feed.hashes.isEmpty)
    }

    @Test func downloadsGiveUpAfterAMinute() {
        let configuration = RuleFeed.sessionConfiguration
        #expect(configuration.timeoutIntervalForRequest == 15)
        #expect(configuration.timeoutIntervalForResource == 60)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.urlCredentialStorage == nil)
    }

    @Test func rulesSignedByTheFeedKeyAreRejected() throws {
        let data = try envelope(payload(), signedBy: feedKey)
        #expect(throws: RuleFeedError.badSignature) { try rulesFeed().review(data, as: Rulebook.self, now: now) }
    }

    @Test func feedSignedByTheFeedKeyOrARulesKeyIsOffered() throws {
        let byFeedKey: FeedCheck<MalwareFeed> = try malwareFeed().review(envelope(feedPayload(version: 1), signedBy: feedKey), as: MalwareFeed.self, now: now)
        let byRulesKey: FeedCheck<MalwareFeed> = try malwareFeed().review(envelope(feedPayload(version: 2), signedBy: backupKey), as: MalwareFeed.self, now: now)
        guard case .available(let first) = byFeedKey, case .available(let second) = byRulesKey else {
            Issue.record("Both feeds should be offered as updates")
            return
        }
        #expect(first.payload.hashes.count == 1)
        #expect(second.payload.version == 2)
    }

    @Test func feedSignedByAnUntrustedKeyIsRejected() throws {
        let data = try envelope(feedPayload(), signedBy: Curve25519.Signing.PrivateKey())
        #expect(throws: RuleFeedError.badSignature) { try malwareFeed().review(data, as: MalwareFeed.self, now: now) }
    }

    @Test func shippedKeysKeepTheFeedKeyOutOfTheRules() {
        let raw = { (keys: [Curve25519.Signing.PublicKey]) in keys.map(\.rawRepresentation) }
        #expect(raw(RuleFeed.rulebook.publicKeys) == raw(RuleFeed.trustedKeys))
        #expect(!raw(RuleFeed.rulebook.publicKeys).contains(RuleFeed.feedKey.rawRepresentation))
        #expect(raw(RuleFeed.malwareFeed.publicKeys) == raw([RuleFeed.feedKey] + RuleFeed.trustedKeys))
        #expect(RuleFeed.fingerprint(of: RuleFeed.feedKey) == "53:7F:76:5A:31:22:FD:35")
        #expect(RuleFeed.malwareFeed.minimumVersion == 0)
        #expect(RuleFeed.malwareFeed.maxEnvelopeBytes == 4_000_000)
        #expect(RuleFeed.malwareFeed.storedURL != RuleFeed.rulebook.storedURL)
        #expect(RuleFeed.rulebook.bundledURL?.lastPathComponent == "rules.signed.json")
        #expect(RuleFeed.malwareFeed.bundledURL?.lastPathComponent == "feed.signed.json")
    }

    @Test func expiredFeedIsRejected() throws {
        let expires = now.addingTimeInterval(-60)
        let data = try envelope(feedPayload(expires: expires), signedBy: feedKey)
        #expect(throws: RuleFeedError.expired(expires)) { try malwareFeed().review(data, as: MalwareFeed.self, now: now) }
    }

    @Test func missingStoredCopyFallsBackToBundled() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == nil)
    }

    @Test func storedCopyWithBadSignatureFallsBackToBundled() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try place(envelope(payload(version: 9), signedBy: Curve25519.Signing.PrivateKey()), at: storedRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == .badSignature)
    }

    @Test func corruptStoredCopyFallsBackToBundled() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try place(Data("not json".utf8), at: storedRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == .badSignature)
    }

    @Test func storedCopyThatIsASymlinkOrDirectoryFallsBackToBundled() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try FileManager.default.createSymbolicLink(at: storedRules, withDestinationURL: bundledRules)
        let linked: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(linked.storedError == .badSignature)
        try FileManager.default.removeItem(at: storedRules)
        try FileManager.default.createDirectory(at: storedRules, withIntermediateDirectories: true)
        let directory: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(directory.payload.version == 3)
        #expect(directory.storedError == .badSignature)
    }

    @Test func oversizedStoredCopyFallsBackToBundled() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try place(Data(count: RuleFeed.rulebook.maxEnvelopeBytes + 1), at: storedRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == .badSignature)
    }

    @Test func expiredStoredCopyFallsBackToBundledWithoutAProblem() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try placeRules(version: 4, at: storedRules, issued: now.addingTimeInterval(-2 * day), expires: now.addingTimeInterval(-day))
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == nil)
    }

    @Test func newerBundledCopyWinsOverAnOlderStoredOne() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 7, at: bundledRules)
        try placeRules(version: 4, at: storedRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 7)
    }

    @Test func newerStoredCopyWinsOverTheBundledOne() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        try placeRules(version: 4, at: storedRules)
        let loaded: LoadedFeed<Rulebook> = try rulesFeed().load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 4)
    }

    @Test func noLocalCopyFails() {
        #expect(throws: RuleFeedError.noLocalCopy) { try rulesFeed().load(Rulebook.self, now: now) }
        #expect(throws: RuleFeedError.noLocalCopy) { try malwareFeed().load(MalwareFeed.self, now: now) }
    }

    @Test func badStoredCopyWithoutABundledOneFailsWithItsError() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try place(Data("not json".utf8), at: storedRules)
        #expect(throws: RuleFeedError.badSignature) { try rulesFeed().load(Rulebook.self, now: now) }
    }

    @Test func expiredCopiesAreNotUsedButStayVisible() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let expires = now.addingTimeInterval(-day)
        try placeRules(version: 4, at: storedRules, issued: now.addingTimeInterval(-2 * day), expires: expires)
        #expect(throws: RuleFeedError.expired(expires)) { try rulesFeed().load(Rulebook.self, now: now) }
        let copy: LoadedFeed<Rulebook> = try rulesFeed().localCopy(Rulebook.self, now: now)
        #expect(copy.payload.version == 4)
    }

    @Test func storedCopyIsVerifiedEveryTimeItLoads() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = rulesFeed()
        try placeRules(version: 3, at: bundledRules)
        try feed.accept(availableUpdate(feed.review(envelope(payload(version: 4), signedBy: key), as: Rulebook.self, now: now)), now: now)
        var stored = try Data(contentsOf: storedRules)
        stored[stored.count / 2] ^= 0xFF
        try stored.write(to: storedRules)
        let loaded: LoadedFeed<Rulebook> = try feed.load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 3)
        #expect(loaded.storedError == .badSignature)
    }

    @Test func checkingWritesNothingWithoutAStoredCopy() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules)
        _ = try availableUpdate(rulesFeed().review(envelope(payload(version: 4), signedBy: key), as: Rulebook.self, now: now))
        #expect(!FileManager.default.fileExists(atPath: storedRules.path))
    }

    @Test func nothingChangesUntilTheUpdateIsAccepted() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = rulesFeed()
        try placeRules(version: 4, at: storedRules)
        let before = try Data(contentsOf: storedRules)
        let update = try availableUpdate(feed.review(envelope(payload(version: 5), signedBy: key), as: Rulebook.self, now: now))
        _ = update.fullFile
        #expect(try Data(contentsOf: storedRules) == before)
        let declined: LoadedFeed<Rulebook> = try feed.load(Rulebook.self, now: now)
        #expect(declined.payload.version == 4)
        try feed.accept(update, now: now)
        #expect(try Data(contentsOf: storedRules) != before)
        let accepted: LoadedFeed<Rulebook> = try feed.load(Rulebook.self, now: now)
        #expect(accepted.payload.version == 5)
    }

    @Test func malwareFeedChangesOnlyWhenAccepted() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = malwareFeed()
        let check: FeedCheck<MalwareFeed> = try feed.review(envelope(feedPayload(version: 5), signedBy: feedKey), as: MalwareFeed.self, now: now)
        guard case .available(let update) = check else {
            Issue.record("The feed should be offered as an update")
            return
        }
        #expect(update.changes.hashes.added.count == 1)
        #expect(throws: RuleFeedError.noLocalCopy) { try feed.load(MalwareFeed.self, now: now) }
        try feed.accept(update, now: now)
        let loaded: LoadedFeed<MalwareFeed> = try feed.load(MalwareFeed.self, now: now)
        #expect(loaded.payload.version == 5)
    }

    @Test func sameVersionIsUpToDate() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 4, at: storedRules)
        let check: FeedCheck<Rulebook> = try rulesFeed().review(envelope(payload(version: 4), signedBy: key), as: Rulebook.self, now: now)
        guard case .upToDate(let remote) = check else {
            Issue.record("The same version should be up to date")
            return
        }
        #expect(remote.version == 4)
    }

    @Test func sameVersionSignedLaterIsAnUpdateWithNoRuleChanges() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 4, at: storedRules, issued: now.addingTimeInterval(-day))
        let update = try availableUpdate(rulesFeed().review(envelope(payload(version: 4), signedBy: key), as: Rulebook.self, now: now))
        #expect(update.changes.isEmpty)
    }

    @Test func comparesTheUpdateWithTheLocalRules() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 4, at: storedRules, rules: rule(id: "kept") + "," + rule(id: "edited") + "," + rule(id: "dropped"))
        let remote = payload(version: 5, rules: rule(id: "kept") + "," + rule(id: "edited", path: "~/Library/other") + "," + rule(id: "fresh", title: "Fresh rule"))
        let changes = try availableUpdate(rulesFeed().review(envelope(remote, signedBy: key), as: Rulebook.self, now: now)).changes
        #expect(changes.added.map(\.id) == ["fresh"])
        #expect(changes.added.map(\.title) == ["Fresh rule"])
        #expect(changes.changed.map(\.id) == ["edited"])
        #expect(changes.removed.map(\.id) == ["dropped"])
    }

    @Test func comparesWithTheBundledRulesWhenNothingIsStored() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 3, at: bundledRules, rules: rule(id: "kept"))
        let remote = payload(version: 5, rules: rule(id: "kept") + "," + rule(id: "fresh"))
        let changes = try availableUpdate(rulesFeed().review(envelope(remote, signedBy: key), as: Rulebook.self, now: now)).changes
        #expect(changes.added.map(\.id) == ["fresh"])
        #expect(changes.changed.isEmpty)
    }

    @Test func olderVersionThanTheStoredCopyIsRefusedAndWritesNothing() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 5, at: storedRules)
        let before = try Data(contentsOf: storedRules)
        let older = try envelope(payload(version: 4), signedBy: key)
        #expect(throws: RuleFeedError.rollback(local: 5, received: 4)) { try rulesFeed().review(older, as: Rulebook.self, now: now) }
        #expect(try Data(contentsOf: storedRules) == before)
    }

    @Test func olderVersionThanTheBundledCopyIsRefused() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 5, at: bundledRules)
        let older = try envelope(payload(version: 4), signedBy: key)
        #expect(throws: RuleFeedError.rollback(local: 5, received: 4)) { try rulesFeed().review(older, as: Rulebook.self, now: now) }
    }

    @Test func olderVersionThanAnExpiredCopyIsStillRefused() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try placeRules(version: 5, at: storedRules, issued: now.addingTimeInterval(-2 * day), expires: now.addingTimeInterval(-day))
        let older = try envelope(payload(version: 4), signedBy: key)
        #expect(throws: RuleFeedError.rollback(local: 5, received: 4)) { try rulesFeed().review(older, as: Rulebook.self, now: now) }
    }

    @Test func feedRollbackIsRefusedEvenAfterTheLocalFeedExpired() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = malwareFeed()
        let issued = now.addingTimeInterval(-9 * day)
        try place(envelope(feedPayload(version: 5, issued: issued, expires: issued.addingTimeInterval(7 * day)), signedBy: feedKey), at: feed.storedURL)
        let older = try envelope(feedPayload(version: 4), signedBy: feedKey)
        #expect(throws: RuleFeedError.rollback(local: 5, received: 4)) { try feed.review(older, as: MalwareFeed.self, now: now) }
    }

    @Test func acceptingVerifiesAgain() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = rulesFeed()
        let expires = now.addingTimeInterval(60)
        let update = try availableUpdate(feed.review(envelope(payload(version: 5, expires: expires), signedBy: key), as: Rulebook.self, now: now))
        #expect(throws: RuleFeedError.expired(expires)) { try feed.accept(update, now: now.addingTimeInterval(120)) }
        #expect(!FileManager.default.fileExists(atPath: storedRules.path))
    }

    @Test func acceptingAnUpdateOlderThanWhatIsNowLocalIsRefused() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        let feed = rulesFeed()
        let update = try availableUpdate(feed.review(envelope(payload(version: 5), signedBy: key), as: Rulebook.self, now: now))
        try placeRules(version: 6, at: storedRules)
        #expect(throws: RuleFeedError.rollback(local: 6, received: 5)) { try feed.accept(update, now: now) }
        let loaded: LoadedFeed<Rulebook> = try feed.load(Rulebook.self, now: now)
        #expect(loaded.payload.version == 6)
    }

    @Test func aSaveFailureIsReported() throws {
        defer { try? FileManager.default.removeItem(at: dataDirectory) }
        try place(Data(), at: dataDirectory.appending(path: "blocker"))
        let feed = RuleFeed(sourceURL: RuleFeed.rulebook.sourceURL, publicKeys: [key.publicKey], minimumVersion: 0, maxEnvelopeBytes: RuleFeed.rulebook.maxEnvelopeBytes, storedURL: dataDirectory.appending(path: "blocker/rules.signed.json"), bundledURL: nil)
        let update = try availableUpdate(feed.review(envelope(payload(version: 5), signedBy: key), as: Rulebook.self, now: now))
        #expect(throws: RuleFeedError.couldNotSave) { try feed.accept(update, now: now) }
    }

    @Test func fullFileIsTheReadablePayload() throws {
        let update = try availableUpdate(rulesFeed().review(envelope(payload(version: 5, rules: rule(id: "fresh")), signedBy: key), as: Rulebook.self, now: now))
        let text = try #require(String(data: update.fullFile, encoding: .utf8))
        #expect(text.contains("\n"))
        #expect(text.contains(#""id" : "fresh""#))
        #expect(!text.contains("signature"))
        #expect(try Rulebook.decode(from: update.fullFile).version == 5)
        #expect(update.fileName == "rules-v5.json")
    }

    @Test func publishedFilesLoadAsBundledCopies() throws {
        let rules = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(component: "rules")
        let rulesFeed = RuleFeed(sourceURL: RuleFeed.rulebook.sourceURL, publicKeys: RuleFeed.trustedKeys, minimumVersion: RuleFeed.minimumVersion, maxEnvelopeBytes: RuleFeed.rulebook.maxEnvelopeBytes, storedURL: dataDirectory.appending(path: "rules.signed.json"), bundledURL: rules.appending(component: "rules.signed.json"))
        let feed = RuleFeed(sourceURL: RuleFeed.malwareFeed.sourceURL, publicKeys: [RuleFeed.feedKey] + RuleFeed.trustedKeys, minimumVersion: 0, maxEnvelopeBytes: RuleFeed.malwareFeed.maxEnvelopeBytes, storedURL: dataDirectory.appending(path: "feed.signed.json"), bundledURL: rules.appending(component: "feed.signed.json"))
        let loadedRules: LoadedFeed<Rulebook> = try rulesFeed.localCopy(Rulebook.self)
        let loadedFeed: LoadedFeed<MalwareFeed> = try feed.localCopy(MalwareFeed.self)
        #expect(loadedRules.payload.version >= RuleFeed.minimumVersion)
        #expect(!loadedFeed.payload.hashes.isEmpty)
    }

    @Test func shipsOnlyKeysItCanParse() {
        #expect(!RuleFeed.trustedKeys.isEmpty)
        #expect(Set(RuleFeed.trustedKeys.map(RuleFeed.fingerprint(of:))).count == RuleFeed.trustedKeys.count)
    }
}
