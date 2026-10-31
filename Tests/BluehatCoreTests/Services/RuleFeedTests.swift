import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct RuleFeedTests {
    let key = Curve25519.Signing.PrivateKey()
    let backupKey = Curve25519.Signing.PrivateKey()
    let feedKey = Curve25519.Signing.PrivateKey()
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)
    let cacheDirectory = FileManager.default.temporaryDirectory.appending(path: "bluehat-feed-\(UUID().uuidString)")

    func payload(version: Int = 5, expires: String? = nil, schema: Int = 1) -> Data {
        let expiresField = expires.map { #", "expires": "\#($0)""# } ?? ""
        return Data(#"{"schema": \#(schema), "version": \#(version)\#(expiresField), "rules": []}"#.utf8)
    }

    func envelope(_ payload: Data, signedBy signer: Curve25519.Signing.PrivateKey) throws -> Data {
        let signature = try signer.signature(for: payload)
        return try JSONEncoder().encode(SignedEnvelope(rules: payload.base64EncodedString(), signature: signature.base64EncodedString()))
    }

    func open(_ envelope: Data, minimumVersion: Int = 0) throws(RuleFeedError) -> Rulebook {
        try RuleFeed.open(envelope: envelope, publicKeys: [key.publicKey, backupKey.publicKey], minimumVersion: minimumVersion, now: now)
    }

    func feedPayload(version: Int = 202610310317, expires: Date? = nil) -> Data {
        let expiresText = ISO8601DateFormatter().string(from: expires ?? now.addingTimeInterval(7 * 24 * 3600))
        let hash = String(repeating: "a", count: 64)
        return Data(#"{"schema": 1, "version": \#(version), "issued": "2026-10-31T03:17:00Z", "expires": "\#(expiresText)", "source": "MalwareBazaar", "hashes": [{"sha256": "\#(hash)", "family": "AMOS", "firstSeen": "2026-10-30"}]}"#.utf8)
    }

    func rulesFeed() -> RuleFeed {
        RuleFeed(sourceURL: RuleFeed.rulebook.sourceURL, publicKeys: [key.publicKey, backupKey.publicKey], minimumVersion: 0, maxEnvelopeBytes: RuleFeed.rulebook.maxEnvelopeBytes, cacheURL: cacheDirectory.appending(path: "rules.signed.json"))
    }

    func malwareFeed() -> RuleFeed {
        RuleFeed(sourceURL: RuleFeed.malwareFeed.sourceURL, publicKeys: [feedKey.publicKey, key.publicKey, backupKey.publicKey], minimumVersion: 0, maxEnvelopeBytes: RuleFeed.malwareFeed.maxEnvelopeBytes, cacheURL: cacheDirectory.appending(path: "feed.signed.json"))
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
        let data = try envelope(payload(expires: ISO8601DateFormatter().string(from: expires)), signedBy: key)
        #expect(throws: RuleFeedError.expired(expires)) { try open(data) }
    }

    @Test func acceptsRulesBeforeTheyExpire() throws {
        let future = ISO8601DateFormatter().string(from: now.addingTimeInterval(60))
        #expect(try open(envelope(payload(expires: future), signedBy: key)).expires != nil)
    }

    @Test func rulesSignedByTheFeedKeyAreRejected() throws {
        let data = try envelope(payload(), signedBy: feedKey)
        #expect(throws: RuleFeedError.badSignature) { try rulesFeed().accept(.success(data), as: Rulebook.self, now: now) }
    }

    @Test func feedSignedByTheFeedKeyOrARulesKeyIsAccepted() throws {
        defer { try? FileManager.default.removeItem(at: cacheDirectory) }
        let byFeedKey = try malwareFeed().accept(.success(envelope(feedPayload(version: 1), signedBy: feedKey)), as: MalwareFeed.self, now: now)
        #expect(byFeedKey.payload.hashes.count == 1)
        let byRulesKey = try malwareFeed().accept(.success(envelope(feedPayload(version: 2), signedBy: backupKey)), as: MalwareFeed.self, now: now)
        #expect(byRulesKey.payload.version == 2)
    }

    @Test func feedSignedByAnUntrustedKeyIsRejected() throws {
        let data = try envelope(feedPayload(), signedBy: Curve25519.Signing.PrivateKey())
        #expect(throws: RuleFeedError.badSignature) { try malwareFeed().accept(.success(data), as: MalwareFeed.self, now: now) }
    }

    @Test func shippedKeysKeepTheFeedKeyOutOfTheRules() {
        let raw = { (keys: [Curve25519.Signing.PublicKey]) in keys.map(\.rawRepresentation) }
        #expect(raw(RuleFeed.rulebook.publicKeys) == raw(RuleFeed.trustedKeys))
        #expect(!raw(RuleFeed.rulebook.publicKeys).contains(RuleFeed.feedKey.rawRepresentation))
        #expect(raw(RuleFeed.malwareFeed.publicKeys) == raw([RuleFeed.feedKey] + RuleFeed.trustedKeys))
        #expect(RuleFeed.fingerprint(of: RuleFeed.feedKey) == "53:7F:76:5A:31:22:FD:35")
        #expect(RuleFeed.malwareFeed.minimumVersion == 0)
        #expect(RuleFeed.malwareFeed.maxEnvelopeBytes == 4_000_000)
        #expect(RuleFeed.malwareFeed.cacheURL != RuleFeed.rulebook.cacheURL)
    }

    @Test func expiredFeedIsRejected() throws {
        let expires = now.addingTimeInterval(-60)
        let data = try envelope(feedPayload(expires: expires), signedBy: feedKey)
        #expect(throws: RuleFeedError.expired(expires)) { try malwareFeed().accept(.success(data), as: MalwareFeed.self, now: now) }
    }

    @Test func feedRollbackFallsBackToTheCachedFeed() throws {
        defer { try? FileManager.default.removeItem(at: cacheDirectory) }
        let feed = malwareFeed()
        _ = try feed.accept(.success(envelope(feedPayload(version: 5), signedBy: feedKey)), as: MalwareFeed.self, now: now)
        let loaded = try feed.accept(.success(envelope(feedPayload(version: 4), signedBy: feedKey)), as: MalwareFeed.self, now: now)
        #expect(loaded.payload.version == 5)
        #expect(loaded.remoteError == .rollback(cached: 5, received: 4))
    }

    @Test func unreachableFeedUsesAValidCache() throws {
        defer { try? FileManager.default.removeItem(at: cacheDirectory) }
        let feed = malwareFeed()
        _ = try feed.accept(.success(envelope(feedPayload(version: 5), signedBy: feedKey)), as: MalwareFeed.self, now: now)
        let loaded = try feed.accept(.failure(.unreachable), as: MalwareFeed.self, now: now)
        #expect(loaded.payload.version == 5)
        #expect(loaded.remoteError == .unreachable)
    }

    @Test func expiredCachedFeedIsNotUsed() throws {
        defer { try? FileManager.default.removeItem(at: cacheDirectory) }
        let feed = malwareFeed()
        _ = try feed.accept(.success(envelope(feedPayload(expires: now.addingTimeInterval(60)), signedBy: feedKey)), as: MalwareFeed.self, now: now)
        #expect(throws: RuleFeedError.unreachable) { try feed.accept(.failure(.unreachable), as: MalwareFeed.self, now: now.addingTimeInterval(120)) }
    }

    @Test func unreachableFeedWithoutCacheFails() {
        #expect(throws: RuleFeedError.unreachable) { try malwareFeed().accept(.failure(.unreachable), as: MalwareFeed.self, now: now) }
    }

    @Test func shipsOnlyKeysItCanParse() {
        #expect(!RuleFeed.trustedKeys.isEmpty)
        #expect(Set(RuleFeed.trustedKeys.map(RuleFeed.fingerprint(of:))).count == RuleFeed.trustedKeys.count)
    }
}
