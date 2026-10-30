import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct RuleFeedTests {
    let key = Curve25519.Signing.PrivateKey()
    let backupKey = Curve25519.Signing.PrivateKey()
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)

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

    @Test func shipsOnlyKeysItCanParse() {
        #expect(!RuleFeed.trustedKeys.isEmpty)
        #expect(Set(RuleFeed.trustedKeys.map(RuleFeed.fingerprint(of:))).count == RuleFeed.trustedKeys.count)
    }
}
