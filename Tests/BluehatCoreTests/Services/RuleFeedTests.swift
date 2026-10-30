import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct RuleFeedTests {
    let key = Curve25519.Signing.PrivateKey()
    let payload = Data(#"{"schema": 1, "version": 5, "rules": []}"#.utf8)

    func envelope(payload: Data, signedBy signer: Curve25519.Signing.PrivateKey) throws -> Data {
        let signature = try signer.signature(for: payload)
        return try JSONEncoder().encode(SignedEnvelope(rules: payload.base64EncodedString(), signature: signature.base64EncodedString()))
    }

    @Test func opensEnvelopeSignedByTrustedKey() throws {
        let rulebook = try RuleFeed.open(envelope: envelope(payload: payload, signedBy: key), publicKey: key.publicKey)
        #expect(rulebook.version == 5)
    }

    @Test func rejectsEnvelopeSignedByOtherKey() throws {
        let data = try envelope(payload: payload, signedBy: Curve25519.Signing.PrivateKey())
        #expect(throws: RuleFeedError.badSignature) { try RuleFeed.open(envelope: data, publicKey: key.publicKey) }
    }

    @Test func rejectsTamperedPayload() throws {
        let signature = try key.signature(for: payload)
        let tampered = Data(#"{"schema": 1, "version": 9, "rules": []}"#.utf8)
        let data = try JSONEncoder().encode(SignedEnvelope(rules: tampered.base64EncodedString(), signature: signature.base64EncodedString()))
        #expect(throws: RuleFeedError.badSignature) { try RuleFeed.open(envelope: data, publicKey: key.publicKey) }
    }

    @Test func rejectsPlainRulesWithoutEnvelope() {
        #expect(throws: RuleFeedError.badSignature) { try RuleFeed.open(envelope: payload, publicKey: key.publicKey) }
    }

    @Test func rejectsSignedButInvalidRules() throws {
        let invalid = Data(#"{"schema": 3, "version": 1, "rules": []}"#.utf8)
        let data = try envelope(payload: invalid, signedBy: key)
        #expect(throws: RuleFeedError.invalidRules(.unsupportedSchema(3))) { try RuleFeed.open(envelope: data, publicKey: key.publicKey) }
    }
}
