import CryptoKit
import Foundation

public struct SignedEnvelope: Codable, Sendable {
    public let rules: String
    public let signature: String

    public init(rules: String, signature: String) {
        self.rules = rules
        self.signature = signature
    }
}

public protocol SignedPayload: Sendable {
    var version: Int { get }
    var expires: Date? { get }
    static func decodePayload(_ data: Data) throws(RuleFeedError) -> Self
}

public struct LoadedFeed<Payload: SignedPayload>: Sendable {
    public let payload: Payload
    public let remoteError: RuleFeedError?
}

public enum RuleFeedError: LocalizedError, Equatable {
    case unreachable
    case badResponse
    case tooLarge
    case badSignature
    case invalidRules(RulebookError)
    case invalidMalwareFeed(MalwareFeedError)
    case rollback(cached: Int, received: Int)
    case outdated(Int)
    case expired(Date)

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Could not reach the rules repository."
        case .badResponse: "The rules repository sent an unexpected response."
        case .tooLarge: "The downloaded file is larger than allowed."
        case .badSignature: "The file signature is invalid. It was not signed by a trusted key."
        case .invalidRules(let error): error.errorDescription
        case .invalidMalwareFeed(let error): error.errorDescription
        case .rollback(let cached, let received): "Received an older version (v\(received)) than the verified copy (v\(cached))."
        case .outdated(let version): "Rules v\(version) are older than this version of Bluehat accepts. Sign and push new rules."
        case .expired(let date): "The signed file expired on \(date.formatted(date: .abbreviated, time: .shortened)). Sign and push a new one."
        }
    }
}

public struct RuleFeed: Sendable {
    public static let repositoryURL = URL(string: "https://github.com/lysari/bluehat-rules")!
    public static let trustedKeys = [
        "ejbt4bgFPpvJCdj/67M3kWasEgEs1eKUs9v/ii97PhA=",
        "7QnEa2pH6FwbhIMqMbVO/y2bhumiHbtIqshgdxzKSJA=",
    ].map(publicKey)
    public static let feedKey = publicKey("srVF3Dxj32r6pMW0M+0MMsUdr75RyoD94CafL7iFnoE=")
    public static let minimumVersion = 2026103008
    static let requestTimeout: TimeInterval = 15
    static let cacheDirectory = URL.applicationSupportDirectory.appending(component: "Bluehat")

    public static let rulebook = RuleFeed(
        sourceURL: URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json")!,
        publicKeys: trustedKeys,
        minimumVersion: minimumVersion,
        maxEnvelopeBytes: 2_000_000,
        cacheURL: cacheDirectory.appending(component: "rules.signed.json")
    )
    public static let malwareFeed = RuleFeed(
        sourceURL: URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/feed.signed.json")!,
        publicKeys: [feedKey] + trustedKeys,
        minimumVersion: 0,
        maxEnvelopeBytes: 4_000_000,
        cacheURL: cacheDirectory.appending(component: "feed.signed.json")
    )

    let sourceURL: URL
    let publicKeys: [Curve25519.Signing.PublicKey]
    let minimumVersion: Int
    let maxEnvelopeBytes: Int
    let cacheURL: URL

    public static func fingerprint(of key: Curve25519.Signing.PublicKey) -> String {
        SHA256.hash(data: key.rawRepresentation).prefix(8).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    static func publicKey(_ base64: String) -> Curve25519.Signing.PublicKey {
        try! Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: base64)!)
    }

    public func load<Payload: SignedPayload>(_ type: Payload.Type, now: Date = .now) async throws(RuleFeedError) -> LoadedFeed<Payload> {
        let remote: Result<Data, RuleFeedError>
        do {
            remote = .success(try await download())
        } catch {
            remote = .failure(error)
        }
        return try accept(remote, as: type, now: now)
    }

    func accept<Payload: SignedPayload>(_ remote: Result<Data, RuleFeedError>, as type: Payload.Type, now: Date) throws(RuleFeedError) -> LoadedFeed<Payload> {
        let cached = try? Data(contentsOf: cacheURL)
        let cachedPayload: Payload? = cached.flatMap { try? Self.open(envelope: $0, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now) }
        do throws(RuleFeedError) {
            let envelope = try remote.get()
            let payload: Payload = try Self.open(envelope: envelope, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now)
            if let cachedPayload, payload.version < cachedPayload.version {
                throw RuleFeedError.rollback(cached: cachedPayload.version, received: payload.version)
            }
            try? FileManager.default.createDirectory(at: cacheURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? envelope.write(to: cacheURL, options: .atomic)
            return LoadedFeed(payload: payload, remoteError: nil)
        } catch {
            guard let cachedPayload else { throw error }
            return LoadedFeed(payload: cachedPayload, remoteError: error)
        }
    }

    static func open<Payload: SignedPayload>(envelope: Data, publicKeys: [Curve25519.Signing.PublicKey], minimumVersion: Int, now: Date) throws(RuleFeedError) -> Payload {
        guard
            let decoded = try? JSONDecoder().decode(SignedEnvelope.self, from: envelope),
            let payload = Data(base64Encoded: decoded.rules),
            let signature = Data(base64Encoded: decoded.signature),
            publicKeys.contains(where: { $0.isValidSignature(signature, for: payload) })
        else { throw .badSignature }
        let opened = try Payload.decodePayload(payload)
        guard opened.version >= minimumVersion else { throw .outdated(opened.version) }
        if let expires = opened.expires, expires <= now { throw .expired(expires) }
        return opened
    }

    private func download() async throws(RuleFeedError) -> Data {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = Self.requestTimeout
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        let session = URLSession(configuration: configuration, delegate: RedirectBlocker(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        do {
            let (bytes, response) = try await session.bytes(from: sourceURL)
            guard
                let http = response as? HTTPURLResponse,
                http.statusCode == 200,
                http.url?.host == sourceURL.host
            else { throw RuleFeedError.badResponse }
            guard http.expectedContentLength <= maxEnvelopeBytes else { throw RuleFeedError.tooLarge }
            var envelope = Data()
            for try await byte in bytes {
                envelope.append(byte)
                if envelope.count > maxEnvelopeBytes { throw RuleFeedError.tooLarge }
            }
            return envelope
        } catch let error as RuleFeedError {
            throw error
        } catch {
            throw .unreachable
        }
    }
}

private final class RedirectBlocker: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
