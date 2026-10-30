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

public struct LoadedRulebook: Sendable {
    public let rulebook: Rulebook
    public let remoteError: RuleFeedError?
}

public enum RuleFeedError: LocalizedError, Equatable {
    case unreachable
    case badResponse
    case tooLarge
    case badSignature
    case invalidRules(RulebookError)
    case rollback(cached: Int, received: Int)
    case outdated(Int)
    case expired(Date)

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Could not reach the rules repository."
        case .badResponse: "The rules repository sent an unexpected response."
        case .tooLarge: "The rules file is larger than allowed."
        case .badSignature: "The rules file signature is invalid. It was not signed by a trusted key."
        case .invalidRules(let error): error.errorDescription
        case .rollback(let cached, let received): "Received older rules (v\(received)) than the verified copy (v\(cached))."
        case .outdated(let version): "Rules v\(version) are older than this version of Bluehat accepts. Sign and push new rules."
        case .expired(let date): "The rules expired on \(date.formatted(date: .abbreviated, time: .shortened)). Sign and push new rules."
        }
    }
}

public struct RuleFeed: Sendable {
    public static let repositoryURL = URL(string: "https://github.com/lysari/bluehat-rules")!
    public static let sourceURL = URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json")!
    public static let trustedKeys = [
        "ejbt4bgFPpvJCdj/67M3kWasEgEs1eKUs9v/ii97PhA=",
    ].map { try! Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: $0)!) }
    public static let minimumVersion = 2026103008
    static let maxEnvelopeBytes = 2_000_000
    static let requestTimeout: TimeInterval = 15

    let cacheURL: URL

    public init(cacheURL: URL = Self.defaultCacheURL) {
        self.cacheURL = cacheURL
    }

    public static func fingerprint(of key: Curve25519.Signing.PublicKey) -> String {
        SHA256.hash(data: key.rawRepresentation).prefix(8).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public static var defaultCacheURL: URL {
        URL.applicationSupportDirectory.appending(components: "Bluehat", "rules.signed.json")
    }

    public func load(now: Date = .now) async throws(RuleFeedError) -> LoadedRulebook {
        let cached = try? Data(contentsOf: cacheURL)
        let cachedRulebook = cached.flatMap { try? Self.open(envelope: $0, publicKeys: Self.trustedKeys, minimumVersion: Self.minimumVersion, now: now) }
        do throws(RuleFeedError) {
            let envelope = try await download()
            let rulebook = try Self.open(envelope: envelope, publicKeys: Self.trustedKeys, minimumVersion: Self.minimumVersion, now: now)
            if let cachedRulebook, rulebook.version < cachedRulebook.version {
                throw RuleFeedError.rollback(cached: cachedRulebook.version, received: rulebook.version)
            }
            try? FileManager.default.createDirectory(at: cacheURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? envelope.write(to: cacheURL, options: .atomic)
            return LoadedRulebook(rulebook: rulebook, remoteError: nil)
        } catch {
            guard let cachedRulebook else { throw error }
            return LoadedRulebook(rulebook: cachedRulebook, remoteError: error)
        }
    }

    static func open(envelope: Data, publicKeys: [Curve25519.Signing.PublicKey], minimumVersion: Int, now: Date) throws(RuleFeedError) -> Rulebook {
        guard
            let decoded = try? JSONDecoder().decode(SignedEnvelope.self, from: envelope),
            let payload = Data(base64Encoded: decoded.rules),
            let signature = Data(base64Encoded: decoded.signature),
            publicKeys.contains(where: { $0.isValidSignature(signature, for: payload) })
        else { throw .badSignature }
        let rulebook: Rulebook
        do {
            rulebook = try Rulebook.decode(from: payload)
        } catch let error as RulebookError {
            throw .invalidRules(error)
        } catch {
            throw .invalidRules(.malformed)
        }
        guard rulebook.version >= minimumVersion else { throw .outdated(rulebook.version) }
        if let expires = rulebook.expires, expires <= now { throw .expired(expires) }
        return rulebook
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
            let (bytes, response) = try await session.bytes(from: Self.sourceURL)
            guard
                let http = response as? HTTPURLResponse,
                http.statusCode == 200,
                http.url?.host == Self.sourceURL.host
            else { throw RuleFeedError.badResponse }
            guard http.expectedContentLength <= Self.maxEnvelopeBytes else { throw RuleFeedError.tooLarge }
            var envelope = Data()
            for try await byte in bytes {
                envelope.append(byte)
                if envelope.count > Self.maxEnvelopeBytes { throw RuleFeedError.tooLarge }
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
