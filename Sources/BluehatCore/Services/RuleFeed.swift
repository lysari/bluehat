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

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Could not reach the rules repository."
        case .badResponse: "The rules repository sent an unexpected response."
        case .tooLarge: "The rules file is larger than allowed."
        case .badSignature: "The rules file signature is invalid. It was not signed by your key."
        case .invalidRules(let error): error.errorDescription
        case .rollback(let cached, let received): "Received older rules (v\(received)) than the verified copy (v\(cached))."
        }
    }
}

public struct RuleFeed: Sendable {
    public static let repositoryURL = URL(string: "https://github.com/lysari/bluehat-rules")!
    public static let sourceURL = URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json")!
    static let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: "ejbt4bgFPpvJCdj/67M3kWasEgEs1eKUs9v/ii97PhA=")!)
    static let maxEnvelopeBytes = 2_000_000
    static let requestTimeout: TimeInterval = 15

    let cacheURL: URL

    public init(cacheURL: URL = Self.defaultCacheURL) {
        self.cacheURL = cacheURL
    }

    public static var publicKeyFingerprint: String {
        SHA256.hash(data: publicKey.rawRepresentation).prefix(8).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public static var defaultCacheURL: URL {
        URL.applicationSupportDirectory.appending(components: "Bluehat", "rules.signed.json")
    }

    public func load() async throws(RuleFeedError) -> LoadedRulebook {
        let cached = try? Data(contentsOf: cacheURL)
        let cachedRulebook = cached.flatMap { try? Self.open(envelope: $0, publicKey: Self.publicKey) }
        do throws(RuleFeedError) {
            let envelope = try await download()
            let rulebook = try Self.open(envelope: envelope, publicKey: Self.publicKey)
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

    static func open(envelope: Data, publicKey: Curve25519.Signing.PublicKey) throws(RuleFeedError) -> Rulebook {
        guard
            let decoded = try? JSONDecoder().decode(SignedEnvelope.self, from: envelope),
            let payload = Data(base64Encoded: decoded.rules),
            let signature = Data(base64Encoded: decoded.signature),
            publicKey.isValidSignature(signature, for: payload)
        else { throw .badSignature }
        do {
            return try Rulebook.decode(from: payload)
        } catch let error as RulebookError {
            throw .invalidRules(error)
        } catch {
            throw .invalidRules(.malformed)
        }
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
