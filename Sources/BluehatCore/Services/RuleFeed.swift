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
    associatedtype Changes: Sendable
    static var maxValidity: TimeInterval { get }
    static var versionDateFormat: String { get }
    var version: Int { get }
    var issued: Date? { get }
    var expires: Date? { get }
    static func decodePayload(_ data: Data) throws(RuleFeedError) -> Self
    func changes(from local: Self?) -> Changes
}

public struct LoadedFeed<Payload: SignedPayload>: Sendable {
    public let payload: Payload
    public let storedError: RuleFeedError?
}

public struct FeedUpdate<Payload: SignedPayload>: Sendable {
    public let payload: Payload
    public let changes: Payload.Changes
    public let fileName: String
    let envelope: Data

    public var fullFile: Data {
        guard
            let signed = try? JSONDecoder().decode(SignedEnvelope.self, from: envelope),
            let payload = Data(base64Encoded: signed.rules),
            let object = try? JSONSerialization.jsonObject(with: payload),
            let readable = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return envelope }
        return readable
    }
}

public enum FeedCheck<Payload: SignedPayload>: Sendable {
    case upToDate(remote: Payload)
    case available(FeedUpdate<Payload>)
}

public enum RuleFeedError: LocalizedError, Equatable {
    case unreachable
    case badResponse
    case tooLarge
    case badSignature
    case invalidRules(RulebookError)
    case invalidMalwareFeed(MalwareFeedError)
    case rollback(local: Int, received: Int)
    case outdated(Int)
    case expired(Date)
    case missingDates
    case issuedInFuture(Date)
    case validityTooLong
    case versionAheadOfIssueDate(Int)
    case noLocalCopy
    case couldNotSave

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Could not reach the rules repository. Check your internet connection and try again."
        case .badResponse: "The rules repository sent an unexpected response."
        case .tooLarge: "The downloaded file is larger than allowed."
        case .badSignature: "The file signature is invalid. It was not signed by a trusted key."
        case .invalidRules(let error): error.errorDescription
        case .invalidMalwareFeed(let error): error.errorDescription
        case .rollback(let local, let received): "The repository sent an older version (v\(received)) than the local copy (v\(local)), so it was refused."
        case .outdated(let version): "Rules v\(version) are older than this version of Bluehat accepts. Check for updates in Settings › Rules."
        case .expired(let date): "The signed file expired on \(date.formatted(date: .abbreviated, time: .shortened)). Check for updates in Settings › Rules."
        case .missingDates: "The signed file has no issue or expiry date."
        case .issuedInFuture(let date): "The signed file says it was issued on \(date.formatted(date: .abbreviated, time: .shortened)), which is in the future. Check the Mac's date and time."
        case .validityTooLong: "The signed file is valid for longer than allowed."
        case .versionAheadOfIssueDate(let version): "Version v\(version) is newer than the file's issue date allows."
        case .noLocalCopy: "No signed file was found on this Mac. Check for updates in Settings › Rules, or reinstall Bluehat."
        case .couldNotSave: "The update could not be saved, so the local copy was left as it was."
        }
    }
}

public struct RuleFeed: Sendable {
    public static let trustedKeys = [
        "ejbt4bgFPpvJCdj/67M3kWasEgEs1eKUs9v/ii97PhA=",
        "7QnEa2pH6FwbhIMqMbVO/y2bhumiHbtIqshgdxzKSJA=",
    ].map(publicKey)
    public static let feedKey = publicKey("srVF3Dxj32r6pMW0M+0MMsUdr75RyoD94CafL7iFnoE=")
    public static let minimumVersion = 2026103008
    static let requestTimeout: TimeInterval = 15
    static let downloadTimeout: TimeInterval = 60
    static let dateTolerance: TimeInterval = 24 * 3600
    static let dataDirectory = URL.applicationSupportDirectory.appending(component: "Bluehat")

    public static let rulebook = RuleFeed(
        sourceURL: URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json")!,
        publicKeys: trustedKeys,
        minimumVersion: minimumVersion,
        maxEnvelopeBytes: 2_000_000,
        storedURL: dataDirectory.appending(component: "rules.signed.json"),
        bundledURL: Bundle.main.resourceURL?.appending(component: "rules.signed.json")
    )
    public static let malwareFeed = RuleFeed(
        sourceURL: URL(string: "https://raw.githubusercontent.com/lysari/bluehat-rules/main/feed.signed.json")!,
        publicKeys: [feedKey] + trustedKeys,
        minimumVersion: 0,
        maxEnvelopeBytes: 4_000_000,
        storedURL: dataDirectory.appending(component: "feed.signed.json"),
        bundledURL: Bundle.main.resourceURL?.appending(component: "feed.signed.json")
    )

    let sourceURL: URL
    let publicKeys: [Curve25519.Signing.PublicKey]
    let minimumVersion: Int
    let maxEnvelopeBytes: Int
    let storedURL: URL
    let bundledURL: URL?

    public static func fingerprint(of key: Curve25519.Signing.PublicKey) -> String {
        SHA256.hash(data: key.rawRepresentation).prefix(8).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    static func publicKey(_ base64: String) -> Curve25519.Signing.PublicKey {
        try! Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: base64)!)
    }

    public func load<Payload: SignedPayload>(_ type: Payload.Type, now: Date = .now) throws(RuleFeedError) -> LoadedFeed<Payload> {
        let copy = try localCopy(type, now: now)
        if let expires = copy.payload.expires, expires <= now { throw .expired(expires) }
        return copy
    }

    public func localCopy<Payload: SignedPayload>(_ type: Payload.Type, now: Date = .now) throws(RuleFeedError) -> LoadedFeed<Payload> {
        let copies: LocalCopies<Payload> = localCopies(now: now)
        let unexpired = copies.newestFirst.first { ($0.expires ?? now) > now }
        guard let payload = unexpired ?? copies.newestFirst.first else {
            throw copies.storedError ?? copies.bundledError ?? .noLocalCopy
        }
        return LoadedFeed(payload: payload, storedError: copies.storedError)
    }

    public func check<Payload: SignedPayload>(_ type: Payload.Type, now: Date = .now) async throws(RuleFeedError) -> FeedCheck<Payload> {
        let envelope = try await download()
        return try review(envelope, as: type, now: now)
    }

    func review<Payload: SignedPayload>(_ envelope: Data, as type: Payload.Type, now: Date) throws(RuleFeedError) -> FeedCheck<Payload> {
        let remote: Payload = try Self.open(envelope: envelope, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now)
        let local: Payload? = try newestLocal(notNewerThan: remote, now: now)
        if let local, !Self.isNewer(remote, than: local) { return .upToDate(remote: remote) }
        let fileName = sourceURL.lastPathComponent.replacing(".signed.json", with: "-v\(remote.version).json")
        return .available(FeedUpdate(payload: remote, changes: remote.changes(from: local), fileName: fileName, envelope: envelope))
    }

    public func accept<Payload: SignedPayload>(_ update: FeedUpdate<Payload>, now: Date = .now) throws(RuleFeedError) {
        let verified: Payload = try Self.open(envelope: update.envelope, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now)
        _ = try newestLocal(notNewerThan: verified, now: now)
        do {
            try FileManager.default.createDirectory(at: storedURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try update.envelope.write(to: storedURL, options: .atomic)
        } catch {
            throw .couldNotSave
        }
    }

    private func newestLocal<Payload: SignedPayload>(notNewerThan remote: Payload, now: Date) throws(RuleFeedError) -> Payload? {
        let copies: LocalCopies<Payload> = localCopies(now: now)
        guard let newest = copies.newestFirst.first else { return nil }
        guard remote.version >= newest.version else { throw .rollback(local: newest.version, received: remote.version) }
        return newest
    }

    private static func isNewer<Payload: SignedPayload>(_ remote: Payload, than local: Payload) -> Bool {
        if remote.version != local.version { return remote.version > local.version }
        guard let remoteIssued = remote.issued, let localIssued = local.issued else { return false }
        return remoteIssued > localIssued
    }

    private func localCopies<Payload: SignedPayload>(now: Date) -> LocalCopies<Payload> {
        LocalCopies(stored: openLocal(at: storedURL, now: now), bundled: openLocal(at: bundledURL, now: now))
    }

    private func openLocal<Payload: SignedPayload>(at url: URL?, now: Date) -> Result<Payload, RuleFeedError>? {
        guard let url, (try? FileManager.default.attributesOfItem(atPath: url.path)) != nil else { return nil }
        guard let envelope = RegularFile.read(atPath: url.path, maxBytes: maxEnvelopeBytes, followingSymlinks: false) else { return .failure(.badSignature) }
        do throws(RuleFeedError) {
            return .success(try Self.openIgnoringExpiry(envelope: envelope, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now))
        } catch {
            return .failure(error)
        }
    }

    static func open<Payload: SignedPayload>(envelope: Data, publicKeys: [Curve25519.Signing.PublicKey], minimumVersion: Int, now: Date) throws(RuleFeedError) -> Payload {
        let opened: Payload = try openIgnoringExpiry(envelope: envelope, publicKeys: publicKeys, minimumVersion: minimumVersion, now: now)
        try checkExpiry(of: opened, now: now)
        return opened
    }

    private static func openIgnoringExpiry<Payload: SignedPayload>(envelope: Data, publicKeys: [Curve25519.Signing.PublicKey], minimumVersion: Int, now: Date) throws(RuleFeedError) -> Payload {
        guard
            let decoded = try? JSONDecoder().decode(SignedEnvelope.self, from: envelope),
            let payload = Data(base64Encoded: decoded.rules),
            let signature = Data(base64Encoded: decoded.signature),
            publicKeys.contains(where: { $0.isValidSignature(signature, for: payload) })
        else { throw .badSignature }
        let opened = try Payload.decodePayload(payload)
        guard opened.version >= minimumVersion else { throw .outdated(opened.version) }
        try checkDateLimits(of: opened, now: now)
        return opened
    }

    public static func checkDates<Payload: SignedPayload>(of payload: Payload, now: Date) throws(RuleFeedError) {
        try checkDateLimits(of: payload, now: now)
        try checkExpiry(of: payload, now: now)
    }

    private static func checkExpiry<Payload: SignedPayload>(of payload: Payload, now: Date) throws(RuleFeedError) {
        if let expires = payload.expires, expires <= now { throw .expired(expires) }
    }

    private static func checkDateLimits<Payload: SignedPayload>(of payload: Payload, now: Date) throws(RuleFeedError) {
        guard let issued = payload.issued, let expires = payload.expires else { throw .missingDates }
        guard issued <= now.addingTimeInterval(dateTolerance) else { throw .issuedInFuture(issued) }
        guard expires.timeIntervalSince(issued) <= Payload.maxValidity else { throw .validityTooLong }
        guard payload.version <= latestVersion(issued: issued, format: Payload.versionDateFormat) else { throw .versionAheadOfIssueDate(payload.version) }
    }

    static func latestVersion(issued: Date, format: String) -> Int {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .gmt
        formatter.dateFormat = format
        return Int(formatter.string(from: issued.addingTimeInterval(dateTolerance))) ?? 0
    }

    static var sessionConfiguration: URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = downloadTimeout
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        return configuration
    }

    private func download() async throws(RuleFeedError) -> Data {
        let session = URLSession(configuration: Self.sessionConfiguration, delegate: RedirectBlocker(), delegateQueue: nil)
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

private struct LocalCopies<Payload: SignedPayload> {
    let stored: Result<Payload, RuleFeedError>?
    let bundled: Result<Payload, RuleFeedError>?

    var newestFirst: [Payload] {
        [stored, bundled].compactMap { try? $0?.get() }.sorted { $0.version > $1.version }
    }

    var storedError: RuleFeedError? {
        if case .failure(let error)? = stored { error } else { nil }
    }

    var bundledError: RuleFeedError? {
        if case .failure(let error)? = bundled { error } else { nil }
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
