import CryptoKit
import Foundation

public enum AppUpdateError: LocalizedError, Equatable {
    case unreachable
    case rateLimited(until: Date?)
    case notFound
    case apiFailure(status: Int)
    case malformedResponse
    case cancelled
    case tooLarge
    case couldNotSaveDownload
    case noUpdateKey
    case unsignedRelease
    case badSignature
    case manifestMismatch
    case imageMismatch
    case notInstalled
    case translocated
    case notWritable
    case imageUnusable
    case wrongApp
    case notNewer
    case invalidCodeSignature
    case differentDeveloper
    case replaceFailed
    case launchFailed
    case rollbackFailed(keptAt: String)

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Could not reach GitHub. Check your internet connection and try again."
        case .rateLimited(let until): "GitHub's request limit for this network was reached. \(until.map { "Try again after \($0.formatted(date: .omitted, time: .shortened))." } ?? "Try again later.")"
        case .notFound: "GitHub doesn't have this release or file."
        case .apiFailure(let status): "GitHub returned an error (HTTP \(status)). Try again later."
        case .malformedResponse: "GitHub sent a response Bluehat can't read."
        case .cancelled: "The update was cancelled."
        case .tooLarge: "The download is larger than allowed, so it was stopped."
        case .couldNotSaveDownload: "The download couldn't be saved on this Mac."
        case .noUpdateKey: "This build of Bluehat has no update key, so it can't install updates itself. Download the new version from the Releases page."
        case .unsignedRelease: "This release has no update signature, so Bluehat won't install it. Download it from the Releases page instead."
        case .badSignature: "The update's signature is invalid. It wasn't signed by an update key built into Bluehat, so nothing was installed."
        case .manifestMismatch: "The update's signature doesn't cover this version of Bluehat, so nothing was installed."
        case .imageMismatch: "The download doesn't match its signature, so nothing was installed."
        case .notInstalled: "Bluehat can update itself only when it runs from an Applications folder. Download the new version from the Releases page."
        case .translocated: "macOS is running Bluehat from a temporary location. Move it to Applications and open it from there, or download the new version from the Releases page."
        case .notWritable: "Bluehat doesn't have permission to replace itself in this folder. Download the new version from the Releases page."
        case .imageUnusable: "The downloaded disk image couldn't be opened, so nothing was installed."
        case .wrongApp: "The downloaded disk image doesn't hold the expected version of Bluehat, so nothing was installed."
        case .notNewer: "The update isn't newer than this copy of Bluehat, so nothing was installed."
        case .invalidCodeSignature: "The app in the update has an invalid code signature, so nothing was installed."
        case .differentDeveloper: "The app in the update is signed by a different developer than this copy, so nothing was installed."
        case .replaceFailed: "The installed app couldn't be replaced, so it was left as it was. macOS may be blocking this: check System Settings › Privacy & Security › App Management, or download the new version from the Releases page."
        case .launchFailed: "The new version didn't start, so the previous version was put back."
        case .rollbackFailed(let path): "The new version didn't start and the previous version couldn't be put back. It's saved at \(path)."
        }
    }
}

public enum AppUpdateCheck: Sendable {
    case upToDate
    case available(AppRelease)
}

public enum AppUpdatePhase: Sendable {
    case downloading(received: Int, total: Int)
    case installing
}

struct AppUpdateManifest: Codable {
    let bundleIdentifier: String
    let version: String
    let size: Int
    let sha256: String
}

struct SignedAppUpdate: Codable {
    let manifest: String
    let signature: String
}

struct VerifiedImage: Sendable {
    let file: URL
    let version: SoftwareVersion
}

public struct AppUpdater: Sendable {
    public static let releasesURL = URL(string: "https://github.com/lysari/bluehat/releases")!
    static let bundleIdentifier = "com.lysari.bluehat"
    public static let signatureSuffix = ".sig"
    public static let trustedKeys = ["Sh+Ufbi7L2jndG2c/Ewjd1ZKKfFkR/UF6vL3cO3smmc=", "HV/2K2VR5/QGXvCY/cax4MpJC6LQiremo6a/b1P2+J4="].map(RuleFeed.publicKey)
    public static let standard = AppUpdater(publicKeys: trustedKeys)
    static let latestReleaseURL = URL(string: "https://api.github.com/repos/lysari/bluehat/releases/latest")!
    static let apiHosts: Set<String> = ["api.github.com"]
    static let downloadHosts: Set<String> = ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"]
    static let maxReleaseBytes = 1_000_000
    static let maxSignatureBytes = 16_000
    static let maxImageBytes = Scanner.maxHashedFileBytes
    static let downloadTimeout: TimeInterval = 600
    static let writeChunkBytes = 1 << 18

    let publicKeys: [Curve25519.Signing.PublicKey]

    public func check(currentVersion: SoftwareVersion) async throws(AppUpdateError) -> AppUpdateCheck {
        var request = URLRequest(url: Self.latestReleaseURL)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        let data = try await Self.fetch(request, hosts: Self.apiHosts, maxBytes: Self.maxReleaseBytes)
        return Self.review(try AppRelease.decode(from: data), currentVersion: currentVersion)
    }

    static func review(_ latest: AppRelease, currentVersion: SoftwareVersion) -> AppUpdateCheck {
        latest.version > currentVersion ? .available(latest) : .upToDate
    }

    public func installRefusal(for release: AppRelease, installer: AppInstaller) -> AppUpdateError? {
        if publicKeys.isEmpty { return .noUpdateKey }
        if release.installAssets == nil { return .unsignedRelease }
        return installer.refusal()
    }

    public func update(_ release: AppRelease, installer: AppInstaller, onPhase: @Sendable (AppUpdatePhase) -> Void) async throws(AppUpdateError) -> ReplacedApp {
        if let refusal = installRefusal(for: release, installer: installer) { throw refusal }
        guard let assets = release.installAssets else { throw .unsignedRelease }
        let workspace = FileManager.default.temporaryDirectory.appending(component: "Bluehat-update-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            throw .couldNotSaveDownload
        }
        defer { try? FileManager.default.removeItem(at: workspace) }

        onPhase(.downloading(received: 0, total: 0))
        let signed = try await Self.fetch(URLRequest(url: assets.signature), hosts: Self.downloadHosts, maxBytes: Self.maxSignatureBytes)
        let manifest = try open(signed, for: release.version)
        let file = workspace.appending(component: "update.dmg")
        try await Self.downloadImage(from: assets.image, to: file, size: manifest.size, onPhase: onPhase)
        let image = try Self.verify(imageAt: file, manifest: manifest, version: release.version)
        if Task.isCancelled { throw .cancelled }
        onPhase(.installing)
        return try installer.install(image, workspace: workspace)
    }

    func open(_ signed: Data, for version: SoftwareVersion) throws(AppUpdateError) -> AppUpdateManifest {
        guard !publicKeys.isEmpty else { throw .noUpdateKey }
        guard
            let decoded = try? JSONDecoder().decode(SignedAppUpdate.self, from: signed),
            let manifestData = Data(base64Encoded: decoded.manifest),
            let signature = Data(base64Encoded: decoded.signature),
            publicKeys.contains(where: { $0.isValidSignature(signature, for: manifestData) }),
            let manifest = try? JSONDecoder().decode(AppUpdateManifest.self, from: manifestData)
        else { throw .badSignature }
        guard
            manifest.bundleIdentifier == Self.bundleIdentifier,
            SoftwareVersion(appRelease: manifest.version) == version,
            (1...Self.maxImageBytes).contains(manifest.size),
            manifest.sha256.wholeMatch(of: /[0-9a-f]{64}/) != nil
        else { throw .manifestMismatch }
        return manifest
    }

    static func verify(imageAt file: URL, manifest: AppUpdateManifest, version: SoftwareVersion) throws(AppUpdateError) -> VerifiedImage {
        guard
            let details = RegularFile.open(atPath: file.path, followingSymlinks: false),
            details.size == manifest.size
        else { throw .imageMismatch }
        try? details.handle.close()
        guard Scanner.sha256(of: file) == manifest.sha256 else { throw .imageMismatch }
        return VerifiedImage(file: file, version: version)
    }

    public static func sign(imageAt file: URL, version: String, with key: Curve25519.Signing.PrivateKey) throws(AppUpdateError) -> Data {
        guard
            SoftwareVersion(appRelease: version) != nil,
            let details = RegularFile.open(atPath: file.path, followingSymlinks: false),
            let sha256 = Scanner.sha256(of: file)
        else { throw .imageMismatch }
        try? details.handle.close()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifest = AppUpdateManifest(bundleIdentifier: bundleIdentifier, version: version, size: details.size, sha256: sha256)
        guard
            let manifestData = try? encoder.encode(manifest),
            let signature = try? key.signature(for: manifestData),
            let signed = try? encoder.encode(SignedAppUpdate(manifest: manifestData.base64EncodedString(), signature: signature.base64EncodedString()))
        else { throw .badSignature }
        return signed
    }

    public func confirmSigned(_ signed: Data, imageAt file: URL, version: String) throws(AppUpdateError) {
        guard let parsed = SoftwareVersion(appRelease: version) else { throw .manifestMismatch }
        _ = try Self.verify(imageAt: file, manifest: try open(signed, for: parsed), version: parsed)
    }

    static func validate(_ response: URLResponse, hosts: Set<String>, now: Date = .now) throws(AppUpdateError) {
        guard let http = response as? HTTPURLResponse, GitHubRedirectPolicy.allows(http.url, hosts: hosts) else { throw .malformedResponse }
        switch http.statusCode {
        case 200:
            return
        case 404:
            throw .notFound
        case 403, 429:
            if let retryAfter = http.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init) {
                throw .rateLimited(until: now.addingTimeInterval(retryAfter))
            }
            guard http.value(forHTTPHeaderField: "X-RateLimit-Remaining") == "0" else { throw .apiFailure(status: http.statusCode) }
            throw .rateLimited(until: http.value(forHTTPHeaderField: "X-RateLimit-Reset").flatMap(TimeInterval.init).map(Date.init(timeIntervalSince1970:)))
        default:
            throw .apiFailure(status: http.statusCode)
        }
    }

    static func networkError(_ error: any Error) -> AppUpdateError {
        if error is CancellationError { return .cancelled }
        guard let urlError = error as? URLError else { return .couldNotSaveDownload }
        return urlError.code == .cancelled ? .cancelled : .unreachable
    }

    static func save(_ bytes: some AsyncSequence<UInt8, any Error>, to file: URL, size: Int, onPhase: @Sendable (AppUpdatePhase) -> Void) async throws(AppUpdateError) {
        guard
            FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]),
            let handle = try? FileHandle(forWritingTo: file)
        else { throw .couldNotSaveDownload }
        defer { try? handle.close() }
        var buffer = Data(capacity: writeChunkBytes)
        var received = 0
        func flush() throws {
            received += buffer.count
            guard received <= size else { throw AppUpdateError.tooLarge }
            try Task.checkCancellation()
            try handle.write(contentsOf: buffer)
            buffer.removeAll(keepingCapacity: true)
            onPhase(.downloading(received: received, total: size))
        }
        do {
            for try await byte in bytes {
                buffer.append(byte)
                if buffer.count == writeChunkBytes { try flush() }
            }
            try flush()
        } catch let error as AppUpdateError {
            throw error
        } catch {
            throw networkError(error)
        }
        guard received == size else { throw .imageMismatch }
    }

    private static func session(hosts: Set<String>) -> URLSession {
        let configuration = RuleFeed.sessionConfiguration
        configuration.timeoutIntervalForResource = downloadTimeout
        return URLSession(configuration: configuration, delegate: GitHubRedirectPolicy(allowedHosts: hosts), delegateQueue: nil)
    }

    private static func fetch(_ request: URLRequest, hosts: Set<String>, maxBytes: Int) async throws(AppUpdateError) -> Data {
        let session = session(hosts: hosts)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            try validate(response, hosts: hosts)
            guard response.expectedContentLength <= maxBytes else { throw AppUpdateError.tooLarge }
            var data = Data()
            for try await byte in bytes {
                data.append(byte)
                if data.count > maxBytes { throw AppUpdateError.tooLarge }
            }
            return data
        } catch let error as AppUpdateError {
            throw error
        } catch {
            throw networkError(error)
        }
    }

    private static func downloadImage(from url: URL, to file: URL, size: Int, onPhase: @Sendable (AppUpdatePhase) -> Void) async throws(AppUpdateError) {
        let session = session(hosts: downloadHosts)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(from: url)
            try validate(response, hosts: downloadHosts)
            guard response.expectedContentLength <= size else { throw AppUpdateError.tooLarge }
            try await save(bytes, to: file, size: size, onPhase: onPhase)
        } catch let error as AppUpdateError {
            throw error
        } catch {
            throw networkError(error)
        }
    }
}

final class GitHubRedirectPolicy: NSObject, URLSessionTaskDelegate, Sendable {
    let allowedHosts: Set<String>

    init(allowedHosts: Set<String>) {
        self.allowedHosts = allowedHosts
    }

    static func allows(_ url: URL?, hosts: Set<String>) -> Bool {
        guard
            let url,
            url.scheme == "https",
            url.user == nil,
            url.password == nil,
            url.port == nil || url.port == 443,
            let host = url.host(percentEncoded: false)?.lowercased()
        else { return false }
        return hosts.contains(host)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        Self.allows(request.url, hosts: allowedHosts) ? request : nil
    }
}
