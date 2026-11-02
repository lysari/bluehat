import CryptoKit
import Foundation
import Testing
@testable import BluehatCore

struct AppUpdaterTests {
    let key = Curve25519.Signing.PrivateKey()
    let directory = FileManager.default.temporaryDirectory.appending(path: "bluehat-updater-\(UUID().uuidString)")
    let imageBytes = Data("disk image bytes".utf8)

    var updater: AppUpdater {
        AppUpdater(publicKeys: [key.publicKey])
    }

    func version(_ text: String) throws -> SoftwareVersion {
        try #require(SoftwareVersion(appRelease: text))
    }

    func release(_ text: String, assets: Bool = true) throws -> AppRelease {
        let page = "https://github.com/lysari/bluehat/releases/tag/v\(text)"
        let list = assets ? """
        [{"name": "Bluehat-\(text).dmg", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/v\(text)/Bluehat-\(text).dmg"},
         {"name": "Bluehat-\(text).dmg.sig", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/v\(text)/Bluehat-\(text).dmg.sig"}]
        """ : "[]"
        return try AppRelease.decode(from: Data(#"{"tag_name": "v\#(text)", "html_url": "\#(page)", "draft": false, "prerelease": false, "published_at": "2026-11-01T07:45:04Z", "body": null, "assets": \#(list)}"#.utf8))
    }

    func writeImage(_ bytes: Data? = nil) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appending(component: "Bluehat.dmg")
        try (bytes ?? imageBytes).write(to: file)
        return file
    }

    func signedManifest(_ manifest: AppUpdateManifest, by signer: Curve25519.Signing.PrivateKey? = nil) throws -> Data {
        let data = try JSONEncoder().encode(manifest)
        let signature = try (signer ?? key).signature(for: data)
        return try JSONEncoder().encode(SignedAppUpdate(manifest: data.base64EncodedString(), signature: signature.base64EncodedString()))
    }

    func manifest(bundleIdentifier: String = AppUpdater.bundleIdentifier, version: String = "1.3", size: Int? = nil, sha256: String? = nil) -> AppUpdateManifest {
        let hash = SHA256.hash(data: imageBytes).map { String(format: "%02x", $0) }.joined()
        return AppUpdateManifest(bundleIdentifier: bundleIdentifier, version: version, size: size ?? imageBytes.count, sha256: sha256 ?? hash)
    }

    func http(_ status: Int, url: String = "https://api.github.com/repos/lysari/bluehat/releases/latest", headers: [String: String] = [:]) -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: url)!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
    }

    func stream(_ bytes: Data) -> AsyncThrowingStream<UInt8, any Error> {
        AsyncThrowingStream { continuation in
            for byte in bytes { continuation.yield(byte) }
            continuation.finish()
        }
    }

    @Test func offersOnlyANewerVersion() throws {
        func isOffered(latest: String, current: String) throws -> Bool {
            if case .available = AppUpdater.review(try release(latest), currentVersion: try version(current)) { return true }
            return false
        }
        #expect(try isOffered(latest: "1.10", current: "1.9"))
        #expect(try isOffered(latest: "1.3", current: "1.2"))
        #expect(try !isOffered(latest: "1.2", current: "1.2"))
        #expect(try !isOffered(latest: "1.2.0", current: "1.2"))
        #expect(try !isOffered(latest: "1.1", current: "1.2"))
        #expect(try !isOffered(latest: "1.9", current: "1.10"))
    }

    @Test func aSignedUpdateRoundTrips() throws {
        let file = try writeImage()
        defer { try? FileManager.default.removeItem(at: directory) }
        let signed = try AppUpdater.sign(imageAt: file, version: "1.3", with: key)
        try updater.confirmSigned(signed, imageAt: file, version: "1.3")
        let opened = try updater.open(signed, for: try version("1.3"))
        #expect(opened.bundleIdentifier == AppUpdater.bundleIdentifier)
        #expect(opened.size == imageBytes.count)
    }

    @Test func refusesAnotherKeysSignature() throws {
        let signed = try signedManifest(manifest(), by: Curve25519.Signing.PrivateKey())
        #expect(throws: AppUpdateError.badSignature) { try updater.open(signed, for: try version("1.3")) }
    }

    @Test func refusesEverythingWithNoKeyConfigured() throws {
        let signed = try signedManifest(manifest())
        #expect(throws: AppUpdateError.noUpdateKey) { try AppUpdater(publicKeys: []).open(signed, for: try version("1.3")) }
    }

    @Test func refusesAChangedManifest() throws {
        let data = try JSONEncoder().encode(manifest())
        let signature = try key.signature(for: data)
        let changed = try JSONEncoder().encode(manifest(version: "1.4"))
        let signed = try JSONEncoder().encode(SignedAppUpdate(manifest: changed.base64EncodedString(), signature: signature.base64EncodedString()))
        #expect(throws: AppUpdateError.badSignature) { try updater.open(signed, for: try version("1.4")) }
    }

    @Test(arguments: ["", "not json", "{}", #"{"manifest": "!!!", "signature": "!!!"}"#])
    func refusesGarbageSignatureFiles(text: String) throws {
        #expect(throws: AppUpdateError.badSignature) { try updater.open(Data(text.utf8), for: try version("1.3")) }
    }

    @Test func refusesASignedManifestThatIsNotAManifest() throws {
        let data = Data(#"{"rules": []}"#.utf8)
        let signature = try key.signature(for: data)
        let signed = try JSONEncoder().encode(SignedAppUpdate(manifest: data.base64EncodedString(), signature: signature.base64EncodedString()))
        #expect(throws: AppUpdateError.badSignature) { try updater.open(signed, for: try version("1.3")) }
    }

    @Test func refusesAnOldSignatureReplayedUnderANewTag() throws {
        let signed = try signedManifest(manifest(version: "1.3"))
        #expect(throws: AppUpdateError.manifestMismatch) { try updater.open(signed, for: try version("1.4")) }
    }

    @Test func refusesAnotherProductsManifest() throws {
        let signed = try signedManifest(manifest(bundleIdentifier: "com.example.other"))
        #expect(throws: AppUpdateError.manifestMismatch) { try updater.open(signed, for: try version("1.3")) }
    }

    @Test(arguments: [0, -1, Scanner.maxHashedFileBytes + 1])
    func refusesAnImpossibleSize(size: Int) throws {
        let signed = try signedManifest(manifest(size: size))
        #expect(throws: AppUpdateError.manifestMismatch) { try updater.open(signed, for: try version("1.3")) }
    }

    @Test(arguments: ["", "abc", String(repeating: "A", count: 64), String(repeating: "g", count: 64)])
    func refusesAMalformedHash(hash: String) throws {
        let signed = try signedManifest(manifest(sha256: hash))
        #expect(throws: AppUpdateError.manifestMismatch) { try updater.open(signed, for: try version("1.3")) }
    }

    @Test func refusesAnImageThatDoesNotMatchItsSignature() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        var changed = imageBytes
        changed[0] ^= 1
        let sameSize = try writeImage(changed)
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.verify(imageAt: sameSize, manifest: manifest(), version: try version("1.3")) }
        let longer = try writeImage(imageBytes + Data([0]))
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.verify(imageAt: longer, manifest: manifest(), version: try version("1.3")) }
        let missing = directory.appending(component: "missing.dmg")
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.verify(imageAt: missing, manifest: manifest(), version: try version("1.3")) }
    }

    @Test func refusesASymlinkInPlaceOfTheImage() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let real = try writeImage()
        let link = directory.appending(component: "link.dmg")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.verify(imageAt: link, manifest: manifest(), version: try version("1.3")) }
    }

    @Test func acceptsTheMatchingImage() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = try writeImage()
        let image = try AppUpdater.verify(imageAt: file, manifest: manifest(), version: try version("1.3"))
        #expect(image.file == file)
        #expect(image.version == (try version("1.3")))
    }

    @Test func confirmSignedRefusesAnImageChangedAfterSigning() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = try writeImage()
        let signed = try AppUpdater.sign(imageAt: file, version: "1.3", with: key)
        try Data("other bytes".utf8).write(to: file)
        #expect(throws: AppUpdateError.imageMismatch) { try updater.confirmSigned(signed, imageAt: file, version: "1.3") }
        #expect(throws: AppUpdateError.manifestMismatch) { try updater.confirmSigned(signed, imageAt: file, version: "not a version") }
    }

    @Test func signRefusesAnUnusableVersionOrFile() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = try writeImage()
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.sign(imageAt: file, version: "1.3-beta", with: key) }
        #expect(throws: AppUpdateError.imageMismatch) { try AppUpdater.sign(imageAt: directory.appending(component: "missing"), version: "1.3", with: key) }
    }

    @Test func updateKeysStaySeparateFromRulesKeys() {
        let rulesKeys = Set((RuleFeed.trustedKeys + [RuleFeed.feedKey]).map(\.rawRepresentation))
        #expect(rulesKeys.isDisjoint(with: AppUpdater.trustedKeys.map(\.rawRepresentation)))
    }

    @Test func refusesToInstallWithoutAKeyOrASignatureAsset() throws {
        let installer = AppInstaller(
            app: directory.appending(component: "Bluehat.app"),
            bundleIdentifier: AppUpdater.bundleIdentifier,
            runningVersion: try version("1.2"),
            requiredTeam: nil,
            installFolders: []
        )
        #expect(AppUpdater(publicKeys: []).installRefusal(for: try release("1.3"), installer: installer) == .noUpdateKey)
        #expect(updater.installRefusal(for: try release("1.3", assets: false), installer: installer) == .unsignedRelease)
        #expect(updater.installRefusal(for: try release("1.3"), installer: installer) == .notInstalled)
    }

    @Test(arguments: [
        ("https://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg", true),
        ("https://release-assets.githubusercontent.com/github-production-release-asset/1/x", true),
        ("https://objects.githubusercontent.com/github-production-release-asset-2e65be/x", true),
        ("https://GitHub.com/lysari/bluehat", true),
        ("https://github.com:443/lysari/bluehat", true),
        ("http://github.com/lysari/bluehat", false),
        ("http://release-assets.githubusercontent.com/x", false),
        ("ftp://github.com/x", false),
        ("https://github.com:8443/x", false),
        ("https://evil.example/x", false),
        ("https://github.com.evil.example/x", false),
        ("https://evilgithub.com/x", false),
        ("https://github.com@evil.example/x", false),
        ("https://user:pass@github.com/x", false),
        ("https://api.github.com/x", false),
        ("https://raw.githubusercontent.com/x", false),
        ("https://githubusercontent.com/x", false),
        ("https://127.0.0.1/x", false),
    ])
    func redirectsStayOnGitHubDownloadHosts(url: String, isAllowed: Bool) {
        #expect(GitHubRedirectPolicy.allows(URL(string: url), hosts: AppUpdater.downloadHosts) == isAllowed)
    }

    @Test func refusesAMissingRedirectTarget() {
        #expect(!GitHubRedirectPolicy.allows(nil, hosts: AppUpdater.downloadHosts))
    }

    @Test func theAPICheckAllowsOnlyTheAPIHost() {
        #expect(GitHubRedirectPolicy.allows(AppUpdater.latestReleaseURL, hosts: AppUpdater.apiHosts))
        #expect(!GitHubRedirectPolicy.allows(URL(string: "https://github.com/lysari/bluehat"), hosts: AppUpdater.apiHosts))
    }

    @Test func theRedirectDelegateFollowsThePolicy() async throws {
        let policy = GitHubRedirectPolicy(allowedHosts: AppUpdater.downloadHosts)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URLRequest(url: URL(string: "https://github.com/x")!))
        let allowed = URLRequest(url: URL(string: "https://release-assets.githubusercontent.com/x")!)
        let refused = URLRequest(url: URL(string: "https://evil.example/x")!)
        #expect(await policy.urlSession(session, task: task, willPerformHTTPRedirection: http(302), newRequest: allowed) != nil)
        #expect(await policy.urlSession(session, task: task, willPerformHTTPRedirection: http(302), newRequest: refused) == nil)
    }

    @Test func acceptsOnlyASuccessFromAnAllowedHost() throws {
        try AppUpdater.validate(http(200), hosts: AppUpdater.apiHosts)
        #expect(throws: AppUpdateError.malformedResponse) { try AppUpdater.validate(http(200, url: "https://evil.example/x"), hosts: AppUpdater.apiHosts) }
        #expect(throws: AppUpdateError.malformedResponse) { try AppUpdater.validate(URLResponse(), hosts: AppUpdater.apiHosts) }
    }

    @Test func namesEachGitHubFailure() {
        let now = Date(timeIntervalSince1970: 1_000)
        let hosts = AppUpdater.apiHosts
        #expect(throws: AppUpdateError.notFound) { try AppUpdater.validate(http(404), hosts: hosts) }
        #expect(throws: AppUpdateError.apiFailure(status: 500)) { try AppUpdater.validate(http(500), hosts: hosts) }
        #expect(throws: AppUpdateError.apiFailure(status: 302)) { try AppUpdater.validate(http(302), hosts: hosts) }
        #expect(throws: AppUpdateError.apiFailure(status: 403)) { try AppUpdater.validate(http(403), hosts: hosts) }
        #expect(throws: AppUpdateError.rateLimited(until: Date(timeIntervalSince1970: 2_000))) {
            try AppUpdater.validate(http(403, headers: ["X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "2000"]), hosts: hosts)
        }
        #expect(throws: AppUpdateError.rateLimited(until: nil)) {
            try AppUpdater.validate(http(429, headers: ["X-RateLimit-Remaining": "0"]), hosts: hosts)
        }
        #expect(throws: AppUpdateError.rateLimited(until: Date(timeIntervalSince1970: 1_060))) {
            try AppUpdater.validate(http(429, headers: ["Retry-After": "60"]), hosts: hosts, now: now)
        }
    }

    @Test func namesOfflineAndCancelled() {
        #expect(AppUpdater.networkError(URLError(.notConnectedToInternet)) == .unreachable)
        #expect(AppUpdater.networkError(URLError(.timedOut)) == .unreachable)
        #expect(AppUpdater.networkError(URLError(.serverCertificateUntrusted)) == .unreachable)
        #expect(AppUpdater.networkError(URLError(.cancelled)) == .cancelled)
        #expect(AppUpdater.networkError(CancellationError()) == .cancelled)
        #expect(AppUpdater.networkError(CocoaError(.fileWriteOutOfSpace)) == .couldNotSaveDownload)
    }

    @Test func savesADownloadAndReportsProgress() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = Data(repeating: 7, count: AppUpdater.writeChunkBytes + 10)
        let file = directory.appending(component: "update.dmg")
        let log = PhaseLog()
        try await AppUpdater.save(stream(bytes), to: file, size: bytes.count) { log.add($0) }
        #expect(try Data(contentsOf: file) == bytes)
        #expect(log.received == [AppUpdater.writeChunkBytes, bytes.count])
    }

    @Test func stopsADownloadPastItsSignedSize() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "update.dmg")
        await #expect(throws: AppUpdateError.tooLarge) {
            try await AppUpdater.save(stream(Data(repeating: 7, count: 20)), to: file, size: 10) { _ in }
        }
    }

    @Test func refusesAShortDownload() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "update.dmg")
        await #expect(throws: AppUpdateError.imageMismatch) {
            try await AppUpdater.save(stream(Data(repeating: 7, count: 5)), to: file, size: 10) { _ in }
        }
    }

    @Test func aCancelledDownloadStops() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(component: "update.dmg")
        let bytes = stream(Data(repeating: 7, count: 10))
        let task = Task {
            try? await Task.sleep(for: .seconds(60))
            do throws(AppUpdateError) {
                try await AppUpdater.save(bytes, to: file, size: 10) { _ in }
                return AppUpdateError?.none
            } catch {
                return error
            }
        }
        task.cancel()
        #expect(await task.value == .cancelled)
    }
}

private final class PhaseLog: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Int] = []

    var received: [Int] {
        lock.withLock { values }
    }

    func add(_ phase: AppUpdatePhase) {
        if case .downloading(let received, _) = phase {
            lock.withLock { values.append(received) }
        }
    }
}
