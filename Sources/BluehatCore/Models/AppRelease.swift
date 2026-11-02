import Foundation

public struct AppRelease: Sendable {
    struct InstallAssets: Sendable {
        let image: URL
        let signature: URL
    }

    static let maxNotesCharacters = 20_000

    public let version: SoftwareVersion
    public let published: Date
    public let notes: String
    public let pageURL: URL
    let installAssets: InstallAssets?

    static func decode(from data: Data) throws(AppUpdateError) -> AppRelease {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        guard
            let decoded = try? decoder.decode(GitHubRelease.self, from: data),
            !decoded.draft,
            !decoded.prerelease,
            decoded.tagName.hasPrefix("v"),
            let version = SoftwareVersion(appRelease: decoded.tagName),
            decoded.htmlUrl.absoluteString == AppUpdater.releasesURL.appending(components: "tag", decoded.tagName).absoluteString
        else { throw .malformedResponse }
        let imageName = "Bluehat-\(decoded.tagName.dropFirst()).dmg"
        let image = try decoded.assetURL(named: imageName)
        let signature = try decoded.assetURL(named: imageName + AppUpdater.signatureSuffix)
        return AppRelease(
            version: version,
            published: decoded.publishedAt,
            notes: String((decoded.body ?? "").prefix(maxNotesCharacters)),
            pageURL: decoded.htmlUrl,
            installAssets: image.flatMap { image in signature.map { InstallAssets(image: image, signature: $0) } }
        )
    }
}

private struct GitHubRelease: Decodable {
    struct Asset: Decodable {
        let name: String
        let browserDownloadUrl: URL
    }

    let tagName: String
    let htmlUrl: URL
    let body: String?
    let draft: Bool
    let prerelease: Bool
    let publishedAt: Date
    let assets: [Asset]

    func assetURL(named name: String) throws(AppUpdateError) -> URL? {
        guard let asset = assets.first(where: { $0.name == name }) else { return nil }
        let expected = AppUpdater.releasesURL.appending(components: "download", tagName, name)
        guard asset.browserDownloadUrl.absoluteString == expected.absoluteString else { throw .malformedResponse }
        return asset.browserDownloadUrl
    }
}
