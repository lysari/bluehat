import Foundation
import Testing
@testable import BluehatCore

struct AppReleaseTests {
    func releaseJSON(
        tag: String = "v1.3",
        page: String? = nil,
        draft: Bool = false,
        prerelease: Bool = false,
        published: String = "2026-11-01T07:45:04Z",
        body: String = "\"Notes\"",
        assets: String? = nil
    ) -> Data {
        let page = page ?? "https://github.com/lysari/bluehat/releases/tag/\(tag)"
        let version = tag.dropFirst()
        let assets = assets ?? """
        [{"name": "Bluehat-\(version).dmg", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/\(tag)/Bluehat-\(version).dmg"},
         {"name": "Bluehat-\(version).dmg.sig", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/\(tag)/Bluehat-\(version).dmg.sig"}]
        """
        return Data("""
        {"tag_name": "\(tag)", "html_url": "\(page)", "draft": \(draft), "prerelease": \(prerelease), "published_at": "\(published)", "body": \(body), "assets": \(assets), "name": "ignored"}
        """.utf8)
    }

    @Test func readsAReleaseWithBothAssets() throws {
        let release = try AppRelease.decode(from: releaseJSON())
        #expect(release.version.description == "1.3")
        #expect(release.notes == "Notes")
        #expect(release.published == ISO8601DateFormatter().date(from: "2026-11-01T07:45:04Z"))
        #expect(release.pageURL.absoluteString == "https://github.com/lysari/bluehat/releases/tag/v1.3")
        #expect(release.installAssets?.image.absoluteString == "https://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg")
        #expect(release.installAssets?.signature.absoluteString == "https://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg.sig")
    }

    @Test func nullNotesReadAsEmpty() throws {
        #expect(try AppRelease.decode(from: releaseJSON(body: "null")).notes == "")
    }

    @Test func longNotesAreCut() throws {
        let body = "\"" + String(repeating: "a", count: AppRelease.maxNotesCharacters + 5) + "\""
        #expect(try AppRelease.decode(from: releaseJSON(body: body)).notes.count == AppRelease.maxNotesCharacters)
    }

    @Test func aReleaseWithoutTheSignatureHasNoInstallAssets() throws {
        let assets = #"[{"name": "Bluehat-1.3.dmg", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg"}]"#
        let release = try AppRelease.decode(from: releaseJSON(assets: assets))
        #expect(release.version.description == "1.3")
        #expect(release.installAssets == nil)
    }

    @Test func aReleaseWithoutTheImageHasNoInstallAssets() throws {
        let assets = #"[{"name": "Bluehat-1.3.dmg.sig", "browser_download_url": "https://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg.sig"}]"#
        #expect(try AppRelease.decode(from: releaseJSON(assets: assets)).installAssets == nil)
    }

    @Test(arguments: [
        #"{"message": "Not Found"}"#,
        "not json",
        "",
        "[]",
    ])
    func refusesAnythingThatIsNotARelease(text: String) {
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: Data(text.utf8)) }
    }

    @Test(arguments: ["1.3", "v", "v1.3-beta", "v1.3rc1", "v1.3/../../evil", "latest", "v１.３"])
    func refusesATagThatIsNotAVersion(tag: String) {
        let page = "https://github.com/lysari/bluehat/releases/tag/\(tag)"
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(tag: tag, page: page, assets: "[]")) }
    }

    @Test func refusesDraftsAndPrereleases() {
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(draft: true)) }
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(prerelease: true)) }
    }

    @Test func refusesABadDate() {
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(published: "yesterday")) }
    }

    @Test(arguments: [
        "https://evil.example/lysari/bluehat/releases/tag/v1.3",
        "https://github.com/someone/bluehat/releases/tag/v1.3",
        "http://github.com/lysari/bluehat/releases/tag/v1.3",
        "https://github.com/lysari/bluehat/releases/tag/v1.2",
    ])
    func refusesAPageOutsideThisRepository(page: String) {
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(page: page)) }
    }

    @Test(arguments: [
        "https://evil.example/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg",
        "https://github.com/someone/bluehat/releases/download/v1.3/Bluehat-1.3.dmg",
        "http://github.com/lysari/bluehat/releases/download/v1.3/Bluehat-1.3.dmg",
        "https://github.com/lysari/bluehat/releases/download/v1.2/Bluehat-1.3.dmg",
    ])
    func refusesAnAssetOutsideThisRelease(url: String) {
        let assets = #"[{"name": "Bluehat-1.3.dmg", "browser_download_url": "\#(url)"}]"#
        #expect(throws: AppUpdateError.malformedResponse) { try AppRelease.decode(from: releaseJSON(assets: assets)) }
    }
}
