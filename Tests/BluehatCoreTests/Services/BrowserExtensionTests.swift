import Foundation
import Testing
@testable import BluehatCore

struct BrowserExtensionTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-browser-\(UUID().uuidString)")

    func write(_ json: String, to relativePath: String) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(json.utf8).write(to: url)
    }

    @Test func readsNewestChromiumVersionWithLocalizedName() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let id = "abcdefghijklmnopabcdefghijklmnop"
        try write(#"{"name": "Old", "permissions": []}"#, to: "Default/Extensions/\(id)/1.9_0/manifest.json")
        try write(#"{"name": "__MSG_appName__", "default_locale": "en", "update_url": "https://evil.example/update.xml", "permissions": ["cookies"], "host_permissions": ["<all_urls>"]}"#, to: "Default/Extensions/\(id)/1.10_0/manifest.json")
        try write(#"{"appName": {"message": "PDF Helper"}}"#, to: "Default/Extensions/\(id)/1.10_0/_locales/en/messages.json")

        let extensions = Scanner.chromiumExtensions(browser: "Chrome", root: root.path)

        #expect(extensions.count == 1)
        #expect(extensions.first?.detail == "Chrome: PDF Helper (\(id))")
        #expect(extensions.first?.descriptor == "browser=Chrome id=\(id) name=PDF Helper update=https://evil.example/update.xml permissions=cookies,<all_urls>")
        #expect(extensions.first?.path.hasSuffix("/1.10_0") == true)
    }

    @Test func readsUserFirefoxAddonsAndSkipsBuiltIns() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write(#"""
        {"addons": [
          {"id": "helper@evil.example", "location": "app-profile", "signedState": 0, "path": "/tmp/helper.xpi", "defaultLocale": {"name": "Helper"}, "userPermissions": {"permissions": ["proxy"], "origins": ["<all_urls>"]}},
          {"id": "uBlock0@raymondhill.net", "location": "app-profile", "signedState": 2, "defaultLocale": {"name": "uBlock Origin"}, "userPermissions": {"permissions": ["storage"], "origins": []}},
          {"id": "formautofill@mozilla.org", "location": "app-builtin", "signedState": 3, "defaultLocale": {"name": "Form Autofill"}}
        ]}
        """#, to: "abc.default-release/extensions.json")

        let extensions = Scanner.firefoxExtensions(profilesRoot: root.path)

        #expect(extensions.map(\.detail) == ["Firefox: Helper (helper@evil.example)", "Firefox: uBlock Origin (uBlock0@raymondhill.net)"])
        #expect(extensions.first?.descriptor == "browser=Firefox id=helper@evil.example name=Helper update=none permissions=proxy,<all_urls>")
        #expect(extensions.last?.descriptor.contains("update=addons.mozilla.org") == true)
    }

    @Test func missingBrowsersGiveNoExtensions() {
        #expect(Scanner.chromiumExtensions(browser: "Chrome", root: root.path).isEmpty)
        #expect(Scanner.firefoxExtensions(profilesRoot: root.path).isEmpty)
    }
}
