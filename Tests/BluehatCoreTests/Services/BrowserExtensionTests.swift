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
        #expect(extensions.first?.descriptor == "browser=Chrome id=\(id) name=PDF_Helper update=https://evil.example/update.xml permissions=cookies,<all_urls>")
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

    func starterRule(_ id: String) throws -> Rule {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(components: "rules", "rules.json")
        return try #require(try Rulebook.decode(from: Data(contentsOf: url)).rules.first { $0.id == id })
    }

    @Test func whitespaceInsideFieldsCannotSplitThem() throws {
        let record = Scanner.extensionRecord(browser: "Chrome", id: "a b", name: "PDF\tHelper permissions=", update: "none", permissions: ["cookies", "x y", "proxy", "<all_urls>"], path: "/x")
        #expect(record.descriptor == "browser=Chrome id=a_b name=PDF_Helper_permissions= update=none permissions=cookies,x_y,proxy,<all_urls>")
        #expect(record.detail == "Chrome: PDF\tHelper permissions= (a b)")
        for id in ["extension.cookie-access", "extension.debugger-proxy"] {
            #expect(Scanner.matches(Scanner.regexes(try starterRule(id).patterns), record.descriptor))
        }
    }

    @Test func localeCannotLeaveTheLocalesFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appending(path: "Default/Extensions/id/1.0")
        try write(#"{"appName": {"message": "Escaped"}}"#, to: "Default/Extensions/x/messages.json")
        try write(#"{"appName": {"message": "Escaped"}}"#, to: "Default/Extensions/id/1.0/_locales/../../../x/messages.json")
        #expect(Scanner.localizedName("__MSG_appName__", manifest: ["default_locale": "../../../x"], directory: directory.path) == "__MSG_appName__")
        #expect(Scanner.localizedName("__MSG_appName__", manifest: ["default_locale": String(repeating: "a", count: 17)], directory: directory.path) == "__MSG_appName__")
    }

    @Test func symlinkedMessagesAreNotFollowed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write(#"{"appName": {"message": "Elsewhere"}}"#, to: "elsewhere.json")
        try write(#"{"appName": {"message": "Real"}}"#, to: "ext/_locales/pt_BR/messages.json")
        try FileManager.default.createDirectory(at: root.appending(path: "ext/_locales/en"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: root.appending(path: "ext/_locales/en/messages.json"), withDestinationURL: root.appending(path: "elsewhere.json"))
        let directory = root.appending(path: "ext").path
        #expect(Scanner.localizedName("__MSG_appName__", manifest: ["default_locale": "pt_BR"], directory: directory) == "Real")
        #expect(Scanner.localizedName("__MSG_appName__", manifest: ["default_locale": "en"], directory: directory) == "__MSG_appName__")
    }

    @Test func missingBrowsersGiveNoExtensions() {
        #expect(Scanner.chromiumExtensions(browser: "Chrome", root: root.path).isEmpty)
        #expect(Scanner.firefoxExtensions(profilesRoot: root.path).isEmpty)
    }
}
