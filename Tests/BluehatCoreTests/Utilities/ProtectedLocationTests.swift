import Foundation
import Testing
@testable import BluehatCore

struct ProtectedLocationTests {
    @Test(arguments: [
        "/System", "/System/Library/CoreServices", "/usr", "/usr/local/lib/node", "/bin", "/bin/zsh", "/sbin/launchd",
        "/Library", "/Library/Frameworks/Python.framework", "/private/var", "/private/var/db", "/var/db",
    ])
    func refusesEveryListedLocationAndWhatIsInside(path: String) {
        #expect(ProtectedLocation.isListed(path))
    }

    @Test(arguments: ["/", "/private"])
    func refusesAFolderHoldingAListedLocation(path: String) {
        #expect(ProtectedLocation.isListed(path))
    }

    @Test(arguments: [
        "/Users/test/.nvm/versions/node/v16.20.2",
        "/Users/test/Library/Application Support/fnm/node-versions/v16.20.2",
        "/Users/test/usr/bin",
        "/Library2/node",
        "/usrlocal/node",
        "/binary",
        "/private/tmp/node",
    ])
    func allowsOtherPaths(path: String) {
        #expect(!ProtectedLocation.isListed(path))
    }

    @Test(arguments: ["/SYSTEM/Library", "/LIBRARY/x", "/Users/test/../../System/x", "/Users/test/./../../usr/x", "//usr//local"])
    func cantBeAvoidedWithCaseOrDots(path: String) {
        #expect(ProtectedLocation.isListed(path))
    }

    @Test func resolvesLinksInParentFolders() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-protected-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appending(path: "real"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "link").path, withDestinationPath: root.appending(path: "real").path)
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "system").path, withDestinationPath: "/usr/lib")
        let realRoot = try #require(ProtectedLocation.resolvedPath(root.appending(path: "real").path)).replacingOccurrences(of: "/real", with: "")

        #expect(ProtectedLocation.resolvedPath(root.appending(path: "link/v16").path) == realRoot + "/real/v16")
        #expect(ProtectedLocation.resolvedPath(root.appending(path: "system/v16").path) == "/usr/lib/v16")
        #expect(ProtectedLocation.contains(root.appending(path: "system/v16").path))
    }

    @Test func aLinkItselfStaysWhereItIs() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-protected-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "system").path, withDestinationPath: "/usr/lib")

        let resolved = try #require(ProtectedLocation.resolvedPath(root.appending(path: "system").path))

        #expect(resolved.hasSuffix("/system"))
        #expect(!resolved.hasPrefix("/usr/lib"))
    }

    @Test func aMissingParentLeavesTheWrittenPathToDecide() {
        #expect(ProtectedLocation.resolvedPath("/Users/test/does-not-exist/v16") == nil)
        #expect(!ProtectedLocation.contains("/Users/test/does-not-exist/v16"))
        #expect(ProtectedLocation.contains("/usr/does-not-exist/v16"))
    }
}
