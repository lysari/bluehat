import Foundation
import Testing
@testable import BluehatCore

@Suite(.serialized)
struct AppInstallerTests {
    let root: URL
    let folder: URL
    let bundleIdentifier = "com.example.bluehat-update-test"

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "bluehat-installer-\(UUID().uuidString)").resolvingSymlinksInPath()
        folder = root.appending(component: "Applications")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    func cleanUp() {
        _ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
        try? FileManager.default.removeItem(at: root)
    }

    func version(_ text: String) throws -> SoftwareVersion {
        try #require(SoftwareVersion(appRelease: text))
    }

    @discardableResult
    func makeApp(at url: URL, version: String, identifier: String? = nil, signed: Bool = true) throws -> URL {
        let contents = url.appending(component: "Contents")
        let macOS = contents.appending(component: "MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: macOS.appending(component: "Bluehat"))
        let plist: [String: Any] = [
            "CFBundleExecutable": "Bluehat",
            "CFBundleIdentifier": identifier ?? bundleIdentifier,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": "1",
        ]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: contents.appending(component: "Info.plist"))
        if signed {
            _ = Scanner.runTool("/usr/bin/codesign", ["--force", "--sign", "-", url.path])
        }
        return url
    }

    func installer(app: URL, running: String = "1.2", requiredTeam: String? = nil, folders: [URL]? = nil) throws -> AppInstaller {
        AppInstaller(app: app, bundleIdentifier: bundleIdentifier, runningVersion: try version(running), requiredTeam: requiredTeam, installFolders: folders ?? [folder])
    }

    func installedVersion(at app: URL) throws -> String {
        let data = try Data(contentsOf: app.appending(components: "Contents", "Info.plist"))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        return try #require(plist["CFBundleShortVersionString"] as? String)
    }

    func makeImage(holding apps: [URL]) throws -> URL {
        let staging = root.appending(component: "image-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
        for app in apps {
            try FileManager.default.moveItem(at: app, to: staging.appending(component: app.lastPathComponent))
        }
        let image = root.appending(component: "\(UUID().uuidString).dmg")
        _ = Scanner.runTool("/usr/bin/hdiutil", ["create", "-volname", "BluehatTest", "-srcfolder", staging.path, "-format", "UDZO", "-ov", image.path], timeout: 120)
        #expect(FileManager.default.fileExists(atPath: image.path))
        return image
    }

    func isMountedAnywhere(_ workspace: URL) -> Bool {
        Scanner.runTool("/sbin/mount", []).contains(workspace.lastPathComponent)
    }

    func stagingFolders() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { $0.hasPrefix(AppInstaller.stagingPrefix) }
    }

    @Test func allowsAnAppInAnInstallFolder() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        #expect(try installer(app: app).refusal() == nil)
    }

    @Test func refusesABuildFolder() throws {
        defer { cleanUp() }
        let app = try makeApp(at: root.appending(components: ".build", "Bluehat.app"), version: "1.2")
        #expect(try installer(app: app).refusal() == .notInstalled)
    }

    @Test func refusesASwiftRunBinary() throws {
        defer { cleanUp() }
        #expect(try installer(app: folder.appending(component: "debug")).refusal() == .notInstalled)
    }

    @Test func refusesASubfolderOfAnInstallFolder() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(components: "Utilities", "Bluehat.app"), version: "1.2")
        #expect(try installer(app: app).refusal() == .notInstalled)
    }

    @Test func refusesATranslocatedApp() throws {
        defer { cleanUp() }
        let parent = root.appending(components: "AppTranslocation", "ABC", "d")
        let app = try makeApp(at: parent.appending(component: "Bluehat.app"), version: "1.2")
        #expect(try installer(app: app, folders: [parent]).refusal() == .translocated)
    }

    @Test func refusesAFolderItCannotWrite() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: folder.path)
        #expect(try installer(app: app).refusal() == .notWritable)
    }

    @Test func installFoldersForTheRunningAppAreApplicationsOnly() throws {
        defer { cleanUp() }
        let folders = AppInstaller.running(version: try version("1.2")).installFolders.map(\.path)
        #expect(folders.first == "/Applications")
        #expect(folders.count == 2)
        #expect(folders[1].hasSuffix("/Applications"))
    }

    @Test func aTestRunnerIsNotAnInstalledApp() throws {
        defer { cleanUp() }
        #expect(AppInstaller.running(version: try version("1.2")).refusal() == .notInstalled)
    }

    @Test func acceptsAValidNewerApp() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.10")
        try installer(app: folder.appending(component: "Bluehat.app"), running: "1.9").inspect(candidate, expected: try version("1.10"))
    }

    @Test func refusesTheWrongBundleIdentifier() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3", identifier: "com.example.other")
        #expect(throws: AppUpdateError.wrongApp) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test func refusesAVersionOtherThanTheSignedOne() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.4")
        #expect(throws: AppUpdateError.wrongApp) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test(arguments: ["1.2", "1.1", "1.2.0"])
    func refusesAnAppThatIsNotNewer(candidateVersion: String) throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: candidateVersion)
        #expect(throws: AppUpdateError.notNewer) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version(candidateVersion))
        }
    }

    @Test func refusesAnUnsignedApp() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3", signed: false)
        #expect(throws: AppUpdateError.invalidCodeSignature) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test func refusesAnAppChangedAfterSigning() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let binary = candidate.appending(components: "Contents", "MacOS", "Bluehat")
        var bytes = try Data(contentsOf: binary)
        bytes[bytes.count / 2] ^= 1
        try bytes.write(to: binary)
        #expect(throws: AppUpdateError.invalidCodeSignature) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test func refusesAPlistChangedAfterSigning() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let plist = candidate.appending(components: "Contents", "Info.plist")
        let changed = String(decoding: try Data(contentsOf: plist), as: UTF8.self) + "\n"
        try Data(changed.utf8).write(to: plist)
        #expect(throws: AppUpdateError.invalidCodeSignature) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test func refusesAnotherDeveloper() throws {
        defer { cleanUp() }
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        #expect(throws: AppUpdateError.differentDeveloper) {
            try installer(app: folder.appending(component: "Bluehat.app"), requiredTeam: "TEAM123456").inspect(candidate, expected: try version("1.3"))
        }
    }

    @Test func refusesASymlinkInPlaceOfTheApp() throws {
        defer { cleanUp() }
        let real = try makeApp(at: root.appending(component: "Real.app"), version: "1.3")
        let link = root.appending(component: "Bluehat.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        #expect(throws: AppUpdateError.wrongApp) {
            try installer(app: folder.appending(component: "Bluehat.app")).inspect(link, expected: try version("1.3"))
        }
    }

    @Test func replacesTheAppAndKeepsThePreviousUntilCommit() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let replaced = try installer(app: app).replace(with: candidate, expected: try version("1.3"))
        #expect(try installedVersion(at: app) == "1.3")
        #expect(try installedVersion(at: replaced.previous) == "1.2")
        #expect(AppInstaller.hasValidCodeSignature(app))
        replaced.commit()
        #expect(try stagingFolders().isEmpty)
        #expect(try installedVersion(at: app) == "1.3")
    }

    @Test func rollBackRestoresThePreviousApp() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let replaced = try installer(app: app).replace(with: candidate, expected: try version("1.3"))
        try replaced.rollBack()
        #expect(try installedVersion(at: app) == "1.2")
        #expect(AppInstaller.hasValidCodeSignature(app))
        #expect(try stagingFolders().isEmpty)
    }

    @Test func aFailedRollBackKeepsThePreviousAppAndSaysWhere() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let replaced = try installer(app: app).replace(with: candidate, expected: try version("1.3"))
        try FileManager.default.removeItem(at: app)
        #expect(throws: AppUpdateError.rollbackFailed(keptAt: replaced.previous.path)) { try replaced.rollBack() }
        #expect(try installedVersion(at: replaced.previous) == "1.2")
    }

    @Test func aBadCandidateLeavesTheAppUntouched() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3", signed: false)
        #expect(throws: AppUpdateError.invalidCodeSignature) {
            try installer(app: app).replace(with: candidate, expected: try version("1.3"))
        }
        #expect(try installedVersion(at: app) == "1.2")
        #expect(AppInstaller.hasValidCodeSignature(app))
        #expect(try stagingFolders().isEmpty)
    }

    @Test func aMissingCandidateLeavesTheAppUntouched() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        #expect(throws: AppUpdateError.wrongApp) {
            try installer(app: app).replace(with: root.appending(component: "Missing.app"), expected: try version("1.3"))
        }
        #expect(try installedVersion(at: app) == "1.2")
        #expect(try stagingFolders().isEmpty)
    }

    @Test func refusesWhenTheCopyOnDiskIsAlreadyAsNew() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.3")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        #expect(throws: AppUpdateError.notNewer) {
            try installer(app: app, running: "1.2").replace(with: candidate, expected: try version("1.3"))
        }
        #expect(try installedVersion(at: app) == "1.3")
        #expect(try stagingFolders().isEmpty)
    }

    @Test func refusesWhenSomethingElseIsAtTheInstallPath() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2", identifier: "com.example.other")
        let candidate = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        #expect(throws: AppUpdateError.replaceFailed) {
            try installer(app: app).replace(with: candidate, expected: try version("1.3"))
        }
        #expect(try installedVersion(at: app) == "1.2")
        #expect(try stagingFolders().isEmpty)
    }

    @Test func installsFromAMountedImageAndUnmounts() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let abandoned = folder.appending(component: AppInstaller.stagingPrefix + "abandoned")
        try FileManager.default.createDirectory(at: abandoned, withIntermediateDirectories: true)
        let unrelated = folder.appending(component: "Other.app")
        try FileManager.default.createDirectory(at: unrelated, withIntermediateDirectories: true)
        let contained = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.3")
        let file = try makeImage(holding: [contained])
        let workspace = root.appending(component: "workspace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)

        let replaced = try installer(app: app).install(VerifiedImage(file: file, version: try version("1.3")), workspace: workspace)

        #expect(try installedVersion(at: app) == "1.3")
        #expect(AppInstaller.hasValidCodeSignature(app))
        #expect(try installedVersion(at: replaced.previous) == "1.2")
        #expect(!isMountedAnywhere(workspace))
        #expect(!FileManager.default.fileExists(atPath: abandoned.path))
        #expect(FileManager.default.fileExists(atPath: unrelated.path))
        replaced.commit()
        #expect(try stagingFolders().isEmpty)
    }

    @Test func anImageWithTheWrongAppUnmountsAndChangesNothing() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let contained = try makeApp(at: root.appending(component: "Bluehat.app"), version: "1.1")
        let file = try makeImage(holding: [contained])
        let workspace = root.appending(component: "workspace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)

        #expect(throws: AppUpdateError.wrongApp) {
            try installer(app: app).install(VerifiedImage(file: file, version: try version("1.3")), workspace: workspace)
        }
        #expect(try installedVersion(at: app) == "1.2")
        #expect(!isMountedAnywhere(workspace))
        #expect(try stagingFolders().isEmpty)
    }

    @Test func anImageWithoutBluehatUnmountsAndChangesNothing() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let other = try makeApp(at: root.appending(component: "Other.app"), version: "1.3")
        let file = try makeImage(holding: [other])
        let workspace = root.appending(component: "workspace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)

        #expect(throws: AppUpdateError.imageUnusable) {
            try installer(app: app).install(VerifiedImage(file: file, version: try version("1.3")), workspace: workspace)
        }
        #expect(try installedVersion(at: app) == "1.2")
        #expect(!isMountedAnywhere(workspace))
    }

    @Test func aFileThatIsNotADiskImageChangesNothing() throws {
        defer { cleanUp() }
        let app = try makeApp(at: folder.appending(component: "Bluehat.app"), version: "1.2")
        let file = root.appending(component: "not-an-image.dmg")
        try Data("not a disk image".utf8).write(to: file)
        let workspace = root.appending(component: "workspace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)

        #expect(throws: AppUpdateError.imageUnusable) {
            try installer(app: app).install(VerifiedImage(file: file, version: try version("1.3")), workspace: workspace)
        }
        #expect(try installedVersion(at: app) == "1.2")
    }

    @Test func refusesToInstallFromABuildFolder() throws {
        defer { cleanUp() }
        let app = try makeApp(at: root.appending(components: ".build", "Bluehat.app"), version: "1.2")
        #expect(throws: AppUpdateError.notInstalled) {
            try installer(app: app).install(VerifiedImage(file: root.appending(component: "x.dmg"), version: try version("1.3")), workspace: root)
        }
        #expect(try installedVersion(at: app) == "1.2")
    }
}
