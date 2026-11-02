import Foundation
import Security

public struct ReplacedApp: Sendable {
    public let app: URL
    let previous: URL

    private var staging: URL {
        previous.deletingLastPathComponent()
    }

    public func commit() {
        try? FileManager.default.removeItem(at: staging)
    }

    public func rollBack() throws(AppUpdateError) {
        guard renamex_np(previous.path, app.path, UInt32(RENAME_SWAP)) == 0 else { throw .rollbackFailed(keptAt: previous.path) }
        try? FileManager.default.removeItem(at: staging)
    }
}

public struct AppInstaller: Sendable {
    static let stagingPrefix = ".Bluehat-update-"
    static let imageAppName = "Bluehat.app"
    static let translocationFolder = "/AppTranslocation/"
    static let maxInfoPlistBytes = 1_000_000
    static let toolTimeout: TimeInterval = 120

    let app: URL
    let bundleIdentifier: String
    let runningVersion: SoftwareVersion
    let requiredTeam: String?
    let installFolders: [URL]

    public static func running(version: SoftwareVersion) -> AppInstaller {
        AppInstaller(
            app: Bundle.main.bundleURL.resolvingSymlinksInPath(),
            bundleIdentifier: AppUpdater.bundleIdentifier,
            runningVersion: version,
            requiredTeam: signingTeam(of: Bundle.main.bundleURL),
            installFolders: [URL(fileURLWithPath: "/Applications"), FileManager.default.homeDirectoryForCurrentUser.appending(component: "Applications")]
        )
    }

    func refusal() -> AppUpdateError? {
        let resolved = app.resolvingSymlinksInPath()
        if resolved.path.contains(Self.translocationFolder) { return .translocated }
        let parent = resolved.deletingLastPathComponent()
        guard
            resolved.pathExtension == "app",
            installFolders.contains(where: { $0.resolvingSymlinksInPath().path == parent.path })
        else { return .notInstalled }
        return access(parent.path, W_OK) == 0 && access(resolved.path, W_OK) == 0 ? nil : .notWritable
    }

    func install(_ image: VerifiedImage, workspace: URL) throws(AppUpdateError) -> ReplacedApp {
        if let refusal = refusal() { throw refusal }
        let parent = app.deletingLastPathComponent()
        removeAbandonedStaging(in: parent)
        let mount = workspace.appending(component: "mount")
        try? FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true)
        _ = Scanner.runTool("/usr/bin/hdiutil", ["attach", image.file.path, "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount.path], timeout: Self.toolTimeout)
        defer { unmount(mount) }
        let contained = mount.appending(component: Self.imageAppName)
        guard FileManager.default.fileExists(atPath: contained.path) else { throw .imageUnusable }
        try inspect(contained, expected: image.version)
        return try replace(with: contained, expected: image.version)
    }

    func replace(with candidate: URL, expected: SoftwareVersion) throws(AppUpdateError) -> ReplacedApp {
        let staging = app.deletingLastPathComponent().appending(component: Self.stagingPrefix + UUID().uuidString)
        let staged = staging.appending(component: app.lastPathComponent)
        do {
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        } catch {
            throw .replaceFailed
        }
        do throws(AppUpdateError) {
            _ = Scanner.runTool("/usr/bin/ditto", [candidate.path, staged.path], timeout: Self.toolTimeout)
            try inspect(staged, expected: expected)
            try checkInstalledCopy(isOlderThan: expected)
            guard renamex_np(staged.path, app.path, UInt32(RENAME_SWAP)) == 0 else { throw .replaceFailed }
        } catch {
            try? FileManager.default.removeItem(at: staging)
            throw error
        }
        return ReplacedApp(app: app, previous: staged)
    }

    func inspect(_ candidate: URL, expected: SoftwareVersion) throws(AppUpdateError) {
        guard
            (try? FileManager.default.attributesOfItem(atPath: candidate.path))?[.type] as? FileAttributeType == .typeDirectory,
            let details = bundleDetails(of: candidate),
            details.identifier == bundleIdentifier,
            details.version == expected
        else { throw .wrongApp }
        guard details.version > runningVersion else { throw .notNewer }
        guard Self.hasValidCodeSignature(candidate) else { throw .invalidCodeSignature }
        if let requiredTeam, Self.signingTeam(of: candidate) != requiredTeam { throw .differentDeveloper }
    }

    static func signingTeam(of app: URL) -> String? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        return (information as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    static func hasValidCodeSignature(_ app: URL) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &staticCode) == errSecSuccess, let staticCode else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate).union(.noNetworkAccess)
        return SecStaticCodeCheckValidity(staticCode, flags, nil) == errSecSuccess
    }

    private func checkInstalledCopy(isOlderThan expected: SoftwareVersion) throws(AppUpdateError) {
        guard let installed = bundleDetails(of: app), installed.identifier == bundleIdentifier else { throw .replaceFailed }
        guard installed.version < expected else { throw .notNewer }
    }

    private func bundleDetails(of bundle: URL) -> (identifier: String, version: SoftwareVersion)? {
        let path = bundle.appending(components: "Contents", "Info.plist").path
        guard
            let data = RegularFile.read(atPath: path, maxBytes: Self.maxInfoPlistBytes, followingSymlinks: false),
            let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
            let identifier = plist["CFBundleIdentifier"] as? String,
            let version = (plist["CFBundleShortVersionString"] as? String).flatMap(SoftwareVersion.init(appRelease:))
        else { return nil }
        return (identifier, version)
    }

    private func removeAbandonedStaging(in folder: URL) {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        for name in names where name.hasPrefix(Self.stagingPrefix) {
            try? FileManager.default.removeItem(at: folder.appending(component: name))
        }
    }

    private func unmount(_ mount: URL) {
        guard isMounted(mount) else { return }
        _ = Scanner.runTool("/usr/bin/hdiutil", ["detach", mount.path], timeout: Self.toolTimeout)
        guard isMounted(mount) else { return }
        _ = Scanner.runTool("/usr/bin/hdiutil", ["detach", mount.path, "-force"], timeout: Self.toolTimeout)
    }

    private func isMounted(_ mount: URL) -> Bool {
        var mountStatus = stat()
        var parentStatus = stat()
        return stat(mount.path, &mountStatus) == 0
            && stat(mount.deletingLastPathComponent().path, &parentStatus) == 0
            && mountStatus.st_dev != parentStatus.st_dev
    }
}
