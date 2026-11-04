import Foundation
import Synchronization
import Testing
@testable import BluehatCore

struct VolumeWalkTests {
    static let oldAccess = 1_000_000
    static let laterChange = 2_000_000

    let temporaryRoot = FileManager.default.temporaryDirectory.appending(path: "bluehat-walk-\(UUID().uuidString)")

    var root: String {
        VolumeWalk.canonical(temporaryRoot.path) ?? temporaryRoot.path
    }

    init() throws {
        try FileManager.default.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
    }

    func cleanUp() {
        try? FileManager.default.removeItem(at: temporaryRoot)
    }

    func write(_ text: String, to relativePath: String) throws {
        let url = temporaryRoot.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func writeSparse(sized size: Int, to relativePath: String) throws {
        try write("", to: relativePath)
        #expect(truncate("\(root)/\(relativePath)", off_t(size)) == 0)
    }

    func relative(_ paths: some Sequence<String>) -> [String] {
        paths.map { String($0.dropFirst(root.count)) }.sorted()
    }

    func markUnread(_ relativePath: String) {
        var times = [timeval(tv_sec: Self.oldAccess, tv_usec: 0), timeval(tv_sec: Self.laterChange, tv_usec: 0)]
        #expect(utimes("\(root)/\(relativePath)", &times) == 0)
    }

    func wasRead(_ relativePath: String) -> Bool {
        var status = stat()
        #expect(lstat("\(root)/\(relativePath)", &status) == 0)
        return status.st_atimespec.tv_sec != Self.oldAccess
    }

    func fileRule(_ id: String = "walk.file", files: [String], severity: Severity = .high) -> Rule {
        Rule(id: id, title: id, severity: severity, category: .malware, check: .projectFile, patterns: ["evil"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: files, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func packageRule() -> Rule {
        Rule(id: "walk.package", title: "Test", severity: .critical, category: .malware, check: .npmPackage, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: [MaliciousPackage(name: "chalk", versions: .only(["5.6.1"]), advisory: "MAL-1")], files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func walk(_ rules: [Rule], excludedFolders: [String] = [], excludedPatterns: [String] = [], cancellation: ScanCancellation = ScanCancellation()) -> (findings: [Finding], notices: [String], notScanned: NotScannedList) {
        let walk = VolumeWalk(roots: [root], excludedFolders: excludedFolders, excludedPatterns: excludedPatterns, ruleFiles: rules.flatMap { $0.files ?? [] }, cancellation: cancellation)
        let result = walk.packageFileFindings(rules: rules, reported: [])
        return (result.findings, result.notices, walk.notScanned.finished())
    }

    func foundPaths(_ rules: [Rule], excludedFolders: [String] = [], excludedPatterns: [String] = []) -> [String] {
        relative(walk(rules, excludedFolders: excludedFolders, excludedPatterns: excludedPatterns).findings.compactMap(\.path))
    }

    @Test(arguments: [
        ("/foo/bar", "/foo/bar", true),
        ("/foo/bar", "/foo/bar/inner/file", true),
        ("/foo/bar/", "/foo/bar/inner", true),
        ("/foo/bar", "/foo/barbaz", false),
        ("/foo/bar", "/foo/barbaz/inner", false),
        ("/foo/bar", "/foo", false),
        ("/foo/bar", "/other/foo/bar", false),
        ("/foo/bar", "/System/Volumes/Data/foo/bar/inner", true),
        ("/System/Volumes/Data/foo/bar", "/foo/bar/inner", true),
        ("/", "/anything", false),
    ])
    func matchesExcludedFoldersOnWholePathComponents(folder: String, path: String, isExcluded: Bool) {
        defer { cleanUp() }
        #expect(VolumeWalk(roots: [], excludedFolders: [folder]).isExcluded(path) == isExcluded)
    }

    @Test func aSavedSlashIsRefusedSoItCannotEmptyAScan() throws {
        defer { cleanUp() }
        try write("evil", to: "app/next.config.js")
        let result = walk([fileRule(files: ["*.config.js"])], excludedFolders: ["/"])
        #expect(relative(result.findings.compactMap(\.path)) == ["/app/next.config.js"])
        #expect(result.notices == ["Deep Scan ignored the excluded folder / saved in Settings, because it would skip the whole disk."])
    }

    @Test func aSavedSymlinkToTheWholeDiskIsRefusedToo() throws {
        defer { cleanUp() }
        try write("evil", to: "app/next.config.js")
        try FileManager.default.createSymbolicLink(atPath: "\(root)/top", withDestinationPath: "/")
        let walk = VolumeWalk(roots: [root], excludedFolders: ["\(root)/top", "/keep"])
        #expect(walk.excludedFolders == ["/keep"])
        #expect(walk.exclusionSummary == "1 exclude from Settings applied: folders /keep.")
        #expect(walk.wholeDiskNotice == "Deep Scan ignored the excluded folder / saved in Settings, because it would skip the whole disk.")
    }

    @Test func ignoresARelativeExcludedFolder() {
        defer { cleanUp() }
        let walk = VolumeWalk(roots: [], excludedFolders: ["foo"])
        #expect(walk.excludedFolders.isEmpty)
        #expect(walk.exclusionSummary == nil)
    }

    @Test func resolvesASymlinkedExcludedFolder() throws {
        defer { cleanUp() }
        try write("abc", to: "real/file.bin")
        try FileManager.default.createSymbolicLink(atPath: "\(root)/link", withDestinationPath: "\(root)/real")
        #expect(VolumeWalk(roots: [], excludedFolders: ["\(root)/link"]).isExcluded("\(root)/real/file.bin"))
    }

    @Test func opensOnlyPackageFiles() throws {
        defer { cleanUp() }
        let unread = ["huge.bin", "tool", "Payload.app/Contents/MacOS/Payload", "notes.txt", "index.js", "node_modules/left-pad/index.js", "yarn.lock.bak", "my.config.yaml", "x.config.toml"]
        let read = ["package.json", "next.config.js"]
        try writeSparse(sized: 1 << 30, to: "huge.bin")
        for path in unread.dropFirst() + read {
            try write("evil", to: path)
        }
        #expect(chmod("\(root)/tool", 0o755) == 0)
        #expect(chmod("\(root)/Payload.app/Contents/MacOS/Payload", 0o755) == 0)
        for path in unread + read { markUnread(path) }

        let result = walk([fileRule(files: ["*.js", "*.txt", "*.bin", "*.yaml", "*.bak", "*.config.toml", "package.json", "*.config.js"])])

        #expect(unread.filter(wasRead).isEmpty)
        #expect(read.allSatisfy(wasRead))
        #expect(relative(result.findings.compactMap(\.path)) == ["/next.config.js", "/package.json"])
    }

    @Test func aRuleGlobOutsideTheListIsLeftOutAndNamed() throws {
        defer { cleanUp() }
        try write("evil", to: "index.js")
        try write("evil", to: "tool.config.toml")
        let result = walk([fileRule(files: ["*.js", "*.config.toml", "*.config.ts"])])
        #expect(result.findings.isEmpty)
        #expect(result.notices.isEmpty)
        #expect(result.notScanned.entries.map(\.name) == ["*.config.toml", "*.js"])
        #expect(result.notScanned.entries.allSatisfy { $0.reason == .filePatternNotOpened && $0.path == nil })
        #expect(result.notScanned.entries.first?.explanation == "Deep Scan doesn't open this file pattern from the rules across the disk. The normal scan still checks it in your project folders.")
    }

    @Test func theConfigFormsOnTheListAreNeverNamedAsRefused() throws {
        defer { cleanUp() }
        try write("evil", to: "app/vite.config.cts")
        try write("evil", to: "app/vitest.config.mts")
        let result = walk([fileRule(files: ["*.config.cts", "*.config.mts"])])
        #expect(relative(result.findings.compactMap(\.path)) == ["/app/vite.config.cts", "/app/vitest.config.mts"])
        #expect(result.notScanned.isEmpty)
    }

    @Test(arguments: [
        ("package.json", "package.json"),
        ("tailwind.config.js", "*.config.js"),
        ("Tailwind.Config.JS", "*.config.js"),
        ("firebase.config.json", "*.config.json"),
        ("firebase.config.json", "*.config.js"),
        ("vite.config.ts", "*.config.ts"),
        ("next.config.mjs", "*.config.mjs"),
        ("jest.config.cjs", "*.config.cjs"),
        ("vite.config.cts", "*.config.cts"),
        ("vitest.config.mts", "*.config.mts"),
        ("Vitest.Config.MTS", "*.config.mts"),
        ("gulpfile.js", "gulpfile.js"),
        (".eslintrc.js", ".eslintrc.js"),
    ])
    func everyProjectFileFormIsMatchedAndRead(name: String, glob: String) throws {
        defer { cleanUp() }
        try write("clean\nevil\n", to: "any/where/\(name)")
        let findings = walk([fileRule(files: [glob])]).findings
        #expect(relative(findings.compactMap(\.path)) == ["/any/where/\(name)"])
        #expect(findings.first?.detail.hasPrefix("Line 2 · ") == true)
    }

    @Test(arguments: [
        ("package-lock.json", #"{"packages": {"node_modules/chalk": {"version": "5.6.1"}}}"#),
        ("npm-shrinkwrap.json", #"{"packages": {"node_modules/chalk": {"version": "5.6.1"}}}"#),
        ("yarn.lock", "chalk@^5:\n  version \"5.6.1\"\n"),
        ("pnpm-lock.yaml", "packages:\n  chalk@5.6.1:\n    resolution: {}\n"),
    ])
    func everyLockfileFormIsMatchedAndRead(name: String, text: String) throws {
        defer { cleanUp() }
        try write(text, to: "any/where/\(name)")
        #expect(foundPaths([packageRule()]) == ["/any/where/\(name)"])
    }

    @Test func readsThePackageJsonOfEveryPackageInNodeModulesButNotAProjectsOwn() throws {
        defer { cleanUp() }
        try write(#"{"name": "chalk", "version": "5.6.1"}"#, to: "a/b/c/d/e/f/g/h/app/node_modules/chalk/package.json")
        try write(#"{"name": "chalk", "version": "5.6.1"}"#, to: "app/package.json")
        #expect(foundPaths([packageRule()]) == ["/a/b/c/d/e/f/g/h/app/node_modules/chalk"])
    }

    @Test(arguments: [
        ("package.json", true), ("package-lock.json", true), ("npm-shrinkwrap.json", true), ("yarn.lock", true), ("pnpm-lock.yaml", true),
        ("a.config.js", true), ("a.config.json", true), ("a.config.ts", true), ("a.config.mjs", true), ("a.config.cjs", true), ("a.config.cts", true), ("a.config.mts", true), ("A.CONFIG.JS", true), ("gulpfile.js", true),
        ("package.json.bak", false), ("config.js", false), ("a.config.toml", false), ("a.config.yaml", false), ("other.lock", false), ("index.js", false), ("a.exe", false), ("a.app", false),
    ])
    func decidesWhatToOpenByNameAlone(name: String, isPackageFile: Bool) {
        defer { cleanUp() }
        #expect(VolumeWalk(roots: [], ruleFiles: ["gulpfile.js", "*.js"]).isPackageFile(name) == isPackageFile)
    }

    @Test func skipsExcludedFoldersButNotSimilarNames() throws {
        defer { cleanUp() }
        try write("evil", to: "skip/inner/a.config.js")
        try write("evil", to: "skipped/a.config.js")
        let result = walk([fileRule(files: ["*.config.js"])], excludedFolders: ["\(root)/skip"])
        #expect(relative(result.findings.compactMap(\.path)) == ["/skipped/a.config.js"])
        #expect(result.notScanned.coverage?.exclusionSummary?.contains("/skip") == true)
        #expect(result.notScanned.isEmpty)
    }

    @Test func aPatternMatchingAFolderStopsTheWalkEnteringIt() throws {
        defer { cleanUp() }
        try write("evil", to: "kept/node_modules/inner/deeper/a.config.js")
        try write("evil", to: "kept/a.config.js")
        var visits: [String] = []
        var files: [String] = []
        VolumeWalk(roots: [root], excludedPatterns: ["node_modules"]).walk { directory, file in
            if let file {
                files.append(file.path)
            } else {
                visits.append(directory)
            }
        }
        #expect(relative(visits) == ["", "/kept"])
        #expect(relative(files) == ["/kept/a.config.js"])
    }

    @Test(arguments: [
        ("*.config.ts", ["/folder/build/inner.config.js", "/keep/app.config.js", "/plain/build.config.js"]),
        ("build/", ["/keep/app.config.js", "/keep/app.config.ts", "/plain/build.config.js"]),
        ("folder/**", ["/keep/app.config.js", "/keep/app.config.ts", "/plain/build.config.js"]),
        ("keep/app.config.js", ["/folder/build/inner.config.js", "/keep/app.config.ts", "/plain/build.config.js"]),
        ("KEEP", ["/folder/build/inner.config.js", "/plain/build.config.js"]),
        ("k?ep/*.ts", ["/folder/build/inner.config.js", "/keep/app.config.js", "/plain/build.config.js"]),
    ])
    func everyFormSkipsWhatItMatchesInAWalk(pattern: String, kept: [String]) throws {
        defer { cleanUp() }
        try write("evil", to: "keep/app.config.ts")
        try write("evil", to: "keep/app.config.js")
        try write("evil", to: "plain/build.config.js")
        try write("evil", to: "folder/build/inner.config.js")
        #expect(foundPaths([fileRule(files: ["*.config.js", "*.config.ts"])], excludedPatterns: [pattern]) == kept)
    }

    @Test func aPatternHidesOneFileWithoutHidingItsFolder() throws {
        defer { cleanUp() }
        try write("{}", to: "app/package.json")
        try write("chalk@^5:\n  version \"5.6.1\"\n", to: "app/yarn.lock")
        try write("chalk@^5:\n  version \"5.6.1\"\n", to: "other/yarn.lock")
        try write("evil", to: "app/tailwind.config.js")
        let rules = [packageRule(), fileRule(files: ["*.config.js", "package.json"])]
        #expect(foundPaths(rules, excludedPatterns: ["app/*.lock", "*.config.js"]) == ["/other/yarn.lock"])
    }

    @Test func anAbsolutePatternIsAnchoredAtThatPath() throws {
        defer { cleanUp() }
        try write("evil", to: "a/skip/a.config.js")
        try write("evil", to: "b/skip/a.config.js")
        #expect(foundPaths([fileRule(files: ["*.config.js"])], excludedPatterns: ["\(root)/a/skip"]) == ["/b/skip/a.config.js"])
        let walk = VolumeWalk(roots: [], excludedPatterns: ["\(root)/a/skip"])
        #expect(walk.isExcluded("\(root)/a/skip/inner/file"))
        #expect(!walk.isExcluded("\(root)/b/skip/inner/file"))
    }

    @Test func aRootInsideAMatchedFolderIsNotWalked() throws {
        defer { cleanUp() }
        try write("evil", to: "skip/inner/a.config.js")
        let rules = [fileRule(files: ["*.config.js"])]
        let walk = VolumeWalk(roots: ["\(root)/skip/inner"], excludedPatterns: ["skip/"], ruleFiles: ["*.config.js"])
        #expect(walk.packageFileFindings(rules: rules, reported: []).findings.isEmpty)
    }

    @Test func resolvesASymlinkInAnAnchoredPattern() throws {
        defer { cleanUp() }
        try write("evil", to: "real/skip/a.config.js")
        try write("evil", to: "real/other/a.config.js")
        try FileManager.default.createSymbolicLink(atPath: "\(root)/link", withDestinationPath: "\(root)/real")
        #expect(foundPaths([fileRule(files: ["*.config.js"])], excludedPatterns: ["\(root)/link/skip"]) == ["/real/other/a.config.js"])
    }

    @Test func refusesAPatternThatALinkTurnsIntoTheWholeDisk() throws {
        defer { cleanUp() }
        try FileManager.default.createSymbolicLink(atPath: "\(root)/top", withDestinationPath: "/")
        #expect(VolumeWalk(roots: [], excludedPatterns: ["\(root)/top", "\(root)/top/*"]).excludedPatterns.isEmpty)
    }

    @Test(arguments: [
        ("/System/Volumes/Data/foo/bar", "/foo/bar/inner", true),
        ("/foo/bar", "/System/Volumes/Data/foo/bar/inner", true),
        ("bar", "/System/Volumes/Data/foo/bar", true),
        ("Data", "/System/Volumes/Data/foo", false),
        ("Volumes", VolumeWalk.dataVolume, false),
        ("System", VolumeWalk.dataVolume, false),
    ])
    func comparesPatternsWithoutTheDataVolumePrefix(pattern: String, path: String, isExcluded: Bool) {
        defer { cleanUp() }
        #expect(VolumeWalk(roots: [], excludedPatterns: [pattern]).isExcluded(path) == isExcluded)
    }

    @Test(arguments: [
        "*", "**", "/", "/*", "[a-z]*", "~", "~/*", "!foo", "[abc", "",
    ])
    func aWalkDropsAPatternItWouldHaveRefused(pattern: String) throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let walk = VolumeWalk(roots: [root], excludedPatterns: [pattern])
        #expect(walk.excludedPatterns.isEmpty)
        #expect(walk.exclusionSummary == nil)
        #expect(foundPaths([fileRule(files: ["*.config.js"])], excludedPatterns: [pattern]) == ["/a.config.js"])
    }

    @Test func aPickedFolderWithGlobCharactersMeansThatFolderOnly() throws {
        defer { cleanUp() }
        try write("evil", to: "foo[1]/a.config.js")
        try write("evil", to: "foo1/a.config.js")
        try write("evil", to: "other/foo[1]/a.config.js")
        try write("evil", to: "star*/a.config.js")
        try write("evil", to: "starry/a.config.js")
        let found = foundPaths([fileRule(files: ["*.config.js"])], excludedFolders: ["\(root)/foo[1]", "\(root)/star*"])
        #expect(found == ["/foo1/a.config.js", "/other/foo[1]/a.config.js", "/starry/a.config.js"])
    }

    @Test func foldersAndPatternsWorkTogether() throws {
        defer { cleanUp() }
        try write("evil", to: "folder/a.config.js")
        try write("evil", to: "pattern/a.config.js")
        try write("evil", to: "kept/a.config.js")
        #expect(foundPaths([fileRule(files: ["*.config.js"])], excludedFolders: ["\(root)/folder"], excludedPatterns: ["pattern/"]) == ["/kept/a.config.js"])
    }

    @Test func theNoticeNamesEveryFolderAndPattern() {
        defer { cleanUp() }
        let folders = (1...5).map { "/folder\($0)" }
        let patterns = (1...5).map { "pattern\($0)" }
        let notice = VolumeWalk(roots: [], excludedFolders: folders, excludedPatterns: patterns).exclusionSummary ?? ""
        for name in folders + patterns {
            #expect(notice.contains(name))
        }
        #expect(!notice.contains("more"))
    }

    @Test func theNoticeShowsAPatternAsTyped() {
        defer { cleanUp() }
        let notice = VolumeWalk(roots: [], excludedPatterns: ["~/Library/Caches", "*.LOG"]).exclusionSummary
        #expect(notice == "2 excludes from Settings applied: patterns *.LOG, ~/Library/Caches.")
    }

    @Test func aNormalScanIgnoresPatterns() throws {
        defer { cleanUp() }
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)
        let result = Scanner(kind: .normal, excludedPatterns: ["*.log"]).scan(rulebook)
        #expect(result.notScanned.coverage == nil)
    }

    @Test func anExcludedRootIsNotWalked() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        #expect(foundPaths([fileRule(files: ["*.config.js"])], excludedFolders: [root]).isEmpty)
    }

    @Test func neverFollowsSymlinksAndEndsOnALoop() throws {
        defer { cleanUp() }
        let outside = FileManager.default.temporaryDirectory.appending(path: "bluehat-walk-outside-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outside) }
        try Data("evil".utf8).write(to: outside.appending(path: "a.config.js"))
        try write("evil", to: "folder/b.config.js")
        try FileManager.default.createSymbolicLink(atPath: "\(root)/folder/out", withDestinationPath: outside.path)
        try FileManager.default.createSymbolicLink(atPath: "\(root)/folder/loop", withDestinationPath: root)
        try FileManager.default.createSymbolicLink(atPath: "\(root)/link.config.js", withDestinationPath: "\(root)/folder/b.config.js")

        #expect(foundPaths([fileRule(files: ["*.config.js"])]) == ["/folder/b.config.js"])
    }

    @Test func aFolderReachedTwiceIsWalkedOnce() throws {
        defer { cleanUp() }
        try write("{}", to: "folder/package.json")
        var visits: [String] = []
        VolumeWalk(roots: [root, "\(root)/folder", root]).walk { directory, file in
            if file == nil { visits.append(directory) }
        }
        #expect(relative(visits) == ["", "/folder"])
    }

    @Test func skipsUnreadableFolders() throws {
        defer {
            chmod("\(root)/locked", 0o700)
            cleanUp()
        }
        try write("evil", to: "locked/a.config.js")
        try write("evil", to: "open.config.js")
        #expect(chmod("\(root)/locked", 0) == 0)
        #expect(foundPaths([fileRule(files: ["*.config.js"])]) == ["/open.config.js"])
    }

    @Test func countsTheFoldersItReadAndThePackageFilesItOpened() throws {
        defer { cleanUp() }
        try write("clean", to: "a/one.config.js")
        try write("clean", to: "a/b/two.config.ts")
        try write("clean", to: "c/notes.txt")
        try write("clean", to: "c/unlisted.config.mjs")
        let rules = [fileRule(files: ["*.config.js", "*.config.ts"])]
        let walk = VolumeWalk(roots: [root], excludedFolders: ["/keep"], ruleFiles: ["*.config.js", "*.config.ts"])

        let notices = walk.packageFileFindings(rules: rules, reported: []).notices

        #expect(walk.foldersRead == 4)
        #expect(walk.unreadableFolders == 0)
        #expect(walk.packageFilesOpened == 2)
        #expect(notices.isEmpty)
        let coverage = walk.notScanned.finished().coverage
        #expect(coverage?.summary == "Read 4 folders · opened 2 package files")
        #expect(coverage?.exclusionSummary == "1 exclude from Settings applied: folders /keep.")
    }

    @Test func theCoverageSummaryUsesTheSingularAndFormatsLargeNumbers() throws {
        defer { cleanUp() }
        let rules = [fileRule(files: ["*.config.js"])]
        try write("clean", to: "a.config.js")
        let one = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"])
        _ = one.packageFileFindings(rules: rules, reported: [])
        #expect(one.notScanned.finished().coverage?.summary == "Read 1 folder · opened 1 package file")

        for index in 1..<1_000 {
            #expect(FileManager.default.createFile(atPath: "\(root)/\(index).config.js", contents: nil))
        }
        let many = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"])
        _ = many.packageFileFindings(rules: rules, reported: [])
        #expect(many.notScanned.finished().coverage?.summary == "Read 1 folder · opened \(1_000.formatted()) package files")
    }

    @Test func aFileThatFailsToOpenIsNotCountedAsOpened() throws {
        defer { cleanUp() }
        #expect(mkfifo("\(root)/package.json", 0o600) == 0)
        try write("clean", to: "locked.config.js")
        #expect(chmod("\(root)/locked.config.js", 0) == 0)
        let walk = VolumeWalk(roots: [root], ruleFiles: ["package.json", "*.config.js"])
        _ = walk.packageFileFindings(rules: [fileRule(files: ["package.json", "*.config.js"])], reported: [])
        #expect(walk.packageFilesOpened == 0)
        #expect(walk.foldersRead == 1)
        let entries = walk.notScanned.finished().entries
        #expect(relative(entries.compactMap(\.path)) == ["/locked.config.js"])
        #expect(entries.map(\.reason) == [.noPermission])
    }

    @Test func aWalkThatOpensNothingHasNoCoverage() throws {
        defer { cleanUp() }
        let walk = VolumeWalk(roots: [root])
        #expect(walk.packageFileFindings(rules: [], reported: []).notices.isEmpty)
        #expect(walk.notScanned.finished().coverage == nil)
        #expect(walk.notScanned.finished().isEmpty)
    }

    @Test func aFolderPermissionsRefuseIsCountedAsUnreadableAndListed() throws {
        defer {
            chmod("\(root)/locked", 0o700)
            cleanUp()
        }
        try write("clean", to: "locked/inner/a.config.js")
        try write("clean", to: "open/b.config.js")
        #expect(chmod("\(root)/locked", 0) == 0)
        let walk = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"])

        _ = walk.packageFileFindings(rules: [fileRule(files: ["*.config.js"])], reported: [])

        #expect(walk.foldersRead == 2)
        #expect(walk.unreadableFolders == 1)
        #expect(walk.packageFilesOpened == 1)
        let list = walk.notScanned.finished()
        #expect(list.coverage?.summary == "Read 2 folders · opened 1 package file · 1 folder couldn't be read")
        #expect(list.entries.map(\.path) == ["\(root)/locked"])
        #expect(list.entries.map(\.reason) == [.noPermission])
        #expect(list.entries.map(\.explanation) == ["No permission"])
        #expect(list.summaryLine == "1 item couldn't be scanned")
    }

    @Test func aFolderThatCanBeListedButNotEnteredCountsItsSubfoldersAsUnreadable() throws {
        defer {
            chmod("\(root)/listed", 0o700)
            cleanUp()
        }
        try write("clean", to: "listed/one/a.config.js")
        try write("clean", to: "listed/two/b.config.js")
        try write("clean", to: "listed/c.config.js")
        #expect(chmod("\(root)/listed", 0o400) == 0)
        let walk = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"])
        _ = walk.packageFileFindings(rules: [fileRule(files: ["*.config.js"])], reported: [])
        #expect(walk.foldersRead == 2)
        #expect(walk.unreadableFolders == 2)
        #expect(walk.packageFilesOpened == 0)
    }

    @Test func theListKeepsTheShallowestUnreadableFoldersAndCountsTheRest() throws {
        let locked = ["one", "two", "deep/a/b/three", "deep/a/b/c/four", "deep/a/five"]
        defer {
            for path in locked { chmod("\(root)/\(path)", 0o700) }
            cleanUp()
        }
        for path in locked {
            try write("clean", to: "\(path)/a.config.js")
        }
        for path in locked {
            #expect(chmod("\(root)/\(path)", 0) == 0)
        }
        let walk = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"], notScanned: NotScannedCollector(limits: ScanLimits(unchecked: [.maxNotScannedEntries: 3])))

        _ = walk.packageFileFindings(rules: [fileRule(files: ["*.config.js"])], reported: [])

        #expect(walk.unreadableFolders == 5)
        let list = walk.notScanned.finished()
        #expect(Set(list.entries.compactMap(\.path)) == ["\(root)/one", "\(root)/two", "\(root)/deep/a/five"])
        #expect(list.totalCount == 5)
        #expect(list.leftOutCount == 2)
    }

    @Test(arguments: [
        (EACCES, NotScannedReason.noPermission),
        (EPERM, NotScannedReason.noPermission),
        (EIO, NotScannedReason.couldNotRead),
        (ENAMETOOLONG, NotScannedReason.couldNotRead),
        (ETIMEDOUT, NotScannedReason.timedOut),
    ])
    func aFolderErrorGivesAPlainReason(error: Int32, reason: NotScannedReason) {
        defer { cleanUp() }
        let walk = VolumeWalk(roots: [])
        walk.noteUnreadableFolder("/somewhere", error: error)
        #expect(walk.notScanned.finished().entries.map(\.reason) == [reason])
    }

    @Test func aFolderInTheCloudIsListedAndOneOnAnotherVolumeIsNotAndNeitherIsUnreadable() throws {
        defer { cleanUp() }
        var status = stat()
        #expect(lstat(root, &status) == 0)
        var cloud = status
        cloud.st_flags |= UInt32(SF_DATALESS)
        let walk = VolumeWalk(roots: [], excludedFolders: ["\(root)/excluded"])

        walk.noteOffDisk(VolumeWalk.Entry(name: "other", path: "\(root)/other", status: status))
        walk.noteOffDisk(VolumeWalk.Entry(name: "cloud", path: "\(root)/cloud", status: cloud))
        walk.noteOffDisk(VolumeWalk.Entry(name: "excluded", path: "\(root)/excluded", status: cloud))

        let list = walk.notScanned.finished()
        #expect(relative(list.entries.compactMap(\.path)) == ["/cloud"])
        #expect(list.entries.map(\.reason) == [.cloudOnly])
        #expect(list.totalCount == 1)
        #expect(walk.unreadableFolders == 0)
    }

    @Test func aDeepScanWithNothingSkippedHasNoCountOrCalmLineDespiteTheOtherVolumesNote() throws {
        defer { cleanUp() }
        try write("clean", to: "project/a.config.js")
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)

        let list = Scanner(kind: .deep, walkRoots: [root]).scan(rulebook).notScanned

        #expect(list.coverage != nil)
        #expect(list.isEmpty)
        #expect(list.totalCount == 0)
        #expect(list.summaryLine == nil)
        #expect(list.reasons.isEmpty)
        #expect(NotScannedList.Coverage.otherVolumesNote.contains("other volumes"))
    }

    @Test(arguments: [
        (EACCES, 1),
        (EPERM, 1),
        (EIO, 1),
        (ENOENT, 0),
        (ENOTDIR, 0),
        (EDEADLK, 0),
    ])
    func aFolderThatWentAwayOrIsNotDownloadedIsNotUnreadable(error: Int32, counted: Int) {
        defer { cleanUp() }
        let walk = VolumeWalk(roots: [])
        walk.noteUnreadableFolder("/somewhere", error: error)
        #expect(walk.unreadableFolders == counted)
    }

    @Test func excludedFoldersAreNeverCountedAsUnreadable() throws {
        defer {
            chmod("\(root)/picked", 0o700)
            chmod("\(root)/matched", 0o700)
            chmod("\(root)/listed", 0o700)
            cleanUp()
        }
        try write("clean", to: "picked/a.config.js")
        try write("clean", to: "matched/a.config.js")
        try write("clean", to: "listed/skip/a.config.js")
        try write("clean", to: "listed/picked-inside/a.config.js")
        try write("clean", to: "listed/kept/a.config.js")
        let walk = VolumeWalk(roots: [root], excludedFolders: ["\(root)/picked", "\(root)/listed/picked-inside"], excludedPatterns: ["matched/", "skip"], ruleFiles: ["*.config.js"])
        #expect(chmod("\(root)/picked", 0) == 0)
        #expect(chmod("\(root)/matched", 0) == 0)
        #expect(chmod("\(root)/listed", 0o400) == 0)

        _ = walk.packageFileFindings(rules: [fileRule(files: ["*.config.js"])], reported: [])

        #expect(walk.foldersRead == 2)
        #expect(walk.unreadableFolders == 1)
        #expect(relative(walk.notScanned.finished().entries.compactMap(\.path)) == ["/listed/kept"])
    }

    @Test func aLockedFolderInTheCloudOrOnAnotherVolumeIsNeverEntered() throws {
        defer {
            chmod("\(root)/locked", 0o700)
            cleanUp()
        }
        try write("clean", to: "locked/a.config.js")
        #expect(chmod("\(root)/locked", 0) == 0)
        var status = stat()
        #expect(lstat("\(root)/locked", &status) == 0)
        let walk = VolumeWalk(roots: [])
        let devices: Set<dev_t> = [status.st_dev]

        #expect(!walk.isOffDisk(VolumeWalk.Entry(name: "locked", path: "\(root)/locked", status: status), devices: devices))
        #expect(walk.isOffDisk(VolumeWalk.Entry(name: "locked", path: "\(root)/locked", status: status), devices: [status.st_dev + 1]))
        status.st_flags |= UInt32(SF_DATALESS)
        #expect(walk.isOffDisk(VolumeWalk.Entry(name: "locked", path: "\(root)/locked", status: status), devices: devices))
    }

    @Test func anUnreadableFolderChangesNoFindingAndNoSavedResult() throws {
        defer {
            chmod("\(root)/project/locked", 0o700)
            cleanUp()
        }
        try write("clean", to: "project/locked/a.config.js")
        try write("clean", to: "project/b.config.js")
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)
        let scanner = Scanner(kind: .deep, walkRoots: ["\(root)/project"])
        let readable = scanner.scan(rulebook)
        #expect(chmod("\(root)/project/locked", 0) == 0)

        let result = scanner.scan(rulebook)

        #expect(readable.findings.isEmpty)
        #expect(result.findings.isEmpty)
        #expect(result.notices.isEmpty)
        #expect(result.notScanned.coverage?.summary.contains("1 folder couldn't be read") == true)
        #expect(result.notScanned.totalCount == 1)
        let fileURL = temporaryRoot.appending(path: "history.json")
        var history = ScanHistory(fileURL: fileURL)
        try history.append(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: readable.findings, kind: .deep))
        try history.append(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: result.findings, kind: .deep))
        let reloaded = ScanHistory(fileURL: fileURL)
        #expect(reloaded.records.count == 2)
        #expect(reloaded.records.first?.issues.isEmpty == true)
        #expect(reloaded.latestChanges?.isEmpty == true)
    }

    @Test func aNormalScanHasNoCoverage() throws {
        defer { cleanUp() }
        try write("clean", to: "a.config.js")
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)
        let result = Scanner(kind: .normal, walkRoots: [root]).scan(rulebook)
        #expect(result.notices.isEmpty)
        #expect(result.notScanned.coverage == nil)
    }

    @Test func doesNotCrossIntoAnotherVolume() throws {
        defer { cleanUp() }
        var rootStatus = stat()
        var deviceStatus = stat()
        #expect(stat("/", &rootStatus) == 0)
        #expect(stat("/dev", &deviceStatus) == 0)
        try #require(rootStatus.st_dev != deviceStatus.st_dev)
        let others = try FileManager.default.contentsOfDirectory(atPath: "/").filter { $0 != "dev" }.map { "/\($0)" }
        let cancellation = ScanCancellation()
        var visits: [String] = []
        let walk = VolumeWalk(roots: ["/"], excludedFolders: others, cancellation: cancellation)
        walk.walk { directory, file in
            guard file == nil else { return }
            visits.append(directory)
            if visits.count > 1 { cancellation.cancel() }
        }
        #expect(visits == ["/"])
        #expect(walk.foldersRead == 1)
        #expect(walk.unreadableFolders == 0)
        let list = walk.notScanned.finished()
        #expect(list.isEmpty)
        #expect(list.summaryLine == nil)
    }

    @Test func theDataVolumeAliasOfAWalkedFolderIsNotWalkedAgain() throws {
        defer { cleanUp() }
        try write("{}", to: "folder/package.json")
        var visits: [String] = []
        VolumeWalk(roots: [root, VolumeWalk.dataVolume + root]).walk { directory, file in
            if file == nil { visits.append(directory) }
        }
        #expect(relative(visits) == ["", "/folder"])
    }

    @Test func aPipeNamedLikeAPackageFileCannotHangTheWalk() throws {
        defer { cleanUp() }
        try write("evil", to: "app/a.config.js")
        #expect(mkfifo("\(root)/app/package.json", 0o600) == 0)
        #expect(foundPaths([fileRule(files: ["package.json", "*.config.js"])]) == ["/app/a.config.js"])
    }

    @Test func aFolderNamedLikeAPackageFileIsWalkedNotRead() throws {
        defer { cleanUp() }
        try write("evil", to: "package.json/a.config.js")
        #expect(foundPaths([fileRule(files: ["package.json", "*.config.js"])]) == ["/package.json/a.config.js"])
    }

    @Test(arguments: ["package.json", "a.config.js"])
    func aPackageFileOverItsLimitIsListedNotRead(name: String) throws {
        defer { cleanUp() }
        try write("evil" + String(repeating: "\n", count: ScanLimits.defaults[.maxReadBytes]), to: name)
        markUnread(name)
        let result = walk([fileRule(files: ["package.json", "*.config.js"])])
        #expect(result.findings.isEmpty)
        #expect(!wasRead(name))
        #expect(result.notScanned.entries.map(\.path) == ["\(root)/\(name)"])
        #expect(result.notScanned.entries.map(\.reason) == [.overSizeLimit])
        #expect(result.notScanned.entries.first?.explanation.hasSuffix("limit 1 MB)") == true)
    }

    @Test func aLockfileOverItsLimitIsListedNotRead() throws {
        defer { cleanUp() }
        try writeSparse(sized: ScanLimits.defaults[.maxLockfileBytes] + 1, to: "app/yarn.lock")
        markUnread("app/yarn.lock")
        let result = walk([packageRule()])
        #expect(!wasRead("app/yarn.lock"))
        #expect(result.notScanned.entries.map(\.path) == ["\(root)/app/yarn.lock"])
        #expect(result.notScanned.entries.first?.explanation.hasSuffix("limit 30 MB)") == true)
    }

    @Test func everyOversizedFileIsListed() throws {
        defer { cleanUp() }
        for index in 1...(ScanLimits.defaults[.maxNoticePaths] + 2) {
            try writeSparse(sized: ScanLimits.defaults[.maxReadBytes] + 1, to: "\(index).config.js")
        }
        let list = walk([fileRule(files: ["*.config.js"])]).notScanned
        #expect(list.entries.count == ScanLimits.defaults[.maxNoticePaths] + 2)
        #expect(list.leftOutCount == 0)
    }

    @Test func aDeeplyNestedPackageFileCannotCrashTheWalk() throws {
        defer { cleanUp() }
        let nested = String(repeating: #"{"a":"#, count: 512) + "1" + String(repeating: "}", count: 512)
        try write(nested, to: "app/node_modules/nested/package.json")
        try write(String(repeating: "[", count: 200_000), to: "app/node_modules/deep/package.json")
        try write(nested, to: "app/package-lock.json")
        try write(String(repeating: #"{"dependencies":{"a":"#, count: 20_000), to: "other/package-lock.json")
        let result = Scanner(kind: .deep, walkRoots: [root]).walkDisk(rules: [packageRule()], reported: [], notScanned: NotScannedCollector(), onItemsWalked: { _ in })
        #expect(result.findings.isEmpty)
    }

    @Test func aFileStoredOnlyInTheCloudIsCountedAndNeverOpened() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        markUnread("a.config.js")
        var status = stat()
        #expect(lstat("\(root)/a.config.js", &status) == 0)
        status.st_flags |= UInt32(SF_DATALESS)
        let walk = VolumeWalk(roots: [])

        let found = walk.findings(in: VolumeWalk.Entry(name: "a.config.js", path: "\(root)/a.config.js", status: status), directory: root, checks: VolumeWalk.Checks(rules: [fileRule(files: ["*.config.js"])]))

        #expect(found.isEmpty)
        #expect(!wasRead("a.config.js"))
        let entries = walk.notScanned.finished().entries
        #expect(entries.map(\.path) == ["\(root)/a.config.js"])
        #expect(entries.map(\.explanation) == ["Cloud-only, not downloaded"])
    }

    @Test func recognisesAFileStoredOnlyInTheCloud() {
        defer { cleanUp() }
        var status = stat()
        #expect(!VolumeWalk.Entry(name: "x", path: "/x", status: status).isCloudOnly)
        status.st_flags = UInt32(SF_DATALESS)
        #expect(VolumeWalk.Entry(name: "x", path: "/x", status: status).isCloudOnly)
    }

    @Test func aCancelledWalkVisitsNothing() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let cancellation = ScanCancellation()
        cancellation.cancel()
        #expect(walk([fileRule(files: ["*.config.js"])], cancellation: cancellation).findings.isEmpty)
    }

    @Test func cancellingStopsTheWalkBetweenFolders() throws {
        defer { cleanUp() }
        try write("{}", to: "a/package.json")
        try write("{}", to: "b/package.json")
        let cancellation = ScanCancellation()
        var visits = 0
        VolumeWalk(roots: [root], cancellation: cancellation).walk { _, file in
            guard file == nil else { return }
            visits += 1
            cancellation.cancel()
        }
        #expect(visits == 1)
    }

    @Test func cancellingStopsTheWalkBetweenFiles() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        try write("evil", to: "b.config.js")
        let cancellation = ScanCancellation()
        var files = 0
        VolumeWalk(roots: [root], cancellation: cancellation).walk { _, file in
            guard file != nil else { return }
            files += 1
            cancellation.cancel()
        }
        #expect(files == 1)
    }

    @Test func cancellingStopsHashingAFile() throws {
        defer { cleanUp() }
        try write("abc", to: "match.bin")
        let cancellation = ScanCancellation()
        cancellation.cancel()
        #expect(Scanner.sha256(of: temporaryRoot.appending(path: "match.bin"), maxBytes: ScanLimits.defaults[.maxHashedFileBytes], cancellation: cancellation) == nil)
        #expect(Scanner.hashedFiles(in: [root], cancellation: cancellation).hashes.isEmpty)
    }

    @Test func aCancelledDeepScanRunsNoAreaFindsNothingAndNeverWalks() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let cancellation = ScanCancellation()
        cancellation.cancel()
        let finished = Mutex<[CheckKind]>([])
        let walked = Mutex(0)
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)

        let result = Scanner(kind: .deep, cancellation: cancellation, walkRoots: [root]).scan(rulebook) { area, _ in
            finished.withLock { $0.append(area) }
        } onItemsWalked: { count in
            walked.withLock { $0 = count }
        }

        #expect(result.findings.isEmpty)
        #expect(result.notices.isEmpty)
        #expect(finished.withLock { $0 }.isEmpty)
        #expect(walked.withLock { $0 } == 0)
    }

    @Test func aDeepScanRunsTheNormalScanThenAddsWhatTheWalkFindsOnce() throws {
        defer { cleanUp() }
        try write("{}", to: "project/package.json")
        try write("evil", to: "project/next.config.js")
        try write("evil", to: "elsewhere/deep/er/vite.config.js")
        let normalFindings = Mutex<[Finding]>([])
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)

        let result = Scanner(projectFolders: ["\(root)/project"], kind: .deep, walkRoots: [root]).scan(rulebook) { _, findings in
            normalFindings.withLock { $0 += findings }
        }

        #expect(relative(normalFindings.withLock { $0 }.compactMap(\.path)) == ["/project/next.config.js"])
        #expect(relative(result.findings.compactMap(\.path)) == ["/elsewhere/deep/er/vite.config.js", "/project/next.config.js"])
    }

    @Test func aDeepScanSaysWhichFindingsCameFromTheWalk() throws {
        defer { cleanUp() }
        try write("{}", to: "project/package.json")
        try write("evil", to: "project/next.config.js")
        try write("evil", to: "elsewhere/vite.config.js")
        let rulebook = Rulebook(schema: 1, version: 1, rules: [fileRule(files: ["*.config.js"])], issued: nil, expires: nil)

        let deep = Scanner(projectFolders: ["\(root)/project"], kind: .deep, walkRoots: [root]).scan(rulebook)
        let normal = Scanner(projectFolders: ["\(root)/project"], kind: .normal, walkRoots: [root]).scan(rulebook)

        #expect(relative(deep.findings.filter { deep.walkFindingIDs.contains($0.id) }.compactMap(\.path)) == ["/elsewhere/vite.config.js"])
        #expect(!normal.findings.isEmpty)
        #expect(normal.walkFindingIDs.isEmpty)
    }

    @Test func aRulebookWithNothingToOpenSkipsTheWalk() throws {
        defer { cleanUp() }
        try write("{}", to: "package.json")
        let rule = Rule(id: "walk.none", title: "Test", severity: .high, category: .malware, check: .path, patterns: nil, paths: ["/nonexistent/bluehat"], ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
        let walked = Mutex(false)
        let result = Scanner(kind: .deep, walkRoots: [root]).walkDisk(rules: [rule], reported: [], notScanned: NotScannedCollector(), onItemsWalked: { _ in walked.withLock { $0 = true } })
        #expect(result.findings.isEmpty)
        #expect(!walked.withLock { $0 })
    }

    @Test func keepsTheMostSevereFindingsAndSaysWhatItLeftOut() throws {
        defer { cleanUp() }
        for index in 0...(ScanLimits.defaults[.maxFindings] + 1) {
            try write("evil", to: "\(index).config.js")
        }
        try write("evil", to: "worst.config.ts")
        let result = walk([fileRule("walk.common", files: ["*.config.js"], severity: .low), fileRule("walk.worst", files: ["*.config.ts"], severity: .critical)])
        #expect(result.findings.count == ScanLimits.defaults[.maxFindings])
        #expect(result.findings.contains { $0.rule.id == "walk.worst" })
        #expect(result.notices == ["Deep Scan kept the 1,000 most severe matches on the disk and left out 3 more, from walk.common."])
    }

    @Test func findingsTheNormalScanReportedAreNotRepeated() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let rules = [fileRule(files: ["*.config.js"])]
        let first = walk(rules).findings
        let again = VolumeWalk(roots: [root], ruleFiles: ["*.config.js"]).packageFileFindings(rules: rules, reported: Set(first.map(\.fingerprint)))
        #expect(first.count == 1)
        #expect(again.findings.isEmpty)
    }

    @Test func theWalkRunsAtBackgroundPriorityAndReportsProgress() throws {
        defer { cleanUp() }
        for index in 0...VolumeWalk.progressInterval {
            #expect(FileManager.default.createFile(atPath: "\(root)/\(index)", contents: nil))
        }
        let reported = Mutex<[Int]>([])
        let isBackground = Mutex(false)
        let refusesDownloads = Mutex(false)
        _ = Scanner(kind: .deep, walkRoots: [root]).walkDisk(rules: [packageRule()], reported: [], notScanned: NotScannedCollector(), onItemsWalked: { count in
            reported.withLock { $0.append(count) }
            isBackground.withLock { $0 = qos_class_self() == QOS_CLASS_BACKGROUND }
            refusesDownloads.withLock { $0 = getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD) == IOPOL_MATERIALIZE_DATALESS_FILES_OFF }
        })
        #expect(reported.withLock { $0 } == [VolumeWalk.progressInterval + 1])
        #expect(isBackground.withLock { $0 })
        #expect(refusesDownloads.withLock { $0 })
    }
}
