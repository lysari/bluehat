import Foundation
import Synchronization
import Testing
@testable import BluehatCore

struct JSONFileTests {
    static let tooDeep = JSONFile.maxNesting + 1
    static let nestedExplanation = "Nested more than 300 levels deep, so it wasn't parsed"

    let temporaryRoot = FileManager.default.temporaryDirectory.appending(path: "bluehat-json-\(UUID().uuidString)")

    var root: String {
        VolumeWalk.canonical(temporaryRoot.path) ?? temporaryRoot.path
    }

    func cleanUp() {
        try? FileManager.default.removeItem(at: temporaryRoot)
    }

    func write(_ data: Data, to relativePath: String) throws {
        let url = temporaryRoot.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
    }

    static func objects(_ depth: Int, key: String = "a") -> Data {
        Data((String(repeating: #"{"\#(key)":"#, count: depth) + "1" + String(repeating: "}", count: depth)).utf8)
    }

    static func manifest(name: String, version: String) -> Data {
        Data(#"{"name": "\#(name)", "version": "\#(version)"}"#.utf8)
    }

    static var chalkRule: Rule {
        Rule(id: "json.package", title: "Test", severity: .critical, category: .malware, check: .npmPackage, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: [MaliciousPackage(name: "chalk", versions: .only(["5.6.1"]), advisory: "MAL-1")], files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func onLargeStack<Value: Sendable>(_ work: @escaping @Sendable () -> Value) -> Value {
        let finished = DispatchSemaphore(value: 0)
        let outcome = Mutex<Value?>(nil)
        let thread = Thread {
            let value = work()
            outcome.withLock { $0 = value }
            finished.signal()
        }
        thread.stackSize = VolumeWalk.threadStackBytes
        thread.start()
        finished.wait()
        return outcome.withLock { $0! }
    }

    func packages(inProjects names: [String: Set<String>], moduleDirectories: [String] = [], limits: ScanLimits = .defaults) -> (packages: [InstalledPackage], notScanned: [NotScannedEntry]) {
        let projects = names.map { (path: "\(root)/\($0.key)", files: $0.value) }
        return onLargeStack {
            NpmInventory.packages(inProjects: projects, moduleDirectories: moduleDirectories, limits: limits)
        }
    }

    @Test func nestingUpToTheLimitPassesAndOneMoreLevelIsRefused() {
        #expect(JSONFile.refusal(of: Self.objects(JSONFile.maxNesting)) == nil)
        #expect(JSONFile.refusal(of: Self.objects(Self.tooDeep)) == .tooDeep)
    }

    @Test(arguments: ["[", #"{"a":"#, #"[{"a":"#, #"{"a":["#])
    func everyShapeOfOpenNestingIsRefused(opening: String) {
        #expect(JSONFile.refusal(of: Data(String(repeating: opening, count: Self.tooDeep).utf8)) == .tooDeep)
        #expect(JSONFile.refusal(of: Data(String(repeating: opening, count: 100_000).utf8)) == .tooDeep)
    }

    @Test(arguments: ["}}}", "]]]", #"\""#, #"\\"#, #"\\\""#, "é", "∀", "\\u0022", "{[", " "])
    func keysCannotHideNesting(key: String) {
        #expect(JSONFile.refusal(of: Self.objects(JSONFile.maxNesting, key: key)) == nil)
        #expect(JSONFile.refusal(of: Self.objects(Self.tooDeep, key: key)) == .tooDeep)
    }

    @Test func bracesInsideStringsAreNotNesting() {
        let braces = String(repeating: "{[", count: 5_000)
        let text = #"{"script": "\#(braces)", "escaped": "\"\#(braces)", "backslash": "\\", "after": {"b": 1}}"#
        #expect(JSONFile.refusal(of: Data(text.utf8)) == nil)
    }

    @Test(arguments: [String.Encoding.utf16, .utf16LittleEndian, .utf16BigEndian, .utf32, .utf32LittleEndian, .utf32BigEndian])
    func otherEncodingsAreRefused(encoding: String.Encoding) throws {
        let data = try #require(#"{"a": 1}"#.data(using: encoding))
        #expect(JSONFile.refusal(of: data) == .notUTF8)
    }

    @Test func aQuoteByteInsideAUTF16CharacterCannotHideNesting() throws {
        let text = String(repeating: #"{"∀":"#, count: Self.tooDeep)
        #expect(JSONFile.refusal(of: try #require(text.data(using: .utf16BigEndian))) == .notUTF8)
        #expect(JSONFile.refusal(of: try #require(text.data(using: .utf16LittleEndian))) == .notUTF8)
    }

    @Test func aNulByteAnywhereIsRefused() {
        #expect(JSONFile.refusal(of: Data(#"{"a": 1}"#.utf8) + Data([0])) == .notUTF8)
    }

    @Test func parsingGivesTheObjectAndNothingElse() throws {
        #expect(try JSONFile.object(from: Data(#"{"a": 1}"#.utf8))?["a"] as? Int == 1)
        #expect(try JSONFile.object(from: Data([0xEF, 0xBB, 0xBF]) + Data(#"{"a": 1}"#.utf8))?["a"] as? Int == 1)
        #expect(try JSONFile.object(from: Data("[1]".utf8)) == nil)
        #expect(try JSONFile.object(from: Data("not json".utf8)) == nil)
        #expect(try JSONFile.object(from: Data()) == nil)
    }

    @Test func refusingHappensBeforeParsing() {
        let refused = onLargeStack { () -> Bool in
            do {
                _ = try JSONFile.object(from: Self.objects(100_000))
                return false
            } catch {
                return true
            }
        }
        #expect(refused)
    }

    @Test func noSettingAsksForMoreNestingThanIsAllowed() {
        let deepestEntry = 3 + 2 * ScanLimit.maxDependencyDepth.range.upperBound
        #expect(deepestEntry <= JSONFile.maxNesting)
    }

    @Test func aCraftedLockfileIsListedAndTheRestIsStillRead() throws {
        defer { cleanUp() }
        try write(Data("{}".utf8), to: "bad/package.json")
        try write(Self.objects(100_000), to: "bad/package-lock.json")
        try write(Data("chalk@^5.6.1:\n  version \"5.6.1\"\n".utf8), to: "bad/yarn.lock")
        try write(Data("{}".utf8), to: "good/package.json")
        try write(Data(#"{"lockfileVersion": 3, "packages": {"node_modules/debug": {"version": "4.4.2"}}}"#.utf8), to: "good/package-lock.json")

        let result = packages(inProjects: ["bad": ["package.json", "package-lock.json", "yarn.lock"], "good": ["package.json", "package-lock.json"]])

        #expect(Set(result.packages.map(\.name)) == ["chalk", "debug"])
        #expect(result.notScanned.map(\.path) == ["\(root)/bad/package-lock.json"])
        #expect(result.notScanned.first?.reason == .notSafeToParse)
        #expect(result.notScanned.first?.explanation == "\(Self.nestedExplanation) (npm package check)")
    }

    @Test func aRefusedFileAppearsInTheNotScannedListWithoutAFinding() throws {
        defer { cleanUp() }
        try write(Data("{}".utf8), to: "bad/package.json")
        try write(Self.objects(Self.tooDeep), to: "bad/npm-shrinkwrap.json")

        let result = packages(inProjects: ["bad": ["package.json", "npm-shrinkwrap.json"]])
        let collector = NotScannedCollector()
        collector.add(contentsOf: result.notScanned)
        let list = collector.finished()

        #expect(list.reasons == [.notSafeToParse])
        #expect(list.totalCount == 1)
        let group = try #require(list.groups(matching: FindingsFilter()).first)
        #expect(group.reason.title == "Not safe to parse")
        #expect(group.entries.map(\.path) == ["\(root)/bad/npm-shrinkwrap.json"])
        #expect(Scanner.packageFindings([Self.chalkRule], packages: result.packages).isEmpty)
    }

    @Test func aLockfileInUTF16IsListedInsteadOfParsed() throws {
        defer { cleanUp() }
        try write(Data("{}".utf8), to: "bad/package.json")
        try write(try #require(String(repeating: #"{"a":"#, count: 600).data(using: .utf16BigEndian)), to: "bad/package-lock.json")

        let result = packages(inProjects: ["bad": ["package.json", "package-lock.json"]])

        #expect(result.notScanned.map(\.explanation) == ["Not UTF-8 text, so it wasn't parsed (npm package check)"])
    }

    @Test func aCraftedGlobalManifestIsListedAndTheRestIsStillRead() throws {
        defer { cleanUp() }
        try write(Self.objects(100_000), to: "global/evil/package.json")
        try write(Self.manifest(name: "chalk", version: "5.6.1"), to: "global/evil/node_modules/nested/package.json")
        try write(Self.manifest(name: "debug", version: "4.4.2"), to: "global/good/package.json")

        let result = packages(inProjects: [:], moduleDirectories: ["\(root)/global"])

        #expect(Set(result.packages.map(\.name)) == ["chalk", "debug"])
        #expect(result.notScanned.map(\.path) == ["\(root)/global/evil/package.json"])
        #expect(result.notScanned.first?.reason == .notSafeToParse)
    }

    @Test func aCraftedChromiumManifestIsListedAndTheRestIsStillRead() throws {
        defer { cleanUp() }
        try write(Self.objects(100_000), to: "Default/Extensions/evil/1.0/manifest.json")
        try write(Data(#"{"name": "Good", "permissions": []}"#.utf8), to: "Default/Extensions/good/1.0/manifest.json")
        let root = root

        let result = onLargeStack { Scanner.chromiumExtensions(browser: "Chrome", root: root) }

        #expect(result.extensions.map(\.detail) == ["Chrome: Good (good)"])
        #expect(result.notScanned.map(\.path) == ["\(root)/Default/Extensions/evil/1.0/manifest.json"])
        #expect(result.notScanned.first?.explanation == "\(Self.nestedExplanation) (Browser extension check)")
    }

    @Test func craftedMessagesAreListedAndTheExtensionKeepsItsRawName() throws {
        defer { cleanUp() }
        try write(Data(#"{"name": "__MSG_appName__", "default_locale": "en"}"#.utf8), to: "Default/Extensions/evil/1.0/manifest.json")
        try write(Self.objects(100_000), to: "Default/Extensions/evil/1.0/_locales/en/messages.json")
        let root = root

        let result = onLargeStack { Scanner.chromiumExtensions(browser: "Chrome", root: root) }

        #expect(result.extensions.map(\.detail) == ["Chrome: __MSG_appName__ (evil)"])
        #expect(result.notScanned.map(\.path) == ["\(root)/Default/Extensions/evil/1.0/_locales/en/messages.json"])
        #expect(result.notScanned.first?.reason == .notSafeToParse)
    }

    @Test func aCraftedFirefoxListIsListedAndTheRestIsStillRead() throws {
        defer { cleanUp() }
        try write(Self.objects(100_000), to: "evil/extensions.json")
        try write(Data(#"{"addons": [{"id": "good@example.org", "location": "app-profile", "defaultLocale": {"name": "Good"}}]}"#.utf8), to: "good/extensions.json")
        let root = root

        let result = onLargeStack { Scanner.firefoxExtensions(profilesRoot: root) }

        #expect(result.extensions.map(\.detail) == ["Firefox: Good (good@example.org)"])
        #expect(result.notScanned.map(\.path) == ["\(root)/evil/extensions.json"])
        #expect(result.notScanned.first?.reason == .notSafeToParse)
    }

    @Test func theDiskWalkListsCraftedFilesAndKeepsGoing() throws {
        defer { cleanUp() }
        try write(Self.objects(100_000), to: "project/package-lock.json")
        try write(Self.objects(100_000), to: "project/node_modules/evil/package.json")
        try write(Data(#"{"lockfileVersion": 3, "packages": {"node_modules/chalk": {"version": "5.6.1"}}}"#.utf8), to: "project/good/package-lock.json")
        let root = root

        let result = onLargeStack {
            let walk = VolumeWalk(roots: [root])
            let walked = walk.packageFileFindings(rules: [Self.chalkRule], reported: [])
            return (findings: walked.findings, list: walk.notScanned.finished())
        }

        #expect(result.findings.map(\.path) == ["\(root)/project/good/package-lock.json"])
        #expect(result.list.reasons == [.notSafeToParse])
        #expect(Set(result.list.entries.map(\.path)) == ["\(root)/project/package-lock.json", "\(root)/project/node_modules/evil/package.json"])
        #expect(result.list.coverage?.packageFilesOpened == 3)
    }

    @Test(arguments: [false, true])
    func noLimitValueLetsACraftedFileThrough(atCeiling: Bool) throws {
        defer { cleanUp() }
        try write(Data("{}".utf8), to: "bad/package.json")
        try write(Self.objects(Self.tooDeep), to: "bad/package-lock.json")
        let limits = ScanLimits(unchecked: Dictionary(uniqueKeysWithValues: ScanLimit.all.map { ($0, atCeiling ? $0.range.upperBound : $0.range.lowerBound) }))

        let result = packages(inProjects: ["bad": ["package.json", "package-lock.json"]], limits: limits)

        #expect(result.notScanned.map(\.reason) == [.notSafeToParse])
    }

    @Test func aRealisticDeepOldFormatLockfileIsReadNormally() throws {
        defer { cleanUp() }
        var json = #"{"version": "1.0.0"}"#
        for level in 0..<ScanLimit.maxDependencyDepth.range.upperBound {
            json = #"{"version": "1.0.\#(level)", "integrity": "sha512-{[\"", "requires": {"x": "^1.0.0"}, "dependencies": {"dep-\#(level)": \#(json), "sibling-\#(level)": {"version": "2.0.\#(level)"}}}"#
        }
        try write(Data("{}".utf8), to: "app/package.json")
        try write(Data(#"{"name": "app", "lockfileVersion": 1, "dependencies": {"root": \#(json)}}"#.utf8), to: "app/package-lock.json")
        let ceiling = try #require(ScanLimits.defaults.setting(.maxDependencyDepth, to: ScanLimit.maxDependencyDepth.range.upperBound))

        let atDefault = packages(inProjects: ["app": ["package.json", "package-lock.json"]])
        let atCeiling = packages(inProjects: ["app": ["package.json", "package-lock.json"]], limits: ceiling)

        #expect(atDefault.notScanned.isEmpty)
        #expect(atDefault.packages.count == 1 + 2 * (ScanLimits.defaults[.maxDependencyDepth] - 1))
        #expect(atCeiling.notScanned.isEmpty)
        #expect(atCeiling.packages.count == 1 + 2 * (ScanLimit.maxDependencyDepth.range.upperBound - 1))
    }

    @Test func aRealisticFlatLockfileWithLongPathsIsReadNormally() throws {
        defer { cleanUp() }
        let path = (0..<100).map { "node_modules/package-\($0)" }.joined(separator: "/")
        let text = #"{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, "\#(path)": {"version": "1.2.3", "engines": {"node": ">=18"}, "dependencies": {"a": "^1"}}}}"#
        try write(Data("{}".utf8), to: "app/package.json")
        try write(Data(text.utf8), to: "app/package-lock.json")

        let result = packages(inProjects: ["app": ["package.json", "package-lock.json"]])

        #expect(result.notScanned.isEmpty)
        #expect(result.packages.map(\.name) == ["package-99"])
    }
}
