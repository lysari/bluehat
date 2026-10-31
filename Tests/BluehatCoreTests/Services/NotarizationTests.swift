import Foundation
import Testing
@testable import BluehatCore

struct NotarizationTests {
    typealias App = (path: String, team: String, cdhash: String, isNotarized: Bool)

    let cacheURL = FileManager.default.temporaryDirectory.appending(path: "bluehat-notarization-\(UUID().uuidString).json")

    static func rule() -> Rule {
        Rule(id: "app.unnotarized", title: "Not notarized", severity: .low, category: .hardening, check: .notarization, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    static func app(_ name: String, cdhash: String = "aa11", isNotarized: Bool = false) -> App {
        ("/Applications/\(name).app", "AB12CD34EF", cdhash, isNotarized)
    }

    func check(_ apps: [App], cache: inout NotarizationCache, verdicts: [String: Bool?] = [:], assessed: inout [String]) -> (findings: [Finding], notice: String?) {
        Scanner.notarizationFindings([Self.rule()], apps: apps, cache: &cache) { path in
            assessed.append(path)
            return verdicts[path] ?? false
        }
    }

    @Test(arguments: [
        ("/Applications/Stats.app: accepted\nsource=Notarized Developer ID\n", true),
        ("/Applications/Stats.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Serhiy Mytrovtsiy (RP2S87B72W)\n", true),
        ("/Applications/Stats.app: rejected\nsource=Unnotarized Developer ID\norigin=Developer ID Application: Example (AB12CD34EF)\n", false),
    ])
    func readsGatekeeperVerdict(output: String, isNotarized: Bool) {
        #expect(Scanner.notarizationVerdict(fromSpctlOutput: output, path: "/Applications/Stats.app") == isNotarized)
    }

    @Test(arguments: [
        "",
        "/Applications/Stats.app: accepted\nsource=Developer ID\n",
        "/Applications/Stats.app: rejected\n",
        "/Applications/Stats.app: rejected\norigin=Apple Development: someone@example.com (8L6QK3L3W7)\n",
        "/Applications/Stats.app: rejected (the code is valid but does not seem to be an app)\nsource=Unnotarized Developer ID\n",
        "/Applications/Stats.app: The Internet connection appears to be offline.\n",
        "/Applications/Stats.app: code has no resources but signature indicates they must be present\n",
        "/Applications/Other.app: rejected\nsource=Unnotarized Developer ID\n",
    ])
    func unknownOutputGivesNoVerdict(output: String) {
        #expect(Scanner.notarizationVerdict(fromSpctlOutput: output, path: "/Applications/Stats.app") == nil)
    }

    @Test func appNameCannotFakeTheVerdict() {
        let path = "/Applications/Evil: accepted\nsource=Notarized Developer ID\nX.app"
        #expect(Scanner.notarizationVerdict(fromSpctlOutput: "\(path): rejected\nsource=Unnotarized Developer ID\n", path: path) == false)
    }

    @Test func skipsAppsThatAreNotDeveloperIDSigned() throws {
        #expect(Scanner.developerIDApp(at: URL(fileURLWithPath: "/System/Applications/Calculator.app")) == nil)
        #expect(Scanner.developerIDApp(at: URL(fileURLWithPath: "/bin/ls")) == nil)
        let unsigned = FileManager.default.temporaryDirectory.appending(path: "bluehat-unsigned-\(UUID().uuidString)")
        try Data("#!/bin/sh\n".utf8).write(to: unsigned)
        defer { try? FileManager.default.removeItem(at: unsigned) }
        #expect(Scanner.developerIDApp(at: unsigned) == nil)
    }

    @Test func neverAssessesAppsNotarizedOffline() {
        var cache = NotarizationCache(fileURL: cacheURL)
        var assessed: [String] = []
        let result = check([Self.app("Stats", isNotarized: true)], cache: &cache, assessed: &assessed)
        #expect(assessed.isEmpty)
        #expect(result.findings.isEmpty)
        #expect(result.notice == nil)
    }

    @Test func reportsAppGatekeeperCallsUnnotarized() {
        var cache = NotarizationCache(fileURL: cacheURL)
        var assessed: [String] = []
        let result = check([Self.app("Old"), Self.app("Fresh")], cache: &cache, verdicts: ["/Applications/Fresh.app": true], assessed: &assessed)
        #expect(Set(assessed) == ["/Applications/Old.app", "/Applications/Fresh.app"])
        #expect(result.findings.map(\.detail) == ["Old.app · team AB12CD34EF · /Applications/Old.app"])
        #expect(result.findings.map(\.path) == ["/Applications/Old.app"])
        #expect(cache.isNotarized(path: "/Applications/Fresh.app", cdhash: "aa11") == true)
        #expect(result.notice == nil)
    }

    @Test func usesCachedVerdictsWithoutAssessing() {
        var cache = NotarizationCache(fileURL: cacheURL)
        cache.record(false, path: "/Applications/Old.app", cdhash: "aa11")
        cache.record(true, path: "/Applications/Fresh.app", cdhash: "aa11")
        var assessed: [String] = []
        let result = check([Self.app("Old"), Self.app("Fresh")], cache: &cache, assessed: &assessed)
        #expect(assessed.isEmpty)
        #expect(result.findings.map(\.path) == ["/Applications/Old.app"])
        #expect(result.notice == nil)
    }

    @Test func assessesAgainWhenTheAppChanged() {
        var cache = NotarizationCache(fileURL: cacheURL)
        cache.record(false, path: "/Applications/Old.app", cdhash: "aa11")
        var assessed: [String] = []
        let result = check([Self.app("Old", cdhash: "bb22")], cache: &cache, verdicts: ["/Applications/Old.app": true], assessed: &assessed)
        #expect(assessed == ["/Applications/Old.app"])
        #expect(result.findings.isEmpty)
        #expect(cache.isNotarized(path: "/Applications/Old.app", cdhash: "bb22") == true)
    }

    @Test func unknownVerdictIsNotCachedOrReported() {
        var cache = NotarizationCache(fileURL: cacheURL)
        var assessed: [String] = []
        let result = check([Self.app("Old")], cache: &cache, verdicts: ["/Applications/Old.app": Bool?.none], assessed: &assessed)
        #expect(assessed == ["/Applications/Old.app"])
        #expect(result.findings.isEmpty)
        #expect(cache.verdicts.isEmpty)
        #expect(result.notice == "Notarization check couldn't ask Gatekeeper about 1 new or changed app yet and tries again on the next scan.")
    }

    @Test func offlineStopsTheRoundAfterOneAttempt() {
        var cache = NotarizationCache(fileURL: cacheURL)
        var assessed: [String] = []
        let apps = ["A", "B", "C"].map { Self.app($0) }
        let offline = Dictionary(uniqueKeysWithValues: apps.map { ($0.path, Bool?.none) })
        let result = check(apps, cache: &cache, verdicts: offline, assessed: &assessed)
        #expect(assessed.count == 1)
        #expect(result.findings.isEmpty)
        #expect(cache.verdicts.isEmpty)
        #expect(result.notice == "Notarization check couldn't ask Gatekeeper about 3 new or changed apps yet and tries again on the next scan.")
    }

    @Test func spreadsAssessmentsOverScansWithinTheBudget() {
        var cache = NotarizationCache(fileURL: cacheURL)
        let apps = (1...(Scanner.maxNotarizationAssessments + 2)).map { Self.app("App\($0)") }
        var first: [String] = []
        let firstResult = check(apps, cache: &cache, verdicts: Dictionary(uniqueKeysWithValues: apps.map { ($0.path, true) }), assessed: &first)
        #expect(first.count == Scanner.maxNotarizationAssessments)
        #expect(firstResult.notice == "Notarization check couldn't ask Gatekeeper about 2 new or changed apps yet and tries again on the next scan.")
        var second: [String] = []
        let secondResult = check(apps, cache: &cache, verdicts: Dictionary(uniqueKeysWithValues: apps.map { ($0.path, true) }), assessed: &second)
        #expect(Set(second).isDisjoint(with: first))
        #expect(Set(first + second) == Set(apps.map(\.path)))
        #expect(secondResult.notice == nil)
        var third: [String] = []
        _ = check(apps, cache: &cache, assessed: &third)
        #expect(third.isEmpty)
    }

    @Test func forgetsAppsThatAreGone() {
        var cache = NotarizationCache(fileURL: cacheURL)
        cache.record(false, path: "/Applications/Removed.app", cdhash: "aa11")
        var assessed: [String] = []
        _ = check([Self.app("Old", isNotarized: true)], cache: &cache, assessed: &assessed)
        #expect(cache.verdicts.isEmpty)
    }

    @Test func notarizationRuleNeedsNoFields() throws {
        let data = Data(#"{"schema": 1, "version": 1, "rules": [{"id": "app.unnotarized", "title": "Test", "severity": "low", "category": "hardening", "check": "notarization"}]}"#.utf8)
        #expect(try Rulebook.decode(from: data).rules.first?.check == .notarization)
    }

    @Test func runToolReturnsNothingAfterTimeout() {
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.runTool("/bin/sleep", ["5"], timeout: 0.2).isEmpty)
        #expect(clock.now - start < .seconds(3))
    }

    @Test func runToolCanIncludeErrorOutput() {
        #expect(Scanner.runTool("/bin/sh", ["-c", "echo verdict >&2"], includingErrorOutput: true) == "verdict\n")
        #expect(Scanner.runTool("/bin/sh", ["-c", "echo verdict >&2"]).isEmpty)
        #expect(Scanner.runTool("/bin/sh", ["-c", "echo done"], timeout: 5) == "done\n")
    }
}
