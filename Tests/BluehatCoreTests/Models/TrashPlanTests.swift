import Foundation
import Testing
@testable import BluehatCore

struct TrashPlanTests {
    struct MoveRefused: LocalizedError {
        var errorDescription: String? { "The folder is in use." }
    }

    let nvm = "/Users/test/.nvm/versions/node/v16.20.2"
    let pyenv = "/Users/test/.pyenv/versions/3.11.4"
    let brew = "/opt/homebrew/Cellar/node@20/20.10.0"

    func rule(_ id: String, _ check: CheckKind = .softwareVersion) -> Rule {
        Rule(id: id, title: "Test", severity: .high, category: .rce, check: check, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: .node, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func finding(_ id: String, path: String?, check: CheckKind = .softwareVersion) -> Finding {
        Finding(rule: rule(id, check), detail: id, path: path)
    }

    func install(_ path: String, _ manager: InstallManager = .nvm) throws -> Installation {
        Installation(product: .node, version: try #require(SoftwareVersion("16.20.2", for: .node)), path: path, manager: manager)
    }

    @Test func countsOnlyFindingsThatOfferMoveToTrash() throws {
        let plan = TrashPlan(findings: [
            finding("cve.a", path: nvm),
            finding("cve.b", path: brew),
            finding("cve.c", path: "/Users/test/.nvm/versions/node/gone"),
            finding("cve.d", path: nil),
        ], installs: [try install(nvm), try install(brew, .homebrew)])

        #expect(plan.findingCount == 1)
        #expect(plan.otherFindingCount == 3)
        #expect(plan.movable.map(\.path) == [nvm])
        #expect(plan.refused.isEmpty)
    }

    @Test func aPathOnAnotherCheckNeverCounts() throws {
        let plan = TrashPlan(findings: [finding("malware", path: nvm, check: .path)], installs: [try install(nvm)])

        #expect(plan.findingCount == 0)
        #expect(plan.otherFindingCount == 1)
        #expect(plan.movable.isEmpty)
    }

    @Test func listsEachCopyOnceAndCountsEveryFindingOnIt() throws {
        let plan = TrashPlan(findings: [
            finding("cve.a", path: nvm),
            finding("cve.b", path: pyenv),
            finding("cve.c", path: nvm),
        ], installs: [try install(nvm), try install(pyenv, .pyenv)])

        #expect(plan.findingCount == 3)
        #expect(plan.movableFindingCount == 3)
        #expect(plan.otherFindingCount == 0)
        #expect(plan.movable.map(\.path) == [nvm, pyenv])
    }

    @Test func refusesProtectedLocationsAndReportsThemNotMoved() throws {
        let protected = "/Library/Frameworks/nvm/v16.20.2"
        let plan = TrashPlan(findings: [finding("cve.a", path: nvm), finding("cve.b", path: protected)], installs: [try install(nvm), try install(protected)])
        var attempted: [String] = []

        let result = plan.run { attempted.append($0.path) }

        #expect(plan.findingCount == 2)
        #expect(plan.movableFindingCount == 1)
        #expect(plan.otherFindingCount == 0)
        #expect(plan.movable.map(\.path) == [nvm])
        #expect(plan.refused.map(\.path) == [protected])
        #expect(attempted == [nvm])
        #expect(result.moved == [nvm])
        #expect(result.notMoved == [TrashPlan.NotMoved(path: protected, reason: TrashPlan.protectedReason)])
    }

    @Test func keepsMovingPastAFailureAndSaysWhy() throws {
        let third = "/Users/test/.volta/tools/image/node/16.20.2"
        let plan = TrashPlan(findings: [finding("a", path: nvm), finding("b", path: pyenv), finding("c", path: third)], installs: [try install(nvm), try install(pyenv, .pyenv), try install(third, .volta)])
        var attempted: [String] = []

        let result = plan.run { copy in
            attempted.append(copy.path)
            if copy.path == pyenv { throw MoveRefused() }
        }

        #expect(attempted == [nvm, pyenv, third])
        #expect(result.moved == [nvm, third])
        #expect(result.notMoved == [TrashPlan.NotMoved(path: pyenv, reason: "The folder is in use.")])
    }

    @Test func reportsCleanedPathsSoALineCantBeSpoofed() throws {
        let spoofed = "/Users/test/.nvm/versions/node/v16\u{202E}\nx"
        let plan = TrashPlan(findings: [finding("a", path: spoofed)], installs: [try install(spoofed)])

        #expect(plan.run { _ in }.moved == ["/Users/test/.nvm/versions/node/v16 x"])
    }

    @Test func aLinkedVersionFolderIsNeverACopy() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-trash-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let real = root.appending(path: "nvm/v20.0.0").path
        let linked = root.appending(path: "nvm/v18.0.0").path
        try FileManager.default.createDirectory(atPath: real, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appending(path: "elsewhere"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: linked, withDestinationPath: root.appending(path: "elsewhere").path)

        let installs = Scanner.versionedInstalls(of: .node, by: .nvm, in: root.appending(path: "nvm").path)
        let plan = TrashPlan(findings: [finding("a", path: linked)], installs: installs)

        #expect(installs.map(\.path) == [real])
        #expect(plan.findingCount == 0)
    }
}
