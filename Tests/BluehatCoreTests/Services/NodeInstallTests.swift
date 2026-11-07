import Foundation
import Testing
@testable import BluehatCore

struct NodeInstallTests {
    static let cleanCli = """
        const validateEngines = require('./cli/validate-engines.js')
        const cliEntry = require.resolve('./cli/entry.js')

        module.exports = (process) => validateEngines(process, () => require(cliEntry))
        """
    static let injectedCli = cleanCli + "\nglobal.i='5-1857-du';var _$_a1=(function(n,w){return n})('x',1);\n"

    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-node-installs-\(UUID().uuidString)")
    let marker = NodeInstallTests.rule("npm.marker", files: ["npm/lib/cli.js", "npm/bin/npm-cli.js"], patterns: [#"\bglobal\.[A-Za-z_$]{1,3}\s*=\s*['"]\d-\d{3,5}-[a-z]{2}['"]"#])

    static func rule(_ id: String, files: [String], patterns: [String]) -> Rule {
        Rule(id: id, title: id, severity: .critical, category: .malware, check: .nodeInstall, patterns: patterns, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: files, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func write(_ text: String, to relativePath: String) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func nvmModuleDirectories() -> [String] {
        NpmInventory.moduleDirectories(for: Scanner.versionedInstalls(of: .node, by: .nvm, in: root.appending(path: ".nvm/versions/node").path))
    }

    func relative(_ findings: [Finding]) -> [String] {
        findings.map { "\($0.rule.id) \($0.detail.replacingOccurrences(of: root.path + "/", with: ""))" }
    }

    @Test func reportsThePayloadLineInEachInfectedNvmVersion() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write(Self.injectedCli, to: ".nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js")
        try write(Self.injectedCli, to: ".nvm/versions/node/v22.14.0/lib/node_modules/npm/lib/cli.js")
        try write(Self.cleanCli, to: ".nvm/versions/node/v20.11.1/lib/node_modules/npm/lib/cli.js")

        let checked = Scanner.nodeInstallFindings([marker], moduleDirectories: nvmModuleDirectories())

        #expect(relative(checked.findings) == [
            "npm.marker Line 5 · .nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js",
            "npm.marker Line 5 · .nvm/versions/node/v22.14.0/lib/node_modules/npm/lib/cli.js",
        ])
        #expect(checked.findings.first?.path == root.appending(path: ".nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js").path)
        #expect(checked.findings.allSatisfy { !$0.detail.contains("5-1857-du") })
        #expect(checked.notScanned.isEmpty)
    }

    @Test func cleanNpmGivesNoFinding() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write(Self.cleanCli, to: ".nvm/versions/node/v22.14.0/lib/node_modules/npm/lib/cli.js")
        try write("#!/usr/bin/env node\nrequire('../lib/cli.js')(process)\n", to: ".nvm/versions/node/v22.14.0/lib/node_modules/npm/bin/npm-cli.js")

        #expect(Scanner.nodeInstallFindings([marker], moduleDirectories: nvmModuleDirectories()).findings.isEmpty)
    }

    @Test func readsOnlyTheNamedFilesOnceInEachGlobalFolder() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let global = root.appending(path: "homebrew/lib/node_modules").path
        try write(Self.injectedCli, to: "homebrew/lib/node_modules/npm/lib/other.js")
        try write(Self.injectedCli, to: "homebrew/lib/node_modules/left-pad/lib/cli.js")
        try write(Self.injectedCli, to: "homebrew/lib/node_modules/npm/bin/npm-cli.js")
        try write(Self.injectedCli, to: "outside/cli.js")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "homebrew/lib/node_modules/npm/lib/cli.js").path, withDestinationPath: root.appending(path: "outside/cli.js").path)

        let checked = Scanner.nodeInstallFindings([marker], moduleDirectories: [global, global, root.appending(path: "missing").path])

        #expect(relative(checked.findings) == ["npm.marker Line 5 · homebrew/lib/node_modules/npm/bin/npm-cli.js"])
    }

    @Test func scansTheCappedStartOfAnOversizedFileAndReportsIt() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let filler = String(repeating: "// padding\n", count: ScanLimits.defaults[.maxReadBytes] / 11 + 1)
        try write(Self.injectedCli + filler, to: ".nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js")
        try write(filler + Self.injectedCli, to: ".nvm/versions/node/v22.14.0/lib/node_modules/npm/lib/cli.js")

        let checked = Scanner.nodeInstallFindings([marker], moduleDirectories: nvmModuleDirectories())

        #expect(relative(checked.findings) == ["npm.marker Line 5 · .nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js"])
        #expect(checked.notScanned.map(\.path) == [
            root.appending(path: ".nvm/versions/node/v16.20.2/lib/node_modules/npm/lib/cli.js").path,
            root.appending(path: ".nvm/versions/node/v22.14.0/lib/node_modules/npm/lib/cli.js").path,
        ])
        #expect(checked.notScanned.allSatisfy { $0.reason == .partlyRead && $0.explanation == "Only the first 1 MB was read (Node.js install check)" })
    }
}
