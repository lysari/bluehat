import Foundation
import Testing
@testable import BluehatCore

struct InstallationTests {
    func installation(_ manager: InstallManager, _ product: SoftwareProduct, _ version: String, path: String) throws -> Installation {
        Installation(product: product, version: try #require(SoftwareVersion(version, for: product)), path: path, manager: manager)
    }

    func version(_ text: String, _ product: SoftwareProduct = .node) throws -> SoftwareVersion {
        try #require(SoftwareVersion(text, for: product))
    }

    func rule(_ id: String, _ ranges: [VersionRange], product: SoftwareProduct = .node) -> Rule {
        Rule(id: id, title: "Test", severity: .high, category: .rce, check: .softwareVersion, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: product, advisory: "CVE-2024-0001", ranges: ranges, summary: nil, remedy: nil, references: nil)
    }

    func fixed(_ introduced: String, _ fixed: String) -> VersionRange {
        VersionRange(introduced: introduced, fixed: fixed, lastAffected: nil)
    }

    let nvmPath = "/Users/test/.nvm/versions/node/v16.20.2"

    @Test func targetsTheHighestFixAcrossEveryFindingOnTheSameCopy() throws {
        let copy = try installation(.nvm, .node, "16.20.2", path: nvmPath)
        let other = try installation(.nvm, .node, "16.20.2", path: "/Users/test/.nvm/versions/node/v16.20.2-copy")
        let rules = [
            rule("cve.a", [fixed("16.0.0", "16.20.3")]),
            rule("cve.b", [fixed("0", "18.20.1")]),
            rule("cve.c", [fixed("16.0.0", "22.0.0")]),
        ]
        let findings = Scanner.versionFindings(Array(rules.prefix(2)), installs: [copy]) + Scanner.versionFindings([rules[2]], installs: [other])

        #expect(copy.updateTarget(findings: findings) == (try version("18.20.1")))
    }

    @Test(arguments: [
        VersionRange(introduced: "16.0.0", fixed: nil, lastAffected: "16.20.2"),
        VersionRange(introduced: "16.0.0", fixed: nil, lastAffected: nil),
    ])
    func hasNoTargetWhenAnyFindingHasNoFix(range: VersionRange) throws {
        let copy = try installation(.nvm, .node, "16.20.2", path: nvmPath)
        let findings = Scanner.versionFindings([rule("cve.a", [fixed("16.0.0", "16.20.3")]), rule("cve.b", [range])], installs: [copy])

        #expect(findings.count == 2)
        #expect(copy.updateTarget(findings: findings) == nil)
    }

    @Test func hasNoTargetWhenTheHighestFixIsStillAffected() throws {
        let copy = try installation(.nvm, .node, "16.20.2", path: nvmPath)
        let findings = Scanner.versionFindings([
            rule("cve.a", [fixed("16.0.0", "16.20.3"), fixed("18.0.0", "18.20.5")]),
            rule("cve.b", [fixed("0", "18.20.1")]),
        ], installs: [copy])

        #expect(copy.updateTarget(findings: findings) == nil)
    }

    @Test func hasNoTargetWithoutFindings() throws {
        #expect(try installation(.nvm, .node, "16.20.2", path: nvmPath).updateTarget(findings: []) == nil)
    }

    @Test func buildsTheUpdateCommandOfEachManager() throws {
        let cases: [(Installation, String, String)] = [
            (try installation(.nvm, .node, "16.20.2", path: nvmPath), "18.20.1", "nvm install '18.20.1'"),
            (try installation(.fnm, .node, "16.20.2", path: "/Users/test/.local/share/fnm/node-versions/v16.20.2"), "18.20.1", "fnm install '18.20.1'"),
            (try installation(.volta, .node, "16.20.2", path: "/Users/test/.volta/tools/image/node/16.20.2"), "18.20.1", "volta install 'node@18.20.1'"),
            (try installation(.asdf, .node, "16.20.2", path: "/Users/test/.asdf/installs/nodejs/16.20.2"), "18.20.1", "asdf install 'nodejs' '18.20.1'"),
            (try installation(.mise, .python, "3.11.4", path: "/Users/test/.local/share/mise/installs/python/3.11.4"), "3.11.9", "mise install 'python@3.11.9'"),
            (try installation(.pyenv, .python, "3.11.4", path: "/Users/test/.pyenv/versions/3.11.4"), "3.11.9", "pyenv install '3.11.9'"),
            (try installation(.rbenv, .ruby, "3.2.2", path: "/Users/test/.rbenv/versions/3.2.2"), "3.2.4", "rbenv install '3.2.4'"),
            (try installation(.homebrew, .node, "20.10.0", path: "/opt/homebrew/Cellar/node@20/20.10.0"), "20.11.1", "/opt/homebrew/bin/brew upgrade 'node@20'"),
            (try installation(.homebrew, .openssl, "3.3.1", path: "/usr/local/Cellar/openssl@3/3.3.1"), "3.3.2", "/usr/local/bin/brew upgrade 'openssl@3'"),
        ]
        let commands = try cases.map { try $0.0.updateCommand(to: version($0.1, $0.0.product)) }

        #expect(commands.map(\.?.text) == cases.map(\.2))
        #expect(commands.map(\.?.setup) == [Installation.nvmSetup] + Array(repeating: nil, count: cases.count - 1))
    }

    @Test func installersUseTheirDownloadPageInsteadOfTerminal() throws {
        let node = try installation(.nodeInstaller, .node, "20.11.0", path: "/usr/local/bin/node")
        let python = try installation(.pythonOrg, .python, "3.12.1", path: "/Library/Frameworks/Python.framework/Versions/3.12")

        #expect(node.downloadPage?.absoluteString == "https://nodejs.org/en/download")
        #expect(python.downloadPage?.absoluteString == "https://www.python.org/downloads/macos/")
        #expect(node.updateCommand(to: try version("20.11.1")) == nil)
        #expect(python.updateCommand(to: try version("3.12.5", .python)) == nil)
        #expect(node.removeCommand(among: [node]) == nil)
        #expect(!node.isTrashable && !python.isTrashable)
        #expect(try installation(.nvm, .node, "16.20.2", path: nvmPath).downloadPage == nil)
    }

    @Test func refusesUnsafeOrBackwardUpdates() throws {
        let tamperedFormula = try installation(.homebrew, .node, "20.10.0", path: "/opt/homebrew/Cellar/node@20;rm -rf ~/20.10.0")
        let tamperedPlugin = try installation(.mise, .node, "16.20.2", path: "/Users/test/.local/share/mise/installs/no'de/16.20.2")
        let outsideCellar = try installation(.homebrew, .node, "20.10.0", path: "/tmp/Cellar/node/20.10.0")
        let copy = try installation(.nvm, .node, "16.20.2", path: nvmPath)

        #expect(tamperedFormula.updateCommand(to: try version("20.11.1")) == nil)
        #expect(tamperedFormula.removeCommand(among: [tamperedFormula]) == nil)
        #expect(tamperedPlugin.updateCommand(to: try version("18.20.1")) == nil)
        #expect(outsideCellar.updateCommand(to: try version("20.11.1")) == nil)
        #expect(copy.updateCommand(to: try version("16.20.2")) == nil)
        #expect(copy.updateCommand(to: try version("16.0.0")) == nil)
    }

    @Test func removesHomebrewCopiesWithBrewAndNeverTrashesThem() throws {
        let old = try installation(.homebrew, .node, "20.10.0", path: "/opt/homebrew/Cellar/node@20/20.10.0")
        let newest = try installation(.homebrew, .node, "20.11.1", path: "/opt/homebrew/Cellar/node@20/20.11.1")
        let otherFormula = try installation(.homebrew, .node, "22.3.0", path: "/opt/homebrew/Cellar/node/22.3.0")

        #expect(old.removeCommand(among: [old, newest, otherFormula])?.text == "/opt/homebrew/bin/brew cleanup 'node@20'")
        #expect(newest.removeCommand(among: [old, newest, otherFormula])?.text == "/opt/homebrew/bin/brew uninstall 'node@20'")
        #expect(old.removeCommand(among: [old, otherFormula])?.text == "/opt/homebrew/bin/brew uninstall 'node@20'")
        #expect(!old.isTrashable)
    }

    @Test(arguments: [InstallManager.nvm, .volta, .fnm, .asdf, .mise, .pyenv, .rbenv])
    func versionManagerCopiesGoToTheTrash(manager: InstallManager) throws {
        let copy = try installation(manager, .node, "16.20.2", path: nvmPath)

        #expect(copy.isTrashable)
        #expect(copy.removeCommand(among: [copy]) == nil)
    }
}
