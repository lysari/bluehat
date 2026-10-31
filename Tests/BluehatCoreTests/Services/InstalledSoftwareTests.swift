import Foundation
import Testing
@testable import BluehatCore

struct InstalledSoftwareTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-software-\(UUID().uuidString)")

    func makeDirectory(_ relativePath: String) throws {
        try FileManager.default.createDirectory(at: root.appending(path: relativePath), withIntermediateDirectories: true)
    }

    func write(_ text: String, to relativePath: String) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func link(_ relativePath: String, to target: String) throws {
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: relativePath).path, withDestinationPath: target)
    }

    func summary(_ installs: [Installation]) -> [String] {
        installs.map { "\($0.manager.rawValue) \($0.product.rawValue) \($0.version) \($0.path.replacingOccurrences(of: root.path + "/", with: ""))" }
    }

    func rule(_ product: SoftwareProduct, _ ranges: [VersionRange], advisory: String = "CVE-2024-21892") -> Rule {
        Rule(id: "cve.test", title: "Test", severity: .high, category: .rce, check: .softwareVersion, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: product, advisory: advisory, ranges: ranges, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, summary: nil, remedy: nil, references: nil)
    }

    func install(_ product: SoftwareProduct, _ version: String, path: String = "/x") throws -> Installation {
        Installation(product: product, version: try #require(SoftwareVersion(version, for: product)), path: path, manager: .nvm)
    }

    @Test func readsEveryVersionDirectoryAndSkipsLinksFilesAndOtherNames() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try makeDirectory("nvm/v20.11.0")
        try makeDirectory("nvm/v18.19.1")
        try makeDirectory("nvm/system")
        try makeDirectory("nvm/v23.0.0-nightly")
        try write("", to: "nvm/v21.0.0")
        try link("nvm/20", to: root.appending(path: "nvm/v20.11.0").path)

        let installs = Scanner.versionedInstalls(of: .node, by: .nvm, in: root.appending(path: "nvm").path)

        #expect(summary(installs) == ["nvm node 18.19.1 nvm/v18.19.1", "nvm node 20.11.0 nvm/v20.11.0"])
    }

    @Test func readsHomebrewFormulasByProductName() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        for path in ["node/22.3.0", "node@20/20.11.0", "python@3.12/3.12.4_1", "openssl@1.1/1.1.1w", "openssl@3/3.3.1", "git/2.45.2", "git-lfs/3.5.1", "ruby/HEAD-abc123", "php@8.1/8.1.29", "python-tk@3.12/3.12.4"] {
            try makeDirectory("Cellar/\(path)")
        }

        let installs = Scanner.cellarInstalls(in: root.appending(path: "Cellar").path)

        #expect(summary(installs) == [
            "homebrew git 2.45.2 Cellar/git/2.45.2",
            "homebrew node 22.3.0 Cellar/node/22.3.0",
            "homebrew node 20.11.0 Cellar/node@20/20.11.0",
            "homebrew openssl 1.1.1w Cellar/openssl@1.1/1.1.1w",
            "homebrew openssl 3.3.1 Cellar/openssl@3/3.3.1",
            "homebrew php 8.1.29 Cellar/php@8.1/8.1.29",
            "homebrew python 3.12.4 Cellar/python@3.12/3.12.4_1",
        ])
    }

    @Test func readsPythonFrameworkVersionFromItsHeader() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("#define PY_MINOR_VERSION        12\n#define PY_VERSION              \"3.12.1\"\n", to: "Versions/3.12/include/python3.12/patchlevel.h")
        try write("#define PY_VERSION \"3.13.0a1+\"\n", to: "Versions/3.13/include/python3.13/patchlevel.h")
        try makeDirectory("Versions/3.11")
        try link("Versions/Current", to: root.appending(path: "Versions/3.12").path)

        let installs = Scanner.frameworkPythons(in: root.appending(path: "Versions").path)

        #expect(summary(installs) == ["pythonOrg python 3.12.1 Versions/3.12"])
    }

    @Test func readsInstallerNodeOnlyWhenItsBinaryIsARealFile() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("#define NODE_MAJOR_VERSION 20\n#define NODE_MINOR_VERSION 11\n#define NODE_PATCH_VERSION 0\n", to: "installer/include/node/node_version.h")
        try write("", to: "installer/bin/node")
        try write("#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 3\n#define NODE_PATCH_VERSION 0\n", to: "brew/include/node/node_version.h")
        try makeDirectory("brew/bin")
        try link("brew/bin/node", to: root.appending(path: "installer/bin/node").path)

        #expect(summary(Scanner.installerNode(prefix: root.appending(path: "installer").path)) == ["nodeInstaller node 20.11.0 installer/bin/node"])
        #expect(Scanner.installerNode(prefix: root.appending(path: "brew").path).isEmpty)
        #expect(Scanner.installerNode(prefix: root.appending(path: "missing").path).isEmpty)
    }

    @Test func matchesFixedAndLastAffectedRanges() throws {
        let rule = rule(.node, [
            VersionRange(introduced: "20.0.0", fixed: "20.11.1", lastAffected: nil),
            VersionRange(introduced: "0", fixed: nil, lastAffected: "18.19.0"),
            VersionRange(introduced: "22.0.0", fixed: nil, lastAffected: nil),
        ])
        let affected = ["20.0", "20.11.0", "v20.11.0", "18.19.0", "0.10.48", "22.0.0", "23.1.0"]
        let unaffected = ["20.11.1", "20.12.0", "18.19.1", "19.0.0", "21.7.3"]
        for version in affected {
            #expect(Scanner.affectingRange(of: rule, for: try #require(SoftwareVersion(version, for: .node))) != nil, "\(version)")
        }
        for version in unaffected {
            #expect(Scanner.affectingRange(of: rule, for: try #require(SoftwareVersion(version, for: .node))) == nil, "\(version)")
        }
    }

    @Test func reportsEachAffectedCopyWithAdvisoryVersionAndPath() throws {
        let rule = rule(.node, [VersionRange(introduced: "20.0.0", fixed: "20.11.1", lastAffected: nil), VersionRange(introduced: "0", fixed: nil, lastAffected: "18.19.0")])
        let installs = [
            try install(.node, "20.11.0", path: "/opt/homebrew/Cellar/node@20/20.11.0"),
            try install(.node, "v20.10.0", path: "/Users/test/.nvm/versions/node/v20.10.0"),
            try install(.node, "18.17.0", path: "/usr/local/bin/node"),
            try install(.node, "20.11.1", path: "/Users/test/.nvm/versions/node/v20.11.1"),
            try install(.python, "20.10.0", path: "/Users/test/.pyenv/versions/20.10.0"),
        ]

        let findings = Scanner.versionFindings([rule], installs: installs)

        #expect(findings.map(\.detail) == [
            "CVE-2024-21892: node 20.11.0 is affected (fixed in 20.11.1) · /opt/homebrew/Cellar/node@20/20.11.0",
            "CVE-2024-21892: node 20.10.0 is affected (fixed in 20.11.1) · /Users/test/.nvm/versions/node/v20.10.0",
            "CVE-2024-21892: node 18.17.0 is affected (no fixed release listed) · /usr/local/bin/node",
        ])
        #expect(findings.map(\.path) == ["/opt/homebrew/Cellar/node@20/20.11.0", "/Users/test/.nvm/versions/node/v20.10.0", "/usr/local/bin/node"])
        #expect(Set(findings.map(\.fingerprint)).count == 3)
    }

    @Test func namesTheManagerOfEveryVersionDirectory() {
        let managers = Dictionary(uniqueKeysWithValues: Scanner.versionDirectories.map { ($0.directory, $0.manager) })

        #expect(managers == [
            "~/.nvm/versions/node": .nvm,
            "~/.volta/tools/image/node": .volta,
            "~/Library/Application Support/fnm/node-versions": .fnm,
            "~/.local/share/fnm/node-versions": .fnm,
            "~/.asdf/installs/nodejs": .asdf,
            "~/.local/share/mise/installs/node": .mise,
            "~/.pyenv/versions": .pyenv,
            "~/.asdf/installs/python": .asdf,
            "~/.local/share/mise/installs/python": .mise,
            "~/.rbenv/versions": .rbenv,
            "~/.asdf/installs/ruby": .asdf,
            "~/.local/share/mise/installs/ruby": .mise,
            "~/.asdf/installs/php": .asdf,
            "~/.local/share/mise/installs/php": .mise,
        ])
    }

    @Test func recognizesOnlyTheExactFoldersTheScannerFound() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try makeDirectory("nvm/v16.20.2")
        try makeDirectory("nvm/v18.19.0")
        try makeDirectory("elsewhere/v16.20.2")
        try link("nvm/v20.11.0", to: root.appending(path: "elsewhere/v16.20.2").path)
        try makeDirectory("Cellar/node@20/20.10.0")
        try write("#define NODE_MAJOR_VERSION 20\n#define NODE_MINOR_VERSION 11\n#define NODE_PATCH_VERSION 0\n", to: "installer/include/node/node_version.h")
        try write("", to: "installer/bin/node")
        try write("#define PY_VERSION \"3.12.1\"\n", to: "Versions/3.12/include/python3.12/patchlevel.h")
        let installs = Scanner.versionedInstalls(of: .node, by: .nvm, in: root.appending(path: "nvm").path)
            + Scanner.cellarInstalls(in: root.appending(path: "Cellar").path)
            + Scanner.installerNode(prefix: root.appending(path: "installer").path)
            + Scanner.frameworkPythons(in: root.appending(path: "Versions").path)
        func installation(_ relativePath: String) -> Installation? {
            Scanner.installation(at: root.path + "/" + relativePath, in: installs)
        }

        #expect(installation("nvm/v16.20.2")?.isTrashable == true)
        #expect(installation("nvm/v20.11.0") == nil)
        #expect(installation("nvm/v18.19.0/../v16.20.2") == nil)
        #expect(installation("nvm/./v16.20.2") == nil)
        #expect(installation("nvm/v16.20.2/") == nil)
        #expect(installation("nvm") == nil)
        #expect(installation("elsewhere/v16.20.2") == nil)
        #expect(Scanner.installation(at: "/", in: installs) == nil)
        #expect(installation("Cellar/node@20/20.10.0")?.isTrashable == false)
        #expect(installation("installer/bin/node")?.isTrashable == false)
        #expect(installation("Versions/3.12")?.isTrashable == false)
    }

    @Test func missingInstallLocationsGiveNoSoftware() {
        #expect(Scanner.versionedInstalls(of: .node, by: .nvm, in: root.path).isEmpty)
        #expect(Scanner.cellarInstalls(in: root.path).isEmpty)
        #expect(Scanner.frameworkPythons(in: root.path).isEmpty)
    }
}
