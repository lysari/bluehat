import Foundation
import Testing
@testable import BluehatCore

struct ProjectFoldersTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-projects-\(UUID().uuidString)")
    let names: Set<String> = ["package.json", "yarn.lock"]

    func write(_ relativePath: String) throws {
        let url = root.appending(path: relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: url)
    }

    func found(_ folders: [String], budget: Int = ProjectFolders.maxFoldersPerProjectFolder) -> [String] {
        ProjectFolders.directories(in: folders, containing: names, budget: budget).directories.map {
            ($0.path.replacingOccurrences(of: root.path, with: "")) + " " + $0.files.sorted().joined(separator: ",")
        }
    }

    @Test func findsProjectsWithTheirFilesAndSkipsDependencyGitBuildAndLibraryFolders() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("app/package.json")
        try write("app/yarn.lock")
        try write("app/README.md")
        try write("app/packages/web/package.json")
        try write("app/node_modules/chalk/package.json")
        try write("app/.git/hooks/package.json")
        try write("app/.yarn/cache/package.json")
        try write("app/dist/package.json")
        try write("app/build/package.json")
        try write("Library/Caches/package.json")
        try write("notes/todo.txt")

        #expect(found([root.path]) == ["/app README.md,package.json,yarn.lock", "/app/packages/web package.json"])
    }

    @Test func neverFollowsSymlinkedFolders() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("outside/secret/package.json")
        try write("projects/real/package.json")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "projects/linked").path, withDestinationPath: root.appending(path: "outside").path)

        #expect(found([root.appending(path: "projects").path]) == ["/projects/real package.json"])
    }

    @Test func stopsAtTheMaximumDepth() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let deepest = (1...ProjectFolders.maxDepth).map { "d\($0)" }.joined(separator: "/")
        try write("\(deepest)/package.json")
        try write("\(deepest)/too-deep/package.json")

        #expect(found([root.path]) == ["/\(deepest) package.json"])
    }

    @Test func skipsPythonCompiledAndOtherBuildFoldersButNotCodeFolders() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        for skipped in ["__pycache__", "site-packages", "dist-packages", "obj", "_build", "deps", "CMakeFiles", "elm-stuff", "bazel-out", "bazel-app"] {
            try write("skipped/\(skipped)/package.json")
        }
        for kept in ["apps", "bazel", "bin", "env", "lib", "library", "packages", "scripts", "src", "tmp", "tools"] {
            try write("kept/\(kept)/package.json")
        }

        #expect(found([root.path]) == ["apps", "bazel", "bin", "env", "lib", "library", "packages", "scripts", "src", "tmp", "tools"].map { "/kept/\($0) package.json" })
    }

    @Test func checksOnlyTheTopOfPythonEnvironments() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("venv/pyvenv.cfg")
        try write("venv/share/jupyter/lab/package.json")
        try write("tools/pyvenv.cfg")
        try write("tools/package.json")
        try write("tools/web/package.json")
        try write("miniconda/conda-meta/history")
        try write("miniconda/pkgs/lab/package.json")
        try write("env/package.json")

        #expect(found([root.path]) == ["/env package.json", "/tools package.json,pyvenv.cfg"])
    }

    @Test func checksOnlyTheTopOfAppsAndOtherPackages() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("Editor.app/package.json")
        try write("Editor.app/Contents/Resources/app/package.json")
        try write("App.xcodeproj/web/package.json")
        try write("Photos.photoslibrary/resources/package.json")
        try write("Plugin.bundle/Contents/package.json")
        try write("chart.js/package.json")

        #expect(found([root.path]) == ["/Editor.app package.json", "/chart.js package.json"])
    }

    @Test func aFolderOfManyFilesCostsOneFolderOfTheBudget() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        for index in 0..<500 {
            try write("photos/\(index).jpg")
        }
        try write("photos/package.json")
        try write("web/package.json")

        let walked = ProjectFolders.directories(in: [root.path], containing: names, budget: 3)

        #expect(walked.directories.map { URL(fileURLWithPath: $0.path).lastPathComponent } == ["photos", "web"])
        #expect(walked.notice == nil)
    }

    @Test func folderBudgetCutsEachProjectFolderAndNamesEveryCutOne() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("one/a/package.json")
        try write("one/b/deeper/package.json")
        try write("two/a/b/c/package.json")
        try write("three/a/package.json")
        let folders = ["one", "two", "three"].map { root.appending(path: $0).path }

        let walked = ProjectFolders.directories(in: folders, containing: names, budget: 3)

        #expect(walked.directories.map { $0.path.replacingOccurrences(of: root.path, with: "") } == ["/one/a", "/three/a"])
        #expect(walked.notice == "Project folder check covered only the first 3 folders per project folder and stopped early in \(folders[0]), \(folders[1]).")
    }

    @Test func reportsNothingWithinTheBudget() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("a/package.json")

        #expect(ProjectFolders.directories(in: [root.path], containing: names, budget: 2).notice == nil)
    }

    @Test func fileNameBudgetCutsTheWalkAndReportsIt() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("a/package.json")
        try write("a/README.md")
        try write("a/index.js")
        try write("b/package.json")
        try write("notes/one.txt")

        let walked = ProjectFolders.directories(in: [root.path], containing: names, fileNameBudget: 3)

        #expect(walked.directories.map { URL(fileURLWithPath: $0.path).lastPathComponent } == ["a"])
        #expect(walked.notice == "Project folder check kept only the first 3 file names of projects per project folder and stopped early in \(root.path).")
    }

    @Test func walksNestedAndRepeatedFoldersOnce() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("code/app/package.json")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "alias").path, withDestinationPath: root.appending(path: "code").path)

        let folders = [root.appending(path: "code").path, root.appending(path: "code/app").path, root.appending(path: "alias").path, root.appending(path: "code").path]

        #expect(found(folders) == ["/code/app package.json"])
    }

    @Test func keepsOnlyExistingAbsoluteDirectoriesOnceEach() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try write("code/package.json")
        try FileManager.default.createSymbolicLink(atPath: root.appending(path: "alias").path, withDestinationPath: root.appending(path: "code").path)
        let code = root.appending(path: "code").path

        let unique = ProjectFolders.uniqueDirectories([code, root.appending(path: "alias").path, root.appending(path: "missing").path, "\(code)/package.json", "relative/code", code])

        #expect(unique == [code])
    }

    @Test func defaultsAreTheUsualCodeFoldersInHomeOutsideDocuments() {
        #expect(ProjectFolders.defaults == ["~/Developer", "~/Projects", "~/Code", "~/code", "~/src", "~/dev", "~/Sites", "~/git", "~/repos"])
    }
}
