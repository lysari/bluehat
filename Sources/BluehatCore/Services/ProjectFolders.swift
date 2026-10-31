import Foundation

public enum ProjectFolders {
    static let defaults = ["~/Developer", "~/Projects", "~/Code", "~/code", "~/src", "~/dev", "~/Sites", "~/git", "~/repos"]
    static let skippedDirectories: Set<String> = [
        "node_modules", "bower_components", "jspm_packages", "Library", "build", "dist", "out", "target", "coverage", "vendor", "Pods", "DerivedData",
        "__pycache__", "site-packages", "dist-packages", "obj", "_build", "deps", "CMakeFiles", "elm-stuff",
    ]
    static let skippedDirectoryPrefixes = ["bazel-"]
    static let environmentMarkers: Set<String> = ["pyvenv.cfg", "conda-meta"]
    public static let maxDepth = 6
    static let maxFoldersPerProjectFolder = 50_000
    static let maxFileNamesPerProjectFolder = 200_000

    public static func existingDefaults() -> [String] {
        uniqueDirectories(defaults.map(Scanner.expand))
    }

    static func uniqueDirectories(_ paths: [String]) -> [String] {
        var identities = Set<String>()
        return paths.filter { path in
            var status = stat()
            guard path.hasPrefix("/"), stat(path, &status) == 0, status.st_mode & S_IFMT == S_IFDIR else { return false }
            return identities.insert("\(status.st_dev):\(status.st_ino)").inserted
        }
    }

    static func directories(in folders: [String], containing names: Set<String>, budget: Int = maxFoldersPerProjectFolder, fileNameBudget: Int = maxFileNamesPerProjectFolder) -> (directories: [(path: String, files: Set<String>)], notice: String?) {
        var found: [(path: String, files: Set<String>)] = []
        var walked = Set<String>()
        var cut: [String] = []
        var fileNameCut: [String] = []
        for folder in uniqueDirectories(folders) {
            let shownFolder = NSString(string: folder).abbreviatingWithTildeInPath
            var queue = [(path: folder, depth: 0, isPackage: false)]
            var next = 0
            var visited = 0
            var fileNames = 0
            var isCut = false
            walk: while next < queue.count {
                let (directory, depth, isPackage) = queue[next]
                next += 1
                guard walked.insert(directory).inserted else { continue }
                visited += 1
                let entries = contents(of: directory)
                let files = Set(entries.filter { !$0.isDirectory }.map(\.name))
                if !files.isDisjoint(with: names) {
                    fileNames += files.count
                    guard fileNames <= fileNameBudget else {
                        fileNameCut.append(shownFolder)
                        break
                    }
                    found.append((directory, files))
                }
                guard depth < maxDepth, !isPackage, !entries.contains(where: { environmentMarkers.contains($0.name) }) else { continue }
                for entry in entries where entry.isDirectory && !entry.name.hasPrefix(".") && !skippedDirectories.contains(entry.name) && !skippedDirectoryPrefixes.contains(where: { entry.name.hasPrefix($0) }) {
                    guard queue.count - next < budget - visited else {
                        isCut = true
                        continue walk
                    }
                    queue.append(("\(directory)/\(entry.name)", depth + 1, entry.isPackage))
                }
            }
            if isCut, !fileNameCut.contains(shownFolder) { cut.append(shownFolder) }
        }
        let notices = [
            cut.isEmpty ? nil : "Project folder check covered only the first \(budget.formatted()) folders per project folder and stopped early in \(cut.joined(separator: ", ")).",
            fileNameCut.isEmpty ? nil : "Project folder check kept only the first \(fileNameBudget.formatted()) file names of projects per project folder and stopped early in \(fileNameCut.joined(separator: ", ")).",
        ].compactMap { $0 }
        return (found, notices.isEmpty ? nil : notices.joined(separator: " "))
    }

    static func contents(of directory: String) -> [(name: String, isDirectory: Bool, isPackage: Bool)] {
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isSymbolicLinkKey]
        let urls = (try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: directory, isDirectory: true), includingPropertiesForKeys: Array(keys))) ?? []
        return urls.map { url in
            let values = try? url.resourceValues(forKeys: keys)
            let isDirectory = values?.isDirectory == true && values?.isSymbolicLink != true
            return (url.lastPathComponent, isDirectory, isDirectory && (try? url.resourceValues(forKeys: [.isPackageKey]))?.isPackage == true)
        }
        .sorted { $0.name < $1.name }
    }
}
