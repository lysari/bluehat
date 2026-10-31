import Foundation

public enum ProjectFolders {
    static let defaults = ["~/Developer", "~/Projects", "~/Code", "~/code", "~/src", "~/dev", "~/Sites", "~/git", "~/repos"]
    static let skippedDirectories: Set<String> = ["node_modules", "bower_components", "jspm_packages", "Library", "build", "dist", "out", "target", "coverage", "vendor", "Pods", "DerivedData"]
    public static let maxDepth = 6
    static let maxEntriesPerFolder = 100_000

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

    static func directories(in folders: [String], containing names: Set<String>, budget: Int = maxEntriesPerFolder) -> (directories: [(path: String, files: Set<String>)], notice: String?) {
        var found: [(path: String, files: Set<String>)] = []
        var walked = Set<String>()
        var cut: [String] = []
        for folder in uniqueDirectories(folders) {
            var queue = [(path: folder, depth: 0)]
            var next = 0
            var visited = 0
            while next < queue.count {
                let (directory, depth) = queue[next]
                next += 1
                guard walked.insert(directory).inserted else { continue }
                guard visited < budget else {
                    cut.append(NSString(string: folder).abbreviatingWithTildeInPath)
                    break
                }
                let entries = contents(of: directory)
                visited += entries.count
                let files = Set(entries.filter { !$0.isDirectory }.map(\.name))
                if !files.isDisjoint(with: names) { found.append((directory, files)) }
                guard depth < maxDepth else { continue }
                for entry in entries where entry.isDirectory && !entry.name.hasPrefix(".") && !skippedDirectories.contains(entry.name) {
                    queue.append(("\(directory)/\(entry.name)", depth + 1))
                }
            }
        }
        guard !cut.isEmpty else { return (found, nil) }
        return (found, "Project folder check covered only the first \(budget.formatted()) files and folders per project folder and stopped early in \(cut.joined(separator: ", ")).")
    }

    static func contents(of directory: String) -> [(name: String, isDirectory: Bool)] {
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isSymbolicLinkKey]
        let urls = (try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: directory, isDirectory: true), includingPropertiesForKeys: Array(keys))) ?? []
        return urls.map { url in
            let values = try? url.resourceValues(forKeys: keys)
            return (url.lastPathComponent, values?.isDirectory == true && values?.isSymbolicLink != true)
        }
        .sorted { $0.name < $1.name }
    }
}
