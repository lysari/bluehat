import Foundation

enum NpmInventory {
    static let manifestName = "package.json"
    static let packageLockNames = ["package-lock.json", "npm-shrinkwrap.json"]
    static let yarnLockName = "yarn.lock"
    static let pnpmLockName = "pnpm-lock.yaml"
    static let projectFileNames = Set([manifestName, yarnLockName, pnpmLockName] + packageLockNames)
    static let globalModuleDirectories = ["/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"]
    static let installModuleSubpaths = ["lib/node_modules", "installation/lib/node_modules"]
    static let maxLockfileBytes = 30_000_000
    static let maxManifestBytes = 1_000_000
    static let maxDependencyDepth = 32
    static let maxModuleDepth = 8
    static let maxGlobalPackages = 20_000

    static func packages(inProjects projects: [(path: String, files: Set<String>)], moduleDirectories: [String], globalBudget: Int = maxGlobalPackages) -> (packages: [InstalledPackage], notice: String?) {
        var installed = Set<InstalledPackage>()
        var oversized: [String] = []
        for project in projects where project.files.contains(manifestName) {
            for name in project.files.intersection(projectFileNames).subtracting([manifestName]).sorted() {
                let path = "\(project.path)/\(name)"
                guard let data = RegularFile.read(atPath: path, maxBytes: maxLockfileBytes, followingSymlinks: false) else {
                    if (RegularFile.open(atPath: path, followingSymlinks: false)?.size ?? 0) > maxLockfileBytes {
                        oversized.append(NSString(string: path).abbreviatingWithTildeInPath)
                    }
                    continue
                }
                installed.formUnion(lockfilePackages(named: name, data).compactMap { InstalledPackage(name: $0.name, version: $0.version, path: path) })
            }
        }
        var budget = globalBudget
        var cut: [String] = []
        for directory in ProjectFolders.uniqueDirectories(moduleDirectories) {
            installed.formUnion(modulePackages(in: directory, depth: 0, budget: &budget))
            if budget < 0 { cut.append(NSString(string: directory).abbreviatingWithTildeInPath) }
        }
        let notices = [
            oversized.isEmpty ? nil : "npm package check skipped lockfiles over \(Int64(maxLockfileBytes).formatted(.byteCount(style: .decimal))): \(oversized.joined(separator: ", ")).",
            cut.isEmpty ? nil : "npm package check covered only the first \(globalBudget.formatted()) global packages and skipped the rest of \(cut.joined(separator: ", ")).",
        ].compactMap { $0 }
        let sorted = installed.sorted { ($0.path, $0.name, $0.version) < ($1.path, $1.name, $1.version) }
        return (sorted, notices.isEmpty ? nil : notices.joined(separator: " "))
    }

    static func moduleDirectories(for installs: [Installation]) -> [String] {
        installs.filter { $0.product == .node }.flatMap { install in installModuleSubpaths.map { "\(install.path)/\($0)" } } + globalModuleDirectories
    }

    static func lockfilePackages(named name: String, _ data: Data) -> [(name: String, version: String)] {
        switch name {
        case yarnLockName: yarnLockPackages(String(decoding: data, as: UTF8.self))
        case pnpmLockName: pnpmLockPackages(String(decoding: data, as: UTF8.self))
        default: packageLockPackages(data)
        }
    }

    static func packageLockPackages(_ data: Data) -> [(name: String, version: String)] {
        guard let lockfile = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [] }
        if let packages = lockfile["packages"] as? [String: Any] {
            return packages.compactMap { key, value in
                guard
                    let entry = value as? [String: Any], entry["link"] as? Bool != true,
                    let folder = key.range(of: "node_modules/", options: .backwards),
                    let version = entry["version"] as? String
                else { return nil }
                return (entry["name"] as? String ?? String(key[folder.upperBound...]), version)
            }
        }
        return dependencyPackages(lockfile["dependencies"] as? [String: Any] ?? [:], depth: 0)
    }

    static func dependencyPackages(_ dependencies: [String: Any], depth: Int) -> [(name: String, version: String)] {
        guard depth < maxDependencyDepth else { return [] }
        return dependencies.flatMap { name, value -> [(name: String, version: String)] in
            guard let entry = value as? [String: Any] else { return [] }
            let own = (entry["version"] as? String).flatMap { specifier("\(name)@\($0)"[...]) }
            return [own].compactMap { $0 } + dependencyPackages(entry["dependencies"] as? [String: Any] ?? [:], depth: depth + 1)
        }
    }

    static func yarnLockPackages(_ text: String) -> [(name: String, version: String)] {
        var packages: [(name: String, version: String)] = []
        var isInEntry = false
        var name: String?
        var version: String?
        var resolution: String?
        func finishEntry() {
            if let resolution {
                if let resolved = resolution.firstRange(of: "@npm:"), resolved.lowerBound > resolution.startIndex {
                    packages.append((String(resolution[..<resolved.lowerBound]), String(resolution[resolved.upperBound...])))
                }
            } else if let name, let version {
                packages.append((name, version))
            }
            (isInEntry, name, version, resolution) = (false, nil, nil, nil)
        }
        for line in text.split(whereSeparator: \.isNewline) {
            if !line.hasPrefix(" ") {
                finishEntry()
                guard line.hasSuffix(":"), !line.hasPrefix("#") else { continue }
                let first = line.dropLast().split(separator: ",").first?.filter { $0 != "\"" } ?? ""
                isInEntry = true
                name = specifier(first.trimmingCharacters(in: .whitespaces)[...])?.name
            } else if isInEntry, line.hasPrefix("  "), !line.hasPrefix("   ") {
                let field = line.dropFirst(2)
                if let value = yarnValue(field, key: "version") { version = value }
                if let value = yarnValue(field, key: "resolution") { resolution = value }
            }
        }
        finishEntry()
        return packages
    }

    static func yarnValue(_ field: Substring, key: String) -> String? {
        guard field.hasPrefix(key + " ") || field.hasPrefix(key + ":") else { return nil }
        return field.dropFirst(key.count + 1).trimmingCharacters(in: CharacterSet(charactersIn: "\"' ").union(.whitespaces))
    }

    static func pnpmLockPackages(_ text: String) -> [(name: String, version: String)] {
        var isInPackages = false
        var packages: [(name: String, version: String)] = []
        for line in text.split(whereSeparator: \.isNewline) {
            if !line.hasPrefix(" ") {
                isInPackages = line == "packages:" || line == "snapshots:"
                continue
            }
            guard isInPackages, line.hasPrefix("  "), !line.hasPrefix("   "), line.hasSuffix(":") else { continue }
            var key = line.dropFirst(2).dropLast().filter { $0 != "'" && $0 != "\"" }[...]
            if key.hasPrefix("/") { key = key.dropFirst() }
            if let peers = key.firstIndex(of: "(") { key = key[..<peers] }
            if let package = specifier(key) { packages.append(package) }
        }
        return packages
    }

    static func specifier(_ text: Substring) -> (name: String, version: String)? {
        func split(_ text: Substring) -> (name: String, version: Substring)? {
            guard let at = text.dropFirst().firstIndex(of: "@") else { return nil }
            return (String(text[..<at]), text[text.index(after: at)...])
        }
        guard let parts = split(text) else { return nil }
        guard parts.version.hasPrefix("npm:") else { return (parts.name, String(parts.version)) }
        return split(parts.version.dropFirst(4)).map { ($0.name, String($0.version)) }
    }

    static func modulePackages(in directory: String, depth: Int, budget: inout Int) -> [InstalledPackage] {
        var packages: [InstalledPackage] = []
        for entry in ProjectFolders.contents(of: directory) where entry.isDirectory && !entry.name.hasPrefix(".") {
            let path = "\(directory)/\(entry.name)"
            let folders = entry.name.hasPrefix("@") ? ProjectFolders.contents(of: path).filter(\.isDirectory).map { "\(path)/\($0.name)" } : [path]
            for folder in folders {
                budget -= 1
                guard budget >= 0 else { return packages }
                if
                    let data = RegularFile.read(atPath: "\(folder)/\(manifestName)", maxBytes: maxManifestBytes, followingSymlinks: false),
                    let manifest = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                    let name = manifest["name"] as? String, let version = manifest["version"] as? String,
                    let package = InstalledPackage(name: name, version: version, path: folder)
                {
                    packages.append(package)
                }
                if depth < maxModuleDepth {
                    packages += modulePackages(in: "\(folder)/node_modules", depth: depth + 1, budget: &budget)
                }
            }
        }
        return packages
    }
}
