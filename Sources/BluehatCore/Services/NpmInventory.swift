import Foundation

enum NpmInventory {
    static let manifestName = "package.json"
    static let packageLockNames = ["package-lock.json", "npm-shrinkwrap.json"]
    static let moduleFolderName = "node_modules"
    static let yarnLockName = "yarn.lock"
    static let pnpmLockName = "pnpm-lock.yaml"
    static let projectFileNames = Set([manifestName, yarnLockName, pnpmLockName] + packageLockNames)
    static let globalModuleDirectories = ["/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"]
    static let installModuleSubpaths = ["lib/node_modules", "installation/lib/node_modules"]
    static let packageCheckName = "npm package check"

    static func packages(inProjects projects: [(path: String, files: Set<String>)], moduleDirectories: [String], limits: ScanLimits = .defaults) -> (packages: [InstalledPackage], notScanned: [NotScannedEntry]) {
        let maxLockfileBytes = limits[.maxLockfileBytes]
        let globalBudget = limits[.maxGlobalPackages]
        var installed = Set<InstalledPackage>()
        var notScanned: [NotScannedEntry] = []
        for project in projects where project.files.contains(manifestName) {
            for name in project.files.intersection(projectFileNames).subtracting([manifestName]).sorted() {
                let path = "\(project.path)/\(name)"
                guard let data = RegularFile.read(atPath: path, maxBytes: maxLockfileBytes, followingSymlinks: false) else {
                    if let size = RegularFile.open(atPath: path, followingSymlinks: false)?.size, size > maxLockfileBytes {
                        notScanned.append(.oversized(path: path, size: size, limit: maxLockfileBytes, limits: limits))
                    }
                    continue
                }
                do {
                    installed.formUnion(try autoreleasepool { try lockfilePackages(named: name, data, limits: limits).compactMap { InstalledPackage(name: $0.name, version: $0.version, path: path) } })
                } catch {
                    notScanned.append(.notParsed(path: path, check: packageCheckName, problem: error, limits: limits))
                }
            }
        }
        var budget = globalBudget
        for directory in ProjectFolders.uniqueDirectories(moduleDirectories) {
            installed.formUnion(modulePackages(in: directory, depth: 0, budget: &budget, notScanned: &notScanned, limits: limits))
            if budget < 0 {
                notScanned.append(NotScannedEntry(reason: .overCountLimit, path: directory, explanation: "npm package check covered only the first \(globalBudget.formatted()) global packages and skipped the rest here", limits: limits))
            }
        }
        let sorted = installed.sorted { ($0.path, $0.name, $0.version) < ($1.path, $1.name, $1.version) }
        return (sorted, notScanned)
    }

    static func moduleDirectories(for installs: [Installation]) -> [String] {
        installs.filter { $0.product == .node }.flatMap { install in installModuleSubpaths.map { "\(install.path)/\($0)" } } + globalModuleDirectories
    }

    static func lockfilePackages(named name: String, _ data: Data, limits: ScanLimits = .defaults) throws -> [(name: String, version: String)] {
        switch name {
        case yarnLockName: yarnLockPackages(String(decoding: data, as: UTF8.self))
        case pnpmLockName: pnpmLockPackages(String(decoding: data, as: UTF8.self))
        default: try packageLockPackages(data, limits: limits)
        }
    }

    static func packageLockPackages(_ data: Data, limits: ScanLimits = .defaults) throws -> [(name: String, version: String)] {
        guard let lockfile = try JSONFile.object(from: data) else { return [] }
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
        return dependencyPackages(lockfile["dependencies"] as? [String: Any] ?? [:], depth: 0, limits: limits)
    }

    static func dependencyPackages(_ dependencies: [String: Any], depth: Int, limits: ScanLimits = .defaults) -> [(name: String, version: String)] {
        guard depth < limits[.maxDependencyDepth] else { return [] }
        return dependencies.flatMap { name, value -> [(name: String, version: String)] in
            guard let entry = value as? [String: Any] else { return [] }
            let own = (entry["version"] as? String).flatMap { specifier("\(name)@\($0)"[...]) }
            return [own].compactMap { $0 } + dependencyPackages(entry["dependencies"] as? [String: Any] ?? [:], depth: depth + 1, limits: limits)
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

    static func modulePackages(in directory: String, depth: Int, budget: inout Int, notScanned: inout [NotScannedEntry], limits: ScanLimits = .defaults) -> [InstalledPackage] {
        var packages: [InstalledPackage] = []
        for entry in ProjectFolders.contents(of: directory) where entry.isDirectory && !entry.name.hasPrefix(".") {
            let path = "\(directory)/\(entry.name)"
            let folders = entry.name.hasPrefix("@") ? ProjectFolders.contents(of: path).filter(\.isDirectory).map { "\(path)/\($0.name)" } : [path]
            for folder in folders {
                budget -= 1
                guard budget >= 0 else { return packages }
                do {
                    if let package = try manifestPackage(in: folder, limits: limits) {
                        packages.append(package)
                    }
                } catch {
                    notScanned.append(.notParsed(path: "\(folder)/\(manifestName)", check: packageCheckName, problem: error, limits: limits))
                }
                if depth < limits[.maxModuleDepth] {
                    packages += modulePackages(in: "\(folder)/\(moduleFolderName)", depth: depth + 1, budget: &budget, notScanned: &notScanned, limits: limits)
                }
            }
        }
        return packages
    }

    static func manifestPackage(in folder: String, limits: ScanLimits = .defaults) throws -> InstalledPackage? {
        try autoreleasepool {
            guard
                let data = RegularFile.read(atPath: "\(folder)/\(manifestName)", maxBytes: limits[.maxManifestBytes], followingSymlinks: false),
                let manifest = try manifestFields(of: data)
            else { return nil }
            return InstalledPackage(name: manifest.name, version: manifest.version, path: folder)
        }
    }

    static func manifestFields(of data: Data) throws -> (name: String, version: String)? {
        guard
            let manifest = try JSONFile.object(from: data),
            let name = manifest["name"] as? String, let version = manifest["version"] as? String
        else { return nil }
        return (name, version)
    }
}
