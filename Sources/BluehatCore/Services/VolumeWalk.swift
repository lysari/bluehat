import Foundation

final class VolumeWalk {
    struct Entry {
        let name: String
        let path: String
        let status: stat

        var isDirectory: Bool {
            status.st_mode & S_IFMT == S_IFDIR
        }

        var isCloudOnly: Bool {
            status.st_flags & UInt32(SF_DATALESS) != 0
        }
    }

    struct Checks {
        let files: [(rule: Rule, regexes: [NSRegularExpression])]
        let packages: [(rule: Rule, listed: [String: [MaliciousPackage]])]
        let listedPackages: Set<String>

        init(rules: [Rule]) {
            files = Scanner.fileChecks(rules.filter { $0.check == .projectFile })
            packages = Scanner.packageChecks(rules.filter { $0.check == .npmPackage })
            listedPackages = Set(packages.flatMap(\.listed.keys))
        }
    }

    private struct DirectoryIdentity: Hashable {
        let device: dev_t
        let inode: ino_t

        init(_ status: stat) {
            device = status.st_dev
            inode = status.st_ino
        }
    }

    static let dataVolume = "/System/Volumes/Data"
    static let startupRoots = ["/", dataVolume]
    static let volumeMounts = "/System/Volumes"
    static let progressInterval = 5_000
    static let configFileSuffixes = [".config.js", ".config.json", ".config.ts", ".config.mjs", ".config.cjs", ".config.cts", ".config.mts"]
    static let jsonConfigSuffix = ".config.json"
    static let threadStackBytes = 1 << 22
    static let memoryCheckInterval = 1_024

    let roots: [String]
    let excludedFolders: [String]
    let excludedPatterns: [ExclusionPattern]
    let limits: ScanLimits
    let cancellation: ScanCancellation
    private let hasWholeDiskFolder: Bool
    private let ruleFileNames: Set<String>
    private let refusedRuleGlobs: [String]
    private let onItemsWalked: @Sendable (Int) -> Void
    private let memoryFootprint: @Sendable () -> Int?
    let notScanned: NotScannedCollector
    private(set) var foldersRead = 0
    private(set) var unreadableFolders = 0
    private(set) var packageFilesOpened = 0
    private(set) var wasStoppedAtMemoryLimit = false
    private var entriesSinceMemoryCheck = 0
    private var keptFindings: [Finding] = []
    private var leftOutFindings = 0
    private var leftOutRules = Set<String>()

    init(roots: [String], excludedFolders: [String] = [], excludedPatterns: [String] = [], ruleFiles: [String] = [], limits: ScanLimits = .defaults, cancellation: ScanCancellation = ScanCancellation(), notScanned: NotScannedCollector? = nil, memoryFootprint: @escaping @Sendable () -> Int? = ProcessMemory.footprintBytes, onItemsWalked: @escaping @Sendable (Int) -> Void = { _ in }) {
        let folders = excludedFolders.compactMap(Self.canonical)
        self.roots = roots.compactMap(Self.canonical)
        self.excludedFolders = folders.filter { $0 != "/" }
        self.excludedPatterns = excludedPatterns.compactMap { try? ExclusionPattern(parsing: $0).resolvingLinks() }
        self.limits = limits
        self.cancellation = cancellation
        self.notScanned = notScanned ?? NotScannedCollector(limits: limits)
        self.memoryFootprint = memoryFootprint
        self.onItemsWalked = onItemsWalked
        hasWholeDiskFolder = folders.contains("/")
        ruleFileNames = Set(ruleFiles.filter { !$0.contains("*") }.map { $0.lowercased() })
        let allowedGlobs = Set(Self.configFileSuffixes.map { "*" + $0 })
        refusedRuleGlobs = Set(ruleFiles.filter { $0.contains("*") && !allowedGlobs.contains($0.lowercased()) }).sorted()
    }

    static func canonical(_ path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        guard let resolved = realpath(path, nil) else { return withoutDataVolume(URL(fileURLWithPath: path).standardizedFileURL.path) }
        defer { free(resolved) }
        return withoutDataVolume(String(cString: resolved))
    }

    static func withoutDataVolume(_ path: String) -> String {
        path.hasPrefix(dataVolume + "/") ? String(path.dropFirst(dataVolume.count)) : path
    }

    func isExcluded(_ path: String) -> Bool {
        guard !isInExcludedFolder(path) else { return true }
        let components = ExclusionPattern.components(of: Self.withoutDataVolume(path + "/"))
        return excludedPatterns.contains { pattern in
            components.indices.contains { pattern.matches(components[...$0], isDirectory: true) }
        }
    }

    private func isInExcludedFolder(_ path: String) -> Bool {
        let path = Self.withoutDataVolume(path)
        return excludedFolders.contains { path == $0 || path.hasPrefix($0 + "/") }
    }

    private func isPatternMatch(_ name: String, isDirectory: Bool, parent: [[Character]]) -> Bool {
        guard !excludedPatterns.isEmpty else { return false }
        let components = parent + [ExclusionPattern.folded(name)]
        return excludedPatterns.contains { $0.matches(components[...], isDirectory: isDirectory) }
    }

    func isOffDisk(_ folder: Entry, devices: Set<dev_t>) -> Bool {
        folder.isCloudOnly || !devices.contains(folder.status.st_dev)
    }

    func noteUnreadableFolder(_ path: String, error: Int32) {
        guard let reason = NotScannedReason(folderError: error) else { return }
        unreadableFolders += 1
        notScanned.add(NotScannedEntry(reason: reason, path: path, limits: limits))
    }

    func noteOffDisk(_ folder: Entry) {
        guard folder.isCloudOnly, !isInExcludedFolder(folder.path) else { return }
        notScanned.add(NotScannedEntry(reason: .cloudOnly, path: folder.path, limits: limits))
    }

    var exclusionSummary: String? {
        let folders = excludedFolders.isEmpty ? nil : "folders \(Scanner.pathList(excludedFolders, limits: limits, namingAll: true))"
        let patterns = excludedPatterns.isEmpty ? nil : "patterns \(Scanner.pathList(excludedPatterns.map(\.text), limits: limits, namingAll: true))"
        let named = [folders, patterns].compactMap { $0 }
        guard !named.isEmpty else { return nil }
        let count = excludedFolders.count + excludedPatterns.count
        return "\(Self.counted(count, "exclude")) from Settings applied: \(named.joined(separator: "; "))."
    }

    var wholeDiskNotice: String? {
        hasWholeDiskFolder ? "Deep Scan ignored the excluded folder / saved in Settings, because it would skip the whole disk." : nil
    }

    func isPackageFile(_ name: String) -> Bool {
        let name = name.lowercased()
        return NpmInventory.projectFileNames.contains(name) || ruleFileNames.contains(name) || Self.configFileSuffixes.contains { name.hasSuffix($0) }
    }

    private var isStopping: Bool {
        wasStoppedAtMemoryLimit || cancellation.isCancelled
    }

    private func checkMemory() {
        entriesSinceMemoryCheck = 0
        if let footprint = memoryFootprint(), footprint >= limits[.maxDeepScanMemoryBytes] {
            wasStoppedAtMemoryLimit = true
        }
    }

    func walk(_ visit: (_ directory: String, _ file: Entry?) -> Void) {
        checkMemory()
        var visited = Set<DirectoryIdentity>()
        var walkedItems = 0
        let startupDevices = Set(Self.startupRoots.compactMap { Self.status(of: $0)?.st_dev })
        for root in roots where !isExcluded(root) {
            guard let status = Self.status(of: root), status.st_mode & S_IFMT == S_IFDIR, visited.insert(DirectoryIdentity(status)).inserted else { continue }
            let devices = startupDevices.contains(status.st_dev) ? startupDevices : [status.st_dev]
            var pending = [root]
            while !isStopping, let directory = pending.popLast() {
                visit(directory, nil)
                let items = list(directory) { entry in
                    guard entry.isDirectory else {
                        visit(directory, entry)
                        return
                    }
                    guard !isOffDisk(entry, devices: devices) else {
                        noteOffDisk(entry)
                        return
                    }
                    guard visited.insert(DirectoryIdentity(entry.status)).inserted, entry.path != Self.volumeMounts, !isInExcludedFolder(entry.path) else { return }
                    pending.append(entry.path)
                }
                if (walkedItems + items) / Self.progressInterval > walkedItems / Self.progressInterval {
                    onItemsWalked(walkedItems + items)
                }
                walkedItems += items
            }
        }
    }

    private func list(_ directory: String, _ visit: (Entry) -> Void) -> Int {
        guard let stream = opendir(directory) else {
            noteUnreadableFolder(directory, error: errno)
            return 0
        }
        defer { closedir(stream) }
        foldersRead += 1
        let parent = excludedPatterns.isEmpty ? [] : ExclusionPattern.components(of: Self.withoutDataVolume(directory + "/"))
        var items = 0
        while !isStopping, let item = readdir(stream) {
            let length = Int(item.pointee.d_namlen)
            let name = withUnsafeBytes(of: &item.pointee.d_name) { String(decoding: $0.prefix(length), as: UTF8.self) }
            guard name != ".", name != ".." else { continue }
            items += 1
            let type = Int32(item.pointee.d_type)
            guard type == DT_DIR || type == DT_UNKNOWN || isPackageFile(name) else { continue }
            let path = directory == "/" ? "/" + name : directory + "/" + name
            entriesSinceMemoryCheck += 1
            if entriesSinceMemoryCheck >= Self.memoryCheckInterval { checkMemory() }
            var status = stat()
            guard lstat(path, &status) == 0 else {
                let error = errno
                if type == DT_DIR, !isInExcludedFolder(path), !isPatternMatch(name, isDirectory: true, parent: parent) {
                    noteUnreadableFolder(path, error: error)
                }
                continue
            }
            let entry = Entry(name: name, path: path, status: status)
            guard entry.isDirectory || isPackageFile(name), !isPatternMatch(name, isDirectory: entry.isDirectory, parent: parent) else { continue }
            visit(entry)
        }
        return items
    }

    func packageFileFindings(rules: [Rule], reported: Set<String>) -> (findings: [Finding], notices: [String]) {
        let checks = Checks(rules: rules)
        guard !checks.files.isEmpty || !checks.packages.isEmpty else { return ([], []) }
        walk { directory, file in
            guard let file else { return }
            autoreleasepool {
                for finding in findings(in: file, directory: directory, checks: checks) where !reported.contains(finding.fingerprint) {
                    keep(finding)
                }
            }
            checkMemory()
        }
        for glob in refusedRuleGlobs {
            notScanned.add(NotScannedEntry(reason: .filePatternNotOpened, summary: glob, explanation: "Deep Scan doesn't open this file pattern from the rules across the disk. The normal scan still checks it in your project folders.", limits: limits))
        }
        if wasStoppedAtMemoryLimit {
            notScanned.add(NotScannedEntry(reason: .memoryLimit, summary: "The rest of the startup disk", explanation: "Deep Scan stopped at its \(memoryLimitText) memory limit after reading \(Self.counted(foldersRead, "folder")), so this wasn't checked", limits: limits))
        }
        notScanned.record(NotScannedList.Coverage(foldersRead: foldersRead, packageFilesOpened: packageFilesOpened, unreadableFolders: unreadableFolders, exclusionSummary: exclusionSummary, wasStoppedAtMemoryLimit: wasStoppedAtMemoryLimit))
        return (keptFindings, [memoryLimitNotice, wholeDiskNotice, leftOutNotice].compactMap { $0 })
    }

    func findings(in file: Entry, directory: String, checks: Checks) -> [Finding] {
        let name = file.name.lowercased()
        let isManifest = name == NpmInventory.manifestName
        let isLockfile = !isManifest && NpmInventory.projectFileNames.contains(name)
        let readsPackages = !checks.packages.isEmpty && (isLockfile || (isManifest && directory.contains("/\(NpmInventory.moduleFolderName)/")))
        let matchedNames = name.hasSuffix(Self.jsonConfigSuffix) ? [name, String(name.dropLast(2))] : [name]
        let fileChecks = checks.files.filter { check in
            (check.rule.files ?? []).contains { glob in matchedNames.contains { Scanner.fileName($0, matches: glob) } }
        }
        guard readsPackages || !fileChecks.isEmpty else { return [] }
        guard !file.isCloudOnly else {
            notScanned.add(NotScannedEntry(reason: .cloudOnly, path: file.path, limits: limits))
            return []
        }
        let maxBytes = limits[isLockfile ? .maxLockfileBytes : isManifest ? .maxManifestBytes : .maxReadBytes]
        guard Int(file.status.st_size) <= maxBytes else {
            notScanned.add(.oversized(path: file.path, size: Int(file.status.st_size), limit: maxBytes, limits: limits))
            return []
        }
        guard let data = RegularFile.read(atPath: file.path, maxBytes: maxBytes, followingSymlinks: false) else {
            if file.status.st_mode & S_IFMT == S_IFREG {
                notScanned.add(NotScannedEntry(reason: access(file.path, R_OK) == 0 ? .couldNotRead : .noPermission, path: file.path, limits: limits))
            }
            return []
        }
        packageFilesOpened += 1
        let found = Scanner.fileFindings(checks: fileChecks, data: data, path: file.path, limits: limits)
        guard readsPackages else { return found }
        let fields: [(name: String, version: String)]
        do {
            fields = isManifest ? [try NpmInventory.manifestFields(of: data)].compactMap { $0 } : try NpmInventory.lockfilePackages(named: name, data, limits: limits)
        } catch {
            notScanned.add(.notParsed(path: file.path, check: NpmInventory.packageCheckName, problem: error, limits: limits))
            return found
        }
        let installed = fields.filter { checks.listedPackages.contains($0.name) }.compactMap { InstalledPackage(name: $0.name, version: $0.version, path: isManifest ? directory : file.path) }
        let packages = Set(installed).sorted { ($0.name, $0.version) < ($1.name, $1.version) }
        return found + Scanner.packageFindings(checks: checks.packages, packages: packages, limits: limits)
    }

    private func keep(_ finding: Finding) {
        guard keptFindings.count >= limits[.maxFindings] else {
            keptFindings.append(finding)
            return
        }
        var left = finding
        if let weakest = keptFindings.indices.min(by: { keptFindings[$0].rule.severity < keptFindings[$1].rule.severity }), keptFindings[weakest].rule.severity < finding.rule.severity {
            left = keptFindings[weakest]
            keptFindings[weakest] = finding
        }
        leftOutFindings += 1
        leftOutRules.insert(left.rule.id)
    }

    private static func counted(_ count: Int, _ noun: String) -> String {
        "\(count.formatted()) \(noun)\(count == 1 ? "" : "s")"
    }

    private var leftOutNotice: String? {
        leftOutFindings == 0 ? nil : "Deep Scan kept the \(limits[.maxFindings].formatted()) most severe matches on the disk and left out \(leftOutFindings.formatted()) more, from \(Scanner.pathList(Array(leftOutRules), limits: limits))."
    }

    private var memoryLimitText: String {
        ScanLimit.maxDeepScanMemoryBytes.text(for: limits[.maxDeepScanMemoryBytes])
    }

    private var memoryLimitNotice: String? {
        wasStoppedAtMemoryLimit ? "Deep Scan stopped at its \(memoryLimitText) memory limit after reading \(Self.counted(foldersRead, "folder")), so the rest of the disk wasn't checked. To check more, raise Deep Scan memory limit in Settings › Limits or exclude large folders in Settings › General, then scan again." : nil
    }

    private static func status(of path: String) -> stat? {
        var status = stat()
        return stat(path, &status) == 0 ? status : nil
    }
}
