import CryptoKit
import Foundation
import Network
import Security
import Synchronization

public struct Scanner: Sendable {
    static let launchItemDirectories = ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    static let shellProfileFiles = ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin", "~/.bashrc", "~/.bash_profile", "~/.profile"]
    static let hashedDirectories = ["~/Downloads", "~/Desktop", "/Users/Shared", "/private/tmp"]
    static let appDirectories = ["/Applications", "~/Applications", "~/Downloads"]
    static let authorizedKeyFiles = ["~/.ssh/authorized_keys", "~/.ssh/authorized_keys2"]
    static let sshKeyTypePrefixes = ["ssh-", "ecdsa-", "sk-"]
    static let chromiumBrowsers = [
        ("Chrome", "~/Library/Application Support/Google/Chrome"),
        ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Edge", "~/Library/Application Support/Microsoft Edge"),
        ("Arc", "~/Library/Application Support/Arc/User Data"),
        ("Chromium", "~/Library/Application Support/Chromium"),
        ("Vivaldi", "~/Library/Application Support/Vivaldi"),
    ]
    static let firefoxProfiles = "~/Library/Application Support/Firefox/Profiles"
    static let homebrewCellars = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
    static let versionDirectories: [(product: SoftwareProduct, manager: InstallManager, directory: String)] = [
        (.node, .nvm, "~/.nvm/versions/node"),
        (.node, .volta, "~/.volta/tools/image/node"),
        (.node, .fnm, "~/Library/Application Support/fnm/node-versions"),
        (.node, .fnm, "~/.local/share/fnm/node-versions"),
        (.node, .asdf, "~/.asdf/installs/nodejs"),
        (.node, .mise, "~/.local/share/mise/installs/node"),
        (.python, .pyenv, "~/.pyenv/versions"),
        (.python, .asdf, "~/.asdf/installs/python"),
        (.python, .mise, "~/.local/share/mise/installs/python"),
        (.ruby, .rbenv, "~/.rbenv/versions"),
        (.ruby, .asdf, "~/.asdf/installs/ruby"),
        (.ruby, .mise, "~/.local/share/mise/installs/ruby"),
        (.php, .asdf, "~/.asdf/installs/php"),
        (.php, .mise, "~/.local/share/mise/installs/php"),
    ]
    static let pythonFrameworkVersions = "/Library/Frameworks/Python.framework/Versions"
    static let nodeInstallerPrefix = "/usr/local"
    static let xprotectBundles = ["/Library/Apple/System/Library/CoreServices/XProtect.bundle", "/private/var/protected/xprotect/XProtect.bundle"]
    static let appleBundlePrefix = "com.apple."
    static let firefoxSignedState = 2
    static let adHocSignatureFlag: UInt32 = 0x2
    static let developerIDRequirement = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]"
    static let notarizedRequirement = "notarized"
    static let unfinishedSignatureProblem = "couldn't be checked because reading it never finished"
    static let signatureValidationFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures).union(.noNetworkAccess)
    static let unparsedLaunchItemExplanation = "Couldn't be parsed as a launch item, so Launch items and Launch signing skipped it"
    static let hashChunkBytes = 1 << 20
    static let localePattern = "^[A-Za-z0-9_-]{1,16}$"
    static let extensionCheckName = "Browser extension check"

    let projectFolders: [String]
    let kind: ScanKind
    let excludedFolders: [String]
    let excludedPatterns: [String]
    let limits: ScanLimits
    let cancellation: ScanCancellation
    let walkRoots: [String]
    let memoryFootprint: @Sendable () -> Int?

    public init(projectFolders: [String] = [], kind: ScanKind = .normal, excludedFolders: [String] = [], excludedPatterns: [String] = [], limits: ScanLimits = .defaults, cancellation: ScanCancellation = ScanCancellation()) {
        self.init(projectFolders: projectFolders, kind: kind, excludedFolders: excludedFolders, excludedPatterns: excludedPatterns, limits: limits, cancellation: cancellation, walkRoots: VolumeWalk.startupRoots)
    }

    init(projectFolders: [String] = [], kind: ScanKind = .normal, excludedFolders: [String] = [], excludedPatterns: [String] = [], limits: ScanLimits = .defaults, cancellation: ScanCancellation = ScanCancellation(), walkRoots: [String], memoryFootprint: @escaping @Sendable () -> Int? = ProcessMemory.footprintBytes) {
        self.projectFolders = projectFolders
        self.kind = kind
        self.excludedFolders = excludedFolders
        self.excludedPatterns = excludedPatterns
        self.limits = limits
        self.cancellation = cancellation
        self.walkRoots = walkRoots
        self.memoryFootprint = memoryFootprint
    }

    var signatureChecks: SignatureChecks {
        SignatureChecks(limits: limits, cancellation: cancellation)
    }

    public func scan(_ rulebook: Rulebook, onAreaFinished: @Sendable (CheckKind, [Finding]) -> Void = { _, _ in }, onItemsWalked: @escaping @Sendable (Int) -> Void = { _ in }) -> (findings: [Finding], notices: [String], notScanned: NotScannedList, walkFindingIDs: Set<Finding.ID>) {
        var findings: [Finding] = []
        var walkFindingIDs = Set<Finding.ID>()
        var notices = [limits.changedNotice].compactMap { $0 }
        let notScanned = NotScannedCollector(limits: limits)
        var projects: [(path: String, files: Set<String>)]?
        let signatureChecks = signatureChecks
        for area in rulebook.areas where !cancellation.isCancelled {
            autoreleasepool {
                let rules = rulebook.rules.filter { $0.check == area }
                if projects == nil, [.npmPackage, .projectFile].contains(area) {
                    let walk = ProjectFolders.directories(in: projectFolders, containing: NpmInventory.projectFileNames, limits: limits)
                    projects = walk.directories
                    notScanned.add(contentsOf: walk.notScanned)
                }
                let areaFindings = Self.withoutFeedFileDuplicates(Self.findings(in: area, rules: rules, projects: projects ?? [], signatureChecks: signatureChecks, limits: limits, notices: &notices, notScanned: notScanned), reported: findings)
                findings += areaFindings
                onAreaFinished(area, areaFindings)
            }
        }
        notScanned.add(contentsOf: signatureChecks.notScannedEntries(limits: limits))
        if kind == .deep, !cancellation.isCancelled {
            let walked = walkDisk(rules: rulebook.rules, reported: Set(findings.map(\.fingerprint)), notScanned: notScanned, onItemsWalked: onItemsWalked)
            findings += walked.findings
            notices += walked.notices
            walkFindingIDs = Set(walked.findings.map(\.id))
        }
        return (findings.sorted { $0.rule.severity > $1.rule.severity }, notices, notScanned.finished(), walkFindingIDs)
    }

    func walkDisk(rules: [Rule], reported: Set<String>, notScanned: NotScannedCollector, onItemsWalked: @escaping @Sendable (Int) -> Void) -> (findings: [Finding], notices: [String]) {
        let finished = DispatchSemaphore(value: 0)
        let outcome = Mutex<(findings: [Finding], notices: [String])>(([], []))
        let thread = Thread {
            setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
            let walk = VolumeWalk(roots: walkRoots, excludedFolders: excludedFolders, excludedPatterns: excludedPatterns, ruleFiles: rules.filter { $0.check == .projectFile }.flatMap { $0.files ?? [] }, limits: limits, cancellation: cancellation, notScanned: notScanned, memoryFootprint: memoryFootprint, onItemsWalked: onItemsWalked)
            let walked = walk.packageFileFindings(rules: rules, reported: reported)
            outcome.withLock { $0 = walked }
            finished.signal()
        }
        thread.qualityOfService = .background
        thread.stackSize = VolumeWalk.threadStackBytes
        thread.start()
        finished.wait()
        return outcome.withLock { $0 }
    }

    static func findings(in area: CheckKind, rules: [Rule], projects: [(path: String, files: Set<String>)], signatureChecks: SignatureChecks = SignatureChecks(), limits: ScanLimits = .defaults, notices: inout [String], notScanned: NotScannedCollector = NotScannedCollector()) -> [Finding] {
        switch area {
        case .path:
            return rules.flatMap { rule in
                (rule.paths ?? []).map(expand).filter(FileManager.default.fileExists).map {
                    Finding(rule: rule, detail: $0, path: $0, limits: limits)
                }
            }
        case .launchItem:
            let launchItems = launchItemCommands(in: launchItemDirectories.map(expand), limits: limits)
            let checked = launchItemFindings(rules, items: launchItems.items, limits: limits)
            notScanned.add(contentsOf: launchItems.notScanned + checked.notScanned)
            return checked.findings
        case .shellProfile:
            let checked = shellProfileFindings(rules, files: shellProfileFiles.map(expand), limits: limits)
            notScanned.add(contentsOf: checked.notScanned)
            return checked.findings
        case .process:
            return matchingLines(lines(of: runTool("/bin/ps", ["-axww", "-o", "command="], limits: limits, notScanned: notScanned)), rules: rules, limits: limits)
        case .crontab:
            let checked = crontabFindings(rules, lines: lines(of: runTool("/usr/bin/crontab", ["-l"], limits: limits, notScanned: notScanned)), limits: limits)
            notScanned.add(contentsOf: checked.notScanned)
            return checked.findings
        case .listeningPort:
            let listeners = listeningPorts(limits: limits, notScanned: notScanned)
            return rules.flatMap { rule in
                (rule.ports ?? []).sorted().compactMap { port in
                    listeners[port].map { Finding(rule: rule, detail: "Port \(port) open by \($0)", path: nil, limits: limits) }
                }
            }
        case .fileHash:
            let hashed = hashedFiles(in: hashedDirectories.map(expand), limits: limits, cancellation: signatureChecks.cancellation)
            notScanned.add(contentsOf: hashed.notScanned)
            return rules.flatMap { rule in
                let hashes = Set(rule.hashes ?? [])
                return hashed.hashes.filter { hashes.contains($0.value) }.keys.sorted().map {
                    Finding(rule: rule, detail: $0, path: $0, limits: limits)
                }
            }
        case .setting:
            return rules.compactMap { rule in
                rule.setting.flatMap { settingProblem($0, limits: limits, notScanned: notScanned) }.map { Finding(rule: rule, detail: $0, path: nil, limits: limits) }
            }
        case .launchItemSignature:
            let launchItems = launchItemCommands(in: launchItemDirectories.map(expand), limits: limits)
            notScanned.add(contentsOf: launchItems.notScanned)
            return launchItemSignatureFindings(rules, items: launchItems.items, checks: signatureChecks, limits: limits)
        case .sshKey:
            let checked = sshKeyFindings(rules, files: authorizedKeyFiles.map(expand), limits: limits)
            notScanned.add(contentsOf: checked.notScanned)
            return checked.findings
        case .profile:
            let installed = profiles(fromProfilesOutput: runTool("/usr/bin/profiles", ["show", "-type", "configuration"], limits: limits, notScanned: notScanned))
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return installed.filter { profile in
                    rule.patterns == nil || profile.payloadTypes.contains { matches(regexes, $0, limits: limits) }
                }
                .map { Finding(rule: rule, detail: "\($0.name) (\($0.identifier)) · payloads: \($0.payloadTypes.joined(separator: ", "))", path: nil, limits: limits) }
            }
        case .browserExtension:
            let chromium = chromiumBrowsers.map { chromiumExtensions(browser: $0.0, root: expand($0.1), limits: limits) }
            let firefox = firefoxExtensions(profilesRoot: expand(firefoxProfiles), limits: limits)
            let extensions = chromium.flatMap(\.extensions) + firefox.extensions
            notScanned.add(contentsOf: chromium.flatMap(\.notScanned) + firefox.notScanned)
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return extensions.filter { matches(regexes, $0.descriptor, limits: limits) }.map {
                    Finding(rule: rule, detail: $0.detail, path: $0.path, limits: limits)
                }
            }
        case .appSignature:
            return appSignatureFindings(rules, apps: installedApps(), checks: signatureChecks, limits: limits)
        case .softwareVersion:
            return versionFindings(rules, installs: installedSoftware(limits: limits), limits: limits)
        case .npmPackage:
            let inventory = NpmInventory.packages(inProjects: projects, moduleDirectories: NpmInventory.moduleDirectories(for: installedSoftware(limits: limits)), limits: limits)
            notScanned.add(contentsOf: inventory.notScanned)
            return packageFindings(rules, packages: inventory.packages, limits: limits)
        case .projectFile:
            let checked = projectFileFindings(rules, projects: projects, limits: limits)
            notScanned.add(contentsOf: checked.notScanned)
            return checked.findings
        case .systemExtension:
            let extensions = systemExtensions(fromSystemExtensionsctlOutput: runTool("/usr/bin/systemextensionsctl", ["list"], limits: limits, notScanned: notScanned))
                + kernelExtensions(fromKmutilOutput: runTool("/usr/bin/kmutil", ["showloaded", "--list-only"], limits: limits, notScanned: notScanned))
            return systemExtensionFindings(rules, extensions: extensions, limits: limits)
        case .xprotect:
            let versions = xprotectBundles.compactMap { bundle in
                RegularFile.read(atPath: "\(bundle)/Contents/Info.plist", maxBytes: limits[.maxReadBytes], followingSymlinks: false).flatMap(xprotectVersion(fromInfoPlist:))
            }
            return xprotectFindings(rules, version: versions.max(), limits: limits)
        case .outbound:
            let connections = connections(fromNetstatOutput: runTool("/usr/sbin/netstat", ["-anlv", "-p", "tcp"], limits: limits, notScanned: notScanned))
                + connections(fromNetstatOutput: runTool("/usr/sbin/netstat", ["-anlv", "-p", "udp"], limits: limits, notScanned: notScanned))
            return outboundFindings(rules, connections: connections, limits: limits)
        case .notarization:
            var cache = NotarizationCache(limits: limits)
            let installed = installedApps()
            guard !signatureChecks.cancellation.isCancelled else { return [] }
            let candidates = installed.compactMap { developerIDApp(at: $0, checks: signatureChecks) }
            let unchecked = signatureChecks.stuckPaths.union(signatureChecks.skippedPaths)
            let checked = notarizationFindings(rules, apps: candidates, unchecked: unchecked, cache: &cache, limits: limits) { path in
                guard !signatureChecks.cancellation.isCancelled, isNetworkAvailable(limits: limits) else { return nil }
                return notarizationVerdict(fromSpctlOutput: runTool("/usr/sbin/spctl", ["--assess", "--type", "execute", "-v", path], includingErrorOutput: true, timeout: TimeInterval(limits[.notarizationTimeout]), limits: limits), path: path)
            }
            notScanned.add(contentsOf: checked.notScanned)
            do {
                try cache.save()
            } catch {
                notices.append("Couldn't save the notarization cache: \(error.localizedDescription)")
            }
            return checked.findings
        case .nodeInstall:
            let checked = nodeInstallFindings(rules, moduleDirectories: NpmInventory.moduleDirectories(for: installedSoftware(limits: limits)), limits: limits)
            notScanned.add(contentsOf: checked.notScanned)
            return checked.findings
        }
    }

    static func launchItemSignatureFindings(_ rules: [Rule], items: [(path: String, program: String?, command: String)], checks: SignatureChecks, limits: ScanLimits = .defaults) -> [Finding] {
        let items = items.compactMap { item -> (path: String, program: String)? in
            guard let program = item.program, program.hasPrefix("/"), FileManager.default.fileExists(atPath: program) else { return nil }
            return (item.path, program)
        }
        let problems = Set(items.map(\.program)).reduce(into: [String: String]()) { problems, program in
            problems[program] = signatureProblem(at: URL(fileURLWithPath: program), checks: checks)
        }
        return rules.flatMap { rule in
            items.compactMap { item in
                problems[item.program].map { Finding(rule: rule, detail: "\(item.program) \($0)", path: item.path, limits: limits) }
            }
        }
    }

    static func appSignatureFindings(_ rules: [Rule], apps: [URL], checks: SignatureChecks, limits: ScanLimits = .defaults) -> [Finding] {
        let problems = Mutex<[(path: String, problem: String)]>([])
        DispatchQueue.concurrentPerform(iterations: apps.count) { index in
            if let problem = signatureProblem(at: apps[index], checks: checks) {
                problems.withLock { $0.append((apps[index].path, problem)) }
            }
        }
        let sorted = problems.withLock { $0 }.sorted { $0.path < $1.path }
        return rules.flatMap { rule in
            sorted.map { Finding(rule: rule, detail: "\(URL(fileURLWithPath: $0.path).lastPathComponent) \($0.problem)", path: $0.path, limits: limits) }
        }
    }

    static func developerIDApp(at url: URL, checks: SignatureChecks = SignatureChecks()) -> (path: String, team: String, cdhash: String, isNotarized: Bool)? {
        guard case .finished(let app) = checks.inspect(url, { developerIDDetails(of: $0, at: url) }) else { return nil }
        return app
    }

    static func developerIDDetails(of staticCode: SecStaticCode, at url: URL) -> (path: String, team: String, cdhash: String, isNotarized: Bool)? {
        var developerID: SecRequirement?
        var notarized: SecRequirement?
        let offline = SecCSFlags(rawValue: kSecCSBasicValidateOnly).union(.noNetworkAccess)
        guard
            SecRequirementCreateWithString(developerIDRequirement as CFString, [], &developerID) == errSecSuccess, let developerID,
            SecRequirementCreateWithString(notarizedRequirement as CFString, [], &notarized) == errSecSuccess, let notarized,
            SecStaticCodeCheckValidity(staticCode, offline, developerID) == errSecSuccess
        else { return nil }
        var information: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        let signing = information as? [String: Any] ?? [:]
        guard let team = signing[kSecCodeInfoTeamIdentifier as String] as? String, let unique = signing[kSecCodeInfoUnique as String] as? Data else { return nil }
        let cdhash = unique.map { String(format: "%02x", $0) }.joined()
        return (url.path, team, cdhash, SecStaticCodeCheckValidity(staticCode, offline, notarized) == errSecSuccess)
    }

    static func notarizationVerdict(fromSpctlOutput output: String, path: String) -> Bool? {
        guard output.hasPrefix(path + ": ") else { return nil }
        let lines = output.dropFirst(path.count + 2).split(whereSeparator: \.isNewline)
        guard let verdict = lines.first, let source = lines.dropFirst().first(where: { $0.hasPrefix("source=") }) else { return nil }
        switch (verdict, source) {
        case ("accepted", "source=Notarized Developer ID"): return true
        case ("rejected", "source=Unnotarized Developer ID"): return false
        default: return nil
        }
    }

    static func notarizationFindings(_ rules: [Rule], apps: [(path: String, team: String, cdhash: String, isNotarized: Bool)], unchecked: Set<String> = [], cache: inout NotarizationCache, limits: ScanLimits = .defaults, assess: (String) -> Bool?) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        cache.keep(paths: unchecked.union(apps.map(\.path)))
        let unconfirmed = apps.filter { !$0.isNotarized }.sorted { $0.path < $1.path }
        let pending = unconfirmed.filter { cache.isNotarized(path: $0.path, cdhash: $0.cdhash) == nil }
        for app in pending.shuffled().prefix(limits[.maxNotarizationAssessments]) {
            guard let isNotarized = assess(app.path) else { break }
            cache.record(isNotarized, path: app.path, cdhash: app.cdhash)
        }
        let unnotarized = unconfirmed.filter { cache.isNotarized(path: $0.path, cdhash: $0.cdhash) == false }
        let findings = rules.flatMap { rule in
            unnotarized.map { app in
                Finding(rule: rule, detail: "\(URL(fileURLWithPath: app.path).lastPathComponent) · team \(app.team) · \(NSString(string: app.path).abbreviatingWithTildeInPath)", path: app.path, limits: limits)
            }
        }
        let left = unconfirmed.filter { cache.isNotarized(path: $0.path, cdhash: $0.cdhash) == nil }
        return (findings, left.map { NotScannedEntry(reason: .gatekeeperNotAsked, path: $0.path, explanation: "New or changed app. Notarization check couldn't ask Gatekeeper yet and tries again on the next scan", limits: limits) })
    }

    static func isNetworkAvailable(limits: ScanLimits = .defaults) -> Bool {
        let monitor = NWPathMonitor()
        let updated = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { _ in updated.signal() }
        monitor.start(queue: DispatchQueue(label: "bluehat.network-path"))
        defer { monitor.cancel() }
        return updated.wait(timeout: .now() + TimeInterval(limits[.networkPathTimeout])) == .success && monitor.currentPath.status == .satisfied
    }

    static func connections(fromNetstatOutput output: String) -> [Connection] {
        let row = /(tcp|udp)(?:4|6|46)\s+\d+\s+\d+\s+\S+\s+(\S+)\s+(?:([A-Z][A-Z0-9_]*)\s+)?\d+\s+\d+\s+\d+\s+\d+\s+(.*?):\d+\s+[0-9a-f]{5}\s/
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            guard
                let match = line.prefixMatch(of: row),
                let dot = match.2.lastIndex(of: "."),
                let port = RemoteHost.number(match.2[match.2.index(after: dot)...], in: RemoteHost.portRange),
                let host = match.2[..<dot].split(separator: "%").first,
                let address = RemoteHost.address(of: host),
                !RemoteHost.isLocal(address)
            else { return nil }
            let process = match.4.trimmingCharacters(in: .whitespaces)
            return Connection(host: String(host), address: address, port: port, transport: match.1.uppercased(), state: match.3.map(String.init), process: process.isEmpty ? nil : process)
        }
    }

    static func outboundFindings(_ rules: [Rule], connections: [Connection], limits: ScanLimits = .defaults) -> [Finding] {
        let ordered = connections.filter { $0.state == Connection.establishedState } + connections.filter { $0.state != Connection.establishedState }
        return rules.flatMap { rule in
            let hosts = (rule.hosts ?? []).compactMap(RemoteHost.init)
            let ports = Set(rule.ports ?? [])
            var reported = Set<String>()
            return ordered.compactMap { connection -> Finding? in
                guard
                    ports.contains(connection.port) || hosts.contains(where: { $0.matches(connection.address, port: connection.port) }),
                    reported.insert(connection.peer).inserted
                else { return nil }
                return Finding(rule: rule, detail: connection.detail, path: nil, limits: limits)
            }
        }
    }

    static func systemExtensions(fromSystemExtensionsctlOutput output: String) -> [(bundle: String, team: String?, detail: String)] {
        let entry = /[* ]*\t[* ]*\t([^\t]+)\t(\S+) \([^)\t]*\)\t(.*)\t\[([^\]\t]*)\]/
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            guard let match = line.wholeMatch(of: entry) else { return nil }
            let team = String(match.1)
            let bundle = String(match.2)
            return (bundle, team, "\(match.3) (\(bundle)) · team \(team) · \(match.4)")
        }
    }

    static func kernelExtensions(fromKmutilOutput output: String) -> [(bundle: String, team: String?, detail: String)] {
        let entry = /\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+) \(/
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            guard let match = line.prefixMatch(of: entry), !match.1.hasPrefix(appleBundlePrefix) else { return nil }
            let bundle = String(match.1)
            return (bundle, nil, "Kernel extension (\(bundle)) · loaded")
        }
    }

    static func systemExtensionFindings(_ rules: [Rule], extensions: [(bundle: String, team: String?, detail: String)], limits: ScanLimits = .defaults) -> [Finding] {
        rules.flatMap { rule in
            let bundles = (rule.bundles ?? []).map { $0.lowercased() }
            return extensions.filter { installed in
                if let team = installed.team { return !(rule.teams ?? []).contains(team) }
                let bundle = installed.bundle.lowercased()
                return !bundles.contains { bundle == $0 || bundle.hasPrefix($0 + ".") }
            }
            .map { Finding(rule: rule, detail: $0.detail, path: nil, limits: limits) }
        }
    }

    static func xprotectVersion(fromInfoPlist data: Data) -> Int? {
        let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        return (plist?["CFBundleShortVersionString"] as? String).flatMap { Int($0) }
    }

    static func xprotectFindings(_ rules: [Rule], version: Int?, limits: ScanLimits = .defaults) -> [Finding] {
        guard let version else { return [] }
        return rules.compactMap { rule in
            guard let minimum = rule.minimumVersion, version < minimum else { return nil }
            return Finding(rule: rule, detail: "XProtect version \(version) is older than \(minimum)", path: nil, limits: limits)
        }
    }

    static func fileChecks(_ rules: [Rule]) -> [(rule: Rule, regexes: [NSRegularExpression])] {
        rules.map { (rule: $0, regexes: regexes($0.patterns)) }
    }

    static func projectFileFindings(_ rules: [Rule], projects: [(path: String, files: Set<String>)], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let maxReadBytes = limits[.maxReadBytes]
        let compiled = fileChecks(rules)
        var findings: [Finding] = []
        var notScanned: [NotScannedEntry] = []
        for project in projects where project.files.contains(NpmInventory.manifestName) {
            for name in project.files.sorted() {
                let path = "\(project.path)/\(name)"
                let checks = compiled.filter { check in (check.rule.files ?? []).contains { fileName(name, matches: $0) } }
                guard !checks.isEmpty, let file = RegularFile.readStart(atPath: path, maxBytes: maxReadBytes, followingSymlinks: false) else { continue }
                if file.size > maxReadBytes { notScanned.append(.readOnlyStart(path: path, check: "Project file check", limits: limits)) }
                findings += autoreleasepool { fileFindings(checks: checks, data: file.data, path: path, limits: limits) }
            }
        }
        return (findings, notScanned)
    }

    static func nodeInstallFindings(_ rules: [Rule], moduleDirectories: [String], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let maxReadBytes = limits[.maxReadBytes]
        let compiled = fileChecks(rules)
        let files = Set(rules.flatMap { $0.files ?? [] }).sorted()
        var findings: [Finding] = []
        var notScanned: [NotScannedEntry] = []
        for directory in ProjectFolders.uniqueDirectories(moduleDirectories) {
            for file in files {
                let path = "\(directory)/\(file)"
                guard let read = RegularFile.readStart(atPath: path, maxBytes: maxReadBytes, followingSymlinks: false) else { continue }
                if read.size > maxReadBytes { notScanned.append(.readOnlyStart(path: path, check: "Node.js install check", limits: limits)) }
                let checks = compiled.filter { $0.rule.files?.contains(file) == true }
                findings += autoreleasepool { fileFindings(checks: checks, data: read.data, path: path, limits: limits) }
            }
        }
        return (findings, notScanned)
    }

    static func fileFindings(checks: [(rule: Rule, regexes: [NSRegularExpression])], data: Data, path: String, limits: ScanLimits = .defaults) -> [Finding] {
        guard !checks.isEmpty else { return [] }
        let location = NSString(string: path).abbreviatingWithTildeInPath
        let lines = String(decoding: data, as: UTF8.self).split(omittingEmptySubsequences: false) { $0 == "\n" || $0 == "\r\n" || $0 == "\r" }.map(String.init)
        return checks.compactMap { check in
            lines.firstIndex { matches(check.regexes, $0, limits: limits) }.map { Finding(rule: check.rule, detail: "Line \($0 + 1) · \(location)", path: path, limits: limits) }
        }
    }

    static func fileName(_ name: String, matches glob: String) -> Bool {
        let parts = glob.lowercased().split(separator: "*", omittingEmptySubsequences: false)
        var rest = Substring(name.lowercased())
        guard let first = parts.first, rest.hasPrefix(first) else { return false }
        rest = rest.dropFirst(first.count)
        guard let last = parts.last, parts.count > 1 else { return rest.isEmpty }
        for part in parts.dropFirst().dropLast() {
            guard let range = rest.range(of: part) else { return false }
            rest = rest[range.upperBound...]
        }
        return rest.hasSuffix(last)
    }

    static func packageChecks(_ rules: [Rule]) -> [(rule: Rule, listed: [String: [MaliciousPackage]])] {
        rules.map { (rule: $0, listed: Dictionary(grouping: $0.packages ?? [], by: \.name)) }
    }

    static func packageFindings(_ rules: [Rule], packages: [InstalledPackage], limits: ScanLimits = .defaults) -> [Finding] {
        packageFindings(checks: packageChecks(rules), packages: packages, limits: limits)
    }

    static func packageFindings(checks: [(rule: Rule, listed: [String: [MaliciousPackage]])], packages: [InstalledPackage], limits: ScanLimits = .defaults) -> [Finding] {
        let matches = checks.map { rule, listed in
            (rule: rule, hits: packages.compactMap { installed in
                listed[installed.name]?.first { $0.versions.contains(installed.version) }.map { (package: installed, advisory: $0.advisory) }
            })
        }
        let handWritten = Set(matches.filter { !$0.rule.isFromMalwareFeed }.flatMap { $0.hits.map(\.package) })
        return matches.flatMap { rule, hits in
            hits.filter { !rule.isFromMalwareFeed || !handWritten.contains($0.package) }.map { hit in
                let location = NSString(string: hit.package.path).abbreviatingWithTildeInPath
                return Finding(rule: rule, detail: "\(hit.advisory): \(hit.package.name) \(hit.package.version) · \(location)", path: hit.package.path, limits: limits)
            }
        }
    }

    static func withoutFeedFileDuplicates(_ areaFindings: [Finding], reported: [Finding]) -> [Finding] {
        let isFeedFile = { (finding: Finding) in finding.rule.isFromMalwareFeed && finding.rule.check == .fileHash }
        guard areaFindings.contains(where: isFeedFile) else { return areaFindings }
        let resolved = { (path: String) in URL(fileURLWithPath: path).resolvingSymlinksInPath().path }
        let handWritten = Set((reported + areaFindings).filter { !$0.rule.isFromMalwareFeed }.compactMap(\.path).map(resolved))
        return areaFindings.filter { finding in
            guard isFeedFile(finding), let path = finding.path else { return true }
            return !handWritten.contains(resolved(path))
        }
    }

    static func versionFindings(_ rules: [Rule], installs: [Installation], limits: ScanLimits = .defaults) -> [Finding] {
        rules.flatMap { rule in
            installs.filter { $0.product == rule.product }.compactMap { install in
                affectingRange(of: rule, for: install.version).map { range in
                    let fix = range.fixed.map { "fixed in \($0)" } ?? "no fixed release listed"
                    let location = NSString(string: install.path).abbreviatingWithTildeInPath
                    return Finding(rule: rule, detail: "\(rule.advisory ?? rule.id): \(install.product.rawValue) \(install.version) is affected (\(fix)) · \(location)", path: install.path, limits: limits)
                }
            }
        }
    }

    static func affectingRange(of rule: Rule, for version: SoftwareVersion) -> VersionRange? {
        guard let product = rule.product else { return nil }
        return (rule.ranges ?? []).first { range in
            guard let introduced = SoftwareVersion(range.introduced, for: product), introduced <= version else { return false }
            if let fixed = range.fixed {
                return SoftwareVersion(fixed, for: product).map { version < $0 } ?? false
            }
            if let lastAffected = range.lastAffected {
                return SoftwareVersion(lastAffected, for: product).map { version <= $0 } ?? false
            }
            return true
        }
    }

    public static func installedSoftware(limits: ScanLimits = .defaults) -> [Installation] {
        homebrewCellars.flatMap(cellarInstalls)
            + versionDirectories.flatMap { versionedInstalls(of: $0.product, by: $0.manager, in: expand($0.directory)) }
            + frameworkPythons(in: pythonFrameworkVersions, limits: limits)
            + installerNode(prefix: nodeInstallerPrefix, limits: limits)
    }

    public static func installation(at path: String, in installs: [Installation]) -> Installation? {
        installs.first { $0.path == path }
    }

    static func cellarInstalls(in cellar: String) -> [Installation] {
        let formulas = (try? FileManager.default.contentsOfDirectory(atPath: cellar)) ?? []
        return formulas.sorted().flatMap { formula -> [Installation] in
            guard let product = SoftwareProduct.allCases.first(where: { formula == $0.rawValue || formula.hasPrefix($0.rawValue + "@") }) else { return [] }
            return versionedInstalls(of: product, by: .homebrew, in: "\(cellar)/\(formula)")
        }
    }

    static func versionedInstalls(of product: SoftwareProduct, by manager: InstallManager, in directory: String) -> [Installation] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        return names.sorted().compactMap { name in
            let path = "\(directory)/\(name)"
            guard
                fileType(atPath: path) == .typeDirectory,
                let version = SoftwareVersion(name.replacing(/_[0-9]{1,4}$/, with: ""), for: product)
            else { return nil }
            return Installation(product: product, version: version, path: path, manager: manager)
        }
    }

    static func frameworkPythons(in versionsDirectory: String, limits: ScanLimits = .defaults) -> [Installation] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: versionsDirectory)) ?? []
        return names.sorted().compactMap { name in
            let path = "\(versionsDirectory)/\(name)"
            guard
                fileType(atPath: path) == .typeDirectory,
                SoftwareVersion(name, for: .python) != nil,
                let quoted = defines(in: readText("\(path)/include/python\(name)/patchlevel.h", limits: limits))["PY_VERSION"],
                let version = SoftwareVersion(quoted.trimmingCharacters(in: CharacterSet(charactersIn: "\"")), for: .python)
            else { return nil }
            return Installation(product: .python, version: version, path: path, manager: .pythonOrg)
        }
    }

    static func installerNode(prefix: String, limits: ScanLimits = .defaults) -> [Installation] {
        let binary = "\(prefix)/bin/node"
        let header = defines(in: readText("\(prefix)/include/node/node_version.h", limits: limits))
        let parts = ["MAJOR", "MINOR", "PATCH"].compactMap { header["NODE_\($0)_VERSION"] }
        guard
            fileType(atPath: binary) == .typeRegular,
            parts.count == 3,
            let version = SoftwareVersion(parts.joined(separator: "."), for: .node)
        else { return [] }
        return [Installation(product: .node, version: version, path: binary, manager: .nodeInstaller)]
    }

    static func defines(in text: String) -> [String: String] {
        lines(of: text).reduce(into: [:]) { defines, line in
            let fields = line.split(whereSeparator: \.isWhitespace)
            if fields.count >= 3, fields[0] == "#define" { defines[String(fields[1])] = String(fields[2]) }
        }
    }

    static func fileType(atPath path: String) -> FileAttributeType? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.type] as? FileAttributeType
    }

    static func authorizedKeys(in text: String) -> [(line: String, summary: String)] {
        lines(of: text).filter { !$0.hasPrefix("#") }.compactMap { line in
            let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard
                let typeIndex = fields.firstIndex(where: { field in sshKeyTypePrefixes.contains { field.hasPrefix($0) } }),
                typeIndex + 1 < fields.count,
                let blob = Data(base64Encoded: fields[typeIndex + 1])
            else { return nil }
            let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
            let comment = fields.dropFirst(typeIndex + 2).joined(separator: " ")
            let options = typeIndex > 0 ? " · options: " + fields[..<typeIndex].joined(separator: " ") : ""
            return (line, "\(fields[typeIndex]) \(fingerprint)" + (comment.isEmpty ? "" : " \(comment)") + options)
        }
    }

    static func profiles(fromProfilesOutput output: String) -> [(name: String, identifier: String, payloadTypes: [String])] {
        var order: [String] = []
        var attributes: [String: [String: String]] = [:]
        var payloads: [String: [String]] = [:]
        let attribute = /^(\S+\[\d+\]) attribute: (\w+): (.*)$/
        let payload = /^(\S+\[\d+\])\s+payload\[\d+\] type\s*=\s*(.+)$/
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if let match = line.firstMatch(of: attribute) {
                let key = String(match.1)
                if attributes[key] == nil { order.append(key) }
                attributes[key, default: [:]][String(match.2)] = String(match.3)
            } else if let match = line.firstMatch(of: payload) {
                payloads[String(match.1), default: []].append(String(match.2).trimmingCharacters(in: .whitespaces))
            }
        }
        return order.compactMap { key in
            guard let values = attributes[key], values["internaldata"] != "TRUE", let identifier = values["profileIdentifier"] else { return nil }
            return (values["name"] ?? identifier, identifier, payloads[key] ?? [])
        }
    }

    static func chromiumExtensions(browser: String, root: String, limits: ScanLimits = .defaults) -> (extensions: [(descriptor: String, detail: String, path: String)], notScanned: [NotScannedEntry]) {
        let maxReadBytes = limits[.maxReadBytes]
        let fileManager = FileManager.default
        let profiles = (try? fileManager.contentsOfDirectory(atPath: root)) ?? []
        var notScanned: [NotScannedEntry] = []
        let extensions = profiles.flatMap { profile -> [(descriptor: String, detail: String, path: String)] in
            let extensionsRoot = "\(root)/\(profile)/Extensions"
            let ids = (try? fileManager.contentsOfDirectory(atPath: extensionsRoot)) ?? []
            return ids.compactMap { id in
                let versions = ((try? fileManager.contentsOfDirectory(atPath: "\(extensionsRoot)/\(id)")) ?? []).filter { !$0.hasPrefix(".") }
                guard let version = versions.max(by: { $0.compare($1, options: .numeric) == .orderedAscending }) else { return nil }
                let directory = "\(extensionsRoot)/\(id)/\(version)"
                guard let file = RegularFile.readStart(atPath: "\(directory)/manifest.json", maxBytes: maxReadBytes, followingSymlinks: true) else { return nil }
                guard file.size <= maxReadBytes else {
                    notScanned.append(.oversized(path: "\(directory)/manifest.json", size: file.size, limit: maxReadBytes, limits: limits))
                    return nil
                }
                guard let manifest = extensionJSON(file.data, path: "\(directory)/manifest.json", notScanned: &notScanned, limits: limits) else { return nil }
                let name = localizedName(manifest["name"] as? String ?? id, manifest: manifest, directory: directory, notScanned: &notScanned, limits: limits)
                let permissions = ["permissions", "host_permissions", "optional_permissions"].flatMap { (manifest[$0] as? [Any] ?? []).compactMap { $0 as? String } }
                let update = manifest["update_url"] as? String ?? "none"
                return extensionRecord(browser: browser, id: id, name: name, update: update, permissions: permissions, path: directory)
            }
        }
        return (extensions, notScanned)
    }

    static func firefoxExtensions(profilesRoot: String, limits: ScanLimits = .defaults) -> (extensions: [(descriptor: String, detail: String, path: String)], notScanned: [NotScannedEntry]) {
        let maxExtensionIndexBytes = limits[.maxExtensionIndexBytes]
        let profiles = (try? FileManager.default.contentsOfDirectory(atPath: profilesRoot)) ?? []
        var notScanned: [NotScannedEntry] = []
        let extensions = profiles.flatMap { profile -> [(descriptor: String, detail: String, path: String)] in
            let index = "\(profilesRoot)/\(profile)/extensions.json"
            guard let file = RegularFile.readStart(atPath: index, maxBytes: maxExtensionIndexBytes, followingSymlinks: true) else { return [] }
            guard file.size <= maxExtensionIndexBytes else {
                notScanned.append(.oversized(path: index, size: file.size, limit: maxExtensionIndexBytes, limits: limits))
                return []
            }
            guard let addons = extensionJSON(file.data, path: index, notScanned: &notScanned, limits: limits)?["addons"] as? [[String: Any]] else { return [] }
            return addons.compactMap { addon in
                guard let id = addon["id"] as? String, let location = addon["location"] as? String, location == "app-profile" else { return nil }
                let name = (addon["defaultLocale"] as? [String: Any])?["name"] as? String ?? id
                let userPermissions = addon["userPermissions"] as? [String: Any] ?? [:]
                let permissions = ["permissions", "origins"].flatMap { userPermissions[$0] as? [String] ?? [] }
                let isSigned = (addon["signedState"] as? Int ?? 0) >= firefoxSignedState
                return extensionRecord(browser: "Firefox", id: id, name: name, update: isSigned ? "addons.mozilla.org" : "none", permissions: permissions, path: addon["path"] as? String ?? "\(profilesRoot)/\(profile)")
            }
        }
        return (extensions, notScanned)
    }

    static func extensionJSON(_ data: Data, path: String, notScanned: inout [NotScannedEntry], limits: ScanLimits = .defaults) -> [String: Any]? {
        do {
            return try JSONFile.object(from: data)
        } catch {
            notScanned.append(.notParsed(path: path, check: extensionCheckName, problem: error, limits: limits))
            return nil
        }
    }

    static func extensionRecord(browser: String, id: String, name: String, update: String, permissions: [String], path: String) -> (descriptor: String, detail: String, path: String) {
        let descriptor = "browser=\(descriptorField(browser)) id=\(descriptorField(id)) name=\(descriptorField(name)) update=\(descriptorField(update)) permissions=\(permissions.map(descriptorField).joined(separator: ","))"
        return (descriptor, "\(browser): \(name) (\(id))", path)
    }

    static func descriptorField(_ value: String) -> String {
        String(value.map { $0.isWhitespace ? "_" : $0 })
    }

    static func localizedName(_ name: String, manifest: [String: Any], directory: String, notScanned: inout [NotScannedEntry], limits: ScanLimits = .defaults) -> String {
        guard
            name.hasPrefix("__MSG_"), name.hasSuffix("__"),
            let locale = manifest["default_locale"] as? String, locale.range(of: localePattern, options: .regularExpression) != nil
        else { return name }
        let key = String(name.dropFirst(6).dropLast(2)).lowercased()
        let path = "\(directory)/_locales/\(locale)/messages.json"
        guard
            let data = RegularFile.read(atPath: path, maxBytes: limits[.maxReadBytes], followingSymlinks: false),
            let messages = extensionJSON(data, path: path, notScanned: &notScanned, limits: limits),
            let entry = messages.first(where: { $0.key.lowercased() == key })?.value as? [String: Any],
            let message = entry["message"] as? String
        else { return name }
        return message
    }

    static func signatureProblem(at url: URL, checks: SignatureChecks = SignatureChecks()) -> String? {
        switch checks.inspect(url, signatureProblem(of:)) {
        case .finished(let problem): problem
        case .stuck: unfinishedSignatureProblem
        case .skipped: nil
        }
    }

    static func signatureProblem(of staticCode: SecStaticCode) -> String? {
        let validity = SecStaticCodeCheckValidity(staticCode, signatureValidationFlags, nil)
        if validity == errSecCSUnsigned { return "is not signed" }
        var information: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        let flags = (information as? [String: Any])?[kSecCodeInfoFlags as String] as? UInt32 ?? 0
        if flags & adHocSignatureFlag != 0 { return "is ad-hoc signed, with no developer identity" }
        switch validity {
        case errSecSuccess: return nil
        case errSecCSBadResource, errSecCSResourcesNotSealed, errSecCSResourcesNotFound: return "was changed after it was signed"
        case errSecCSSignatureFailed, errSecCSSignatureInvalid: return "has a broken signature"
        default: return nil
        }
    }

    static func installedApps() -> [URL] {
        let ownBundle = Bundle.main.bundleURL.standardizedFileURL
        return appDirectories.map(expand).flatMap { directory -> [URL] in
            let children = (try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: directory), includingPropertiesForKeys: [.isDirectoryKey])) ?? []
            return children.flatMap { child -> [URL] in
                if child.pathExtension == "app" { return [child] }
                guard (try? child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else { return [] }
                let nested = (try? FileManager.default.contentsOfDirectory(at: child, includingPropertiesForKeys: nil)) ?? []
                return nested.filter { $0.pathExtension == "app" }
            }
        }
        .filter { $0.standardizedFileURL != ownBundle }
    }

    static func matchingLines(_ lines: [String], rules: [Rule], limits: ScanLimits = .defaults) -> [Finding] {
        rules.flatMap { rule in
            let regexes = regexes(rule.patterns)
            return lines.filter { matches(regexes, $0, limits: limits) }.map {
                Finding(rule: rule, detail: $0, path: nil, limits: limits)
            }
        }
    }

    static func launchItemFindings(_ rules: [Rule], items: [(path: String, program: String?, command: String)], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let findings = rules.flatMap { rule in
            let regexes = regexes(rule.patterns)
            return items.filter { matches(regexes, $0.command, limits: limits) || matches(regexes, $0.path, limits: limits) }.map {
                Finding(rule: rule, detail: $0.command, path: $0.path, limits: limits)
            }
        }
        return (findings, longLineEntries("Launch item check", paths: items.filter { isLongerThanMatched($0.command, limits: limits) }.map(\.path), limits: limits))
    }

    static func shellProfileFindings(_ rules: [Rule], files: [String], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let read = readStarts(of: files, check: "Shell profile check", limits: limits)
        let profiles = read.files.map { (path: $0.path, lines: lines(of: $0.text)) }
        let findings = rules.flatMap { rule in
            let regexes = regexes(rule.patterns)
            return profiles.flatMap { profile in
                profile.lines.filter { matches(regexes, $0, limits: limits) }.map {
                    Finding(rule: rule, detail: $0, path: profile.path, limits: limits)
                }
            }
        }
        return (findings, read.notScanned)
    }

    static func sshKeyFindings(_ rules: [Rule], files: [String], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let read = readStarts(of: files, check: "SSH key check", limits: limits)
        let keys = read.files.flatMap { file in
            authorizedKeys(in: file.text).map { (file: file.path, key: $0) }
        }
        let findings = rules.flatMap { rule in
            let regexes = regexes(rule.patterns)
            return keys.filter { rule.patterns == nil || matches(regexes, $0.key.line, limits: limits) }.map {
                Finding(rule: rule, detail: $0.key.summary, path: $0.file, limits: limits)
            }
        }
        return (findings, read.notScanned)
    }

    static func crontabFindings(_ rules: [Rule], lines: [String], limits: ScanLimits = .defaults) -> (findings: [Finding], notScanned: [NotScannedEntry]) {
        let longLines = lines.contains { isLongerThanMatched($0, limits: limits) } ? [NotScannedEntry(reason: .partlyRead, summary: "The crontab", explanation: longLineExplanation("Crontab check", limits: limits), limits: limits)] : []
        return (matchingLines(lines, rules: rules, limits: limits), longLines)
    }

    static func readStarts(of files: [String], check: String, limits: ScanLimits = .defaults) -> (files: [(path: String, text: String)], notScanned: [NotScannedEntry]) {
        let maxReadBytes = limits[.maxReadBytes]
        var cut: [NotScannedEntry] = []
        let read = files.compactMap { path -> (path: String, text: String)? in
            guard let file = RegularFile.readStart(atPath: path, maxBytes: maxReadBytes, followingSymlinks: true) else { return nil }
            if file.size > maxReadBytes { cut.append(.readOnlyStart(path: path, check: check, limits: limits)) }
            return (path, String(decoding: file.data, as: UTF8.self))
        }
        let withLongLines = read.filter { lines(of: $0.text).contains { isLongerThanMatched($0, limits: limits) } }.map(\.path)
        return (read, cut + longLineEntries(check, paths: withLongLines, limits: limits))
    }

    static func isLongerThanMatched(_ text: String, limits: ScanLimits = .defaults) -> Bool {
        text.utf16.count > limits[.maxMatchedLength]
    }

    static func longLineEntries(_ check: String, paths: [String], limits: ScanLimits = .defaults) -> [NotScannedEntry] {
        paths.map { NotScannedEntry(reason: .partlyRead, path: $0, explanation: longLineExplanation(check, limits: limits), limits: limits) }
    }

    static func longLineExplanation(_ check: String, limits: ScanLimits = .defaults) -> String {
        "Only the first \(limits[.maxMatchedLength].formatted()) characters of very long lines were matched (\(check))"
    }

    static func pathList(_ paths: [String], limits: ScanLimits = .defaults, namingAll: Bool = false) -> String {
        let named = paths.sorted().prefix(namingAll ? paths.count : limits[.maxNoticePaths]).map { Finding.clip(Finding.displayable(NSString(string: $0).abbreviatingWithTildeInPath), limits: limits) }
        let others = paths.count - named.count
        return named.joined(separator: ", ") + (others > 0 ? " and \(others.formatted()) more" : "")
    }

    static func expand(_ path: String) -> String {
        NSString(string: path).expandingTildeInPath
    }

    static func regexes(_ patterns: [String]?) -> [NSRegularExpression] {
        (patterns ?? []).compactMap { try? NSRegularExpression(pattern: $0) }
    }

    static func matches(_ regexes: [NSRegularExpression], _ text: String, limits: ScanLimits = .defaults) -> Bool {
        let subject = String(decoding: text.utf16.prefix(limits[.maxMatchedLength]), as: UTF16.self)
        let range = NSRange(subject.startIndex..., in: subject)
        return regexes.contains { $0.firstMatch(in: subject, range: range) != nil }
    }

    static func lines(of text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func readText(_ path: String, limits: ScanLimits = .defaults) -> String {
        String(decoding: RegularFile.read(atPath: path, maxBytes: limits[.maxReadBytes], followingSymlinks: true) ?? Data(), as: UTF8.self)
    }

    static func runTool(_ executable: String, _ arguments: [String], includingErrorOutput: Bool = false, timeout: TimeInterval? = nil, limits: ScanLimits = .defaults, notScanned: NotScannedCollector? = nil) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = includingErrorOutput ? output : FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return ""
        }
        let finished = DispatchSemaphore(value: 0)
        let data = Mutex(Data())
        Thread.detachNewThread {
            let read = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            data.withLock { $0 = read }
            finished.signal()
        }
        let limit = timeout ?? TimeInterval(limits[.toolTimeout])
        guard finished.wait(timeout: .now() + limit) == .success else {
            notScanned?.add(NotScannedEntry(reason: .timedOut, summary: executable, explanation: "This system tool didn't finish within \(Int(limit).formatted()) seconds, so its check found nothing", limits: limits))
            process.terminate()
            if finished.wait(timeout: .now() + TimeInterval(limits[.toolKillDelay])) == .timedOut, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            return ""
        }
        guard process.terminationReason == .exit else { return "" }
        return String(decoding: data.withLock { $0 }, as: UTF8.self)
    }

    static func launchItemCommands(in directories: [String], limits: ScanLimits = .defaults) -> (items: [(path: String, program: String?, command: String)], notScanned: [NotScannedEntry]) {
        let maxReadBytes = limits[.maxReadBytes]
        var notScanned: [NotScannedEntry] = []
        let items = directories.flatMap { directory -> [(path: String, program: String?, command: String)] in
            let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            return names.filter { $0.hasSuffix(".plist") }.compactMap { name in
                let path = directory + "/" + name
                guard let file = RegularFile.readStart(atPath: path, maxBytes: maxReadBytes, followingSymlinks: true) else { return nil }
                guard file.size <= maxReadBytes else {
                    notScanned.append(.oversized(path: path, size: file.size, limit: maxReadBytes, limits: limits))
                    return nil
                }
                guard !file.data.isEmpty else { return nil }
                guard let plist = try? PropertyListSerialization.propertyList(from: file.data, format: nil) as? [String: Any] else {
                    notScanned.append(NotScannedEntry(reason: .couldNotParse, path: path, explanation: Self.unparsedLaunchItemExplanation, limits: limits))
                    return nil
                }
                let program = plist["Program"] as? String
                let arguments = plist["ProgramArguments"] as? [String] ?? []
                let command = ([program].compactMap { $0 } + arguments).joined(separator: " ")
                return command.isEmpty ? nil : (path, program ?? arguments.first, command)
            }
        }
        return (items, notScanned)
    }

    static func listeningPorts(limits: ScanLimits = .defaults, notScanned: NotScannedCollector? = nil) -> [Int: String] {
        var ports: [Int: String] = [:]
        var command = "unknown"
        for line in lines(of: runTool("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fcn"], limits: limits, notScanned: notScanned)) {
            if line.hasPrefix("c") {
                command = String(line.dropFirst())
            } else if line.hasPrefix("n"), let port = line.split(separator: ":").last.flatMap({ Int($0) }) {
                ports[port] = command
            }
        }
        return ports
    }

    static func hashedFiles(in directories: [String], limits: ScanLimits = .defaults, cancellation: ScanCancellation = ScanCancellation()) -> (hashes: [String: String], notScanned: [NotScannedEntry]) {
        let budget = limits[.maxHashedFilesPerDirectory]
        let maxHashDepth = limits[.maxHashDepth]
        let maxHashedFileBytes = limits[.maxHashedFileBytes]
        var hashes: [String: String] = [:]
        var notScanned: [NotScannedEntry] = []
        let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .fileSizeKey, .addedToDirectoryDateKey, .creationDateKey]
        let now = Date.now
        for directory in directories {
            let listing = FileManager.default.enumerator(at: URL(fileURLWithPath: directory), includingPropertiesForKeys: keys) { url, error in
                if let reason = NotScannedReason(listingError: error) {
                    notScanned.append(NotScannedEntry(reason: reason, path: url.path, limits: limits))
                }
                return true
            }
            guard let enumerator = listing else { continue }
            var candidates: [(url: URL, arrived: Date)] = []
            for case let url as URL in enumerator {
                let values = try? url.resourceValues(forKeys: Set(keys))
                if enumerator.level > maxHashDepth {
                    enumerator.skipDescendants()
                    if values?.isDirectory == true {
                        notScanned.append(NotScannedEntry(reason: .overDepthLimit, path: url.path, explanation: "Fingerprint check stops \(maxHashDepth.formatted()) levels down, so the files inside weren't checked", limits: limits))
                    }
                }
                guard let values, values.isRegularFile == true else { continue }
                guard (values.fileSize ?? 0) <= maxHashedFileBytes else {
                    notScanned.append(.oversized(path: url.path, size: values.fileSize ?? 0, limit: maxHashedFileBytes, limits: limits))
                    continue
                }
                let arrived = values.addedToDirectoryDate ?? values.creationDate ?? .distantPast
                candidates.append((url, arrived <= now ? arrived : .distantPast))
            }
            let newest = candidates.sorted { $0.arrived > $1.arrived }.prefix(budget)
            for candidate in newest where !cancellation.isCancelled {
                hashes[candidate.url.path] = autoreleasepool { sha256(of: candidate.url, maxBytes: maxHashedFileBytes, cancellation: cancellation) }
            }
            let skippedCount = candidates.count - newest.count
            if skippedCount > 0 {
                notScanned.append(NotScannedEntry(reason: .overCountLimit, path: directory, explanation: "Fingerprint check covered only the \(budget.formatted()) newest files here and skipped \(skippedCount.formatted())", limits: limits))
            }
        }
        return (hashes, notScanned)
    }

    static func sha256(of url: URL, maxBytes: Int, cancellation: ScanCancellation = ScanCancellation()) -> String? {
        guard let file = RegularFile.open(atPath: url.path, followingSymlinks: false), file.size <= maxBytes else { return nil }
        defer { try? file.handle.close() }
        var hasher = SHA256()
        var remaining = file.size
        while remaining > 0, let chunk = RegularFile.readChunk(from: file.handle, upToCount: min(hashChunkBytes, remaining)), !chunk.isEmpty {
            guard !cancellation.isCancelled else { return nil }
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func settingProblem(_ setting: SystemSetting, limits: ScanLimits = .defaults, notScanned: NotScannedCollector? = nil) -> String? {
        switch setting {
        case .sip:
            let status = runTool("/usr/bin/csrutil", ["status"], limits: limits, notScanned: notScanned)
            return status.contains("disabled") ? "Start up in Recovery and run: csrutil enable" : nil
        case .gatekeeper:
            let status = runTool("/usr/sbin/spctl", ["--status"], limits: limits, notScanned: notScanned)
            return status.contains("disabled") ? "Turn on in System Settings › Privacy & Security" : nil
        case .firewall:
            let status = runTool("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], limits: limits, notScanned: notScanned)
            return status.contains("disabled") ? "Turn on in System Settings › Network › Firewall" : nil
        }
    }
}
