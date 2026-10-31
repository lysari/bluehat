import CryptoKit
import Foundation
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
    static let firefoxSignedState = 2
    static let maxExtensionIndexBytes = 10_000_000
    static let adHocSignatureFlag: UInt32 = 0x2
    static let maxReadBytes = 1_000_000
    static let maxMatchedLength = 8_192
    static let maxHashedFileBytes = 50_000_000
    static let maxHashedFilesPerDirectory = 50_000
    static let maxHashDepth = 6
    static let hashChunkBytes = 1 << 20
    static let localePattern = "^[A-Za-z0-9_-]{1,16}$"

    let projectFolders: [String]

    public init(projectFolders: [String] = []) {
        self.projectFolders = projectFolders
    }

    public func scan(_ rulebook: Rulebook, onAreaFinished: @Sendable (CheckKind, [Finding]) -> Void = { _, _ in }) -> (findings: [Finding], notices: [String]) {
        var findings: [Finding] = []
        var notices: [String] = []
        var projects: [(path: String, files: Set<String>)]?
        for area in CheckKind.allCases {
            let rules = rulebook.rules.filter { $0.check == area }
            guard !rules.isEmpty else { continue }
            if projects == nil, [.npmPackage, .projectFile].contains(area) {
                let walk = ProjectFolders.directories(in: projectFolders, containing: NpmInventory.projectFileNames)
                projects = walk.directories
                notices += [walk.notice].compactMap { $0 }
            }
            let areaFindings = Self.findings(in: area, rules: rules, projects: projects ?? [], notices: &notices)
            findings += areaFindings
            onAreaFinished(area, areaFindings)
        }
        return (findings.sorted { $0.rule.severity > $1.rule.severity }, notices)
    }

    static func findings(in area: CheckKind, rules: [Rule], projects: [(path: String, files: Set<String>)], notices: inout [String]) -> [Finding] {
        switch area {
        case .path:
            return rules.flatMap { rule in
                (rule.paths ?? []).map(expand).filter(FileManager.default.fileExists).map {
                    Finding(rule: rule, detail: $0, path: $0)
                }
            }
        case .launchItem:
            let launchItems = launchItemCommands()
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return launchItems.filter { matches(regexes, $0.command) || matches(regexes, $0.path) }.map {
                    Finding(rule: rule, detail: $0.command, path: $0.path)
                }
            }
        case .shellProfile:
            let profiles = shellProfileFiles.map(expand).map { (path: $0, lines: lines(of: readText($0))) }
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return profiles.flatMap { profile in
                    profile.lines.filter { matches(regexes, $0) }.map {
                        Finding(rule: rule, detail: $0, path: profile.path)
                    }
                }
            }
        case .process:
            return matchingLines(lines(of: runTool("/bin/ps", ["-axww", "-o", "command="])), rules: rules)
        case .crontab:
            return matchingLines(lines(of: runTool("/usr/bin/crontab", ["-l"])), rules: rules)
        case .listeningPort:
            let listeners = listeningPorts()
            return rules.flatMap { rule in
                (rule.ports ?? []).sorted().compactMap { port in
                    listeners[port].map { Finding(rule: rule, detail: "Port \(port) open by \($0)", path: nil) }
                }
            }
        case .fileHash:
            let hashed = hashedFiles(in: hashedDirectories.map(expand), budget: maxHashedFilesPerDirectory)
            if let notice = hashed.notice { notices.append(notice) }
            return rules.flatMap { rule in
                let hashes = Set(rule.hashes ?? [])
                return hashed.hashes.filter { hashes.contains($0.value) }.keys.sorted().map {
                    Finding(rule: rule, detail: $0, path: $0)
                }
            }
        case .setting:
            return rules.compactMap { rule in
                rule.setting.flatMap(settingProblem).map { Finding(rule: rule, detail: $0, path: nil) }
            }
        case .launchItemSignature:
            let items = launchItemCommands().compactMap { item -> (path: String, program: String)? in
                guard let program = item.program, program.hasPrefix("/"), FileManager.default.fileExists(atPath: program) else { return nil }
                return (item.path, program)
            }
            let problems = Set(items.map(\.program)).reduce(into: [String: String]()) { problems, program in
                problems[program] = signatureProblem(at: URL(fileURLWithPath: program))
            }
            return rules.flatMap { rule in
                items.compactMap { item in
                    problems[item.program].map { Finding(rule: rule, detail: "\(item.program) \($0)", path: item.path) }
                }
            }
        case .sshKey:
            let keys = authorizedKeyFiles.map(expand).flatMap { file in
                authorizedKeys(in: readText(file)).map { (file: file, key: $0) }
            }
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return keys.filter { rule.patterns == nil || matches(regexes, $0.key.line) }.map {
                    Finding(rule: rule, detail: $0.key.summary, path: $0.file)
                }
            }
        case .profile:
            let installed = profiles(fromProfilesOutput: runTool("/usr/bin/profiles", ["show", "-type", "configuration"]))
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return installed.filter { profile in
                    rule.patterns == nil || profile.payloadTypes.contains { matches(regexes, $0) }
                }
                .map { Finding(rule: rule, detail: "\($0.name) (\($0.identifier)) · payloads: \($0.payloadTypes.joined(separator: ", "))", path: nil) }
            }
        case .browserExtension:
            let extensions = chromiumBrowsers.flatMap { chromiumExtensions(browser: $0.0, root: expand($0.1)) } + firefoxExtensions(profilesRoot: expand(firefoxProfiles))
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return extensions.filter { matches(regexes, $0.descriptor) }.map {
                    Finding(rule: rule, detail: $0.detail, path: $0.path)
                }
            }
        case .appSignature:
            let apps = installedApps()
            let problems = Mutex<[(path: String, problem: String)]>([])
            DispatchQueue.concurrentPerform(iterations: apps.count) { index in
                if let problem = signatureProblem(at: apps[index]) {
                    problems.withLock { $0.append((apps[index].path, problem)) }
                }
            }
            let sorted = problems.withLock { $0 }.sorted { $0.path < $1.path }
            return rules.flatMap { rule in
                sorted.map { Finding(rule: rule, detail: "\(URL(fileURLWithPath: $0.path).lastPathComponent) \($0.problem)", path: $0.path) }
            }
        case .softwareVersion:
            return versionFindings(rules, installs: installedSoftware())
        case .npmPackage:
            let inventory = NpmInventory.packages(inProjects: projects, moduleDirectories: NpmInventory.moduleDirectories(for: installedSoftware()))
            notices += [inventory.notice].compactMap { $0 }
            return packageFindings(rules, packages: inventory.packages)
        case .projectFile:
            let checked = projectFileFindings(rules, projects: projects)
            notices += [checked.notice].compactMap { $0 }
            return checked.findings
        }
    }

    static func projectFileFindings(_ rules: [Rule], projects: [(path: String, files: Set<String>)]) -> (findings: [Finding], notice: String?) {
        let compiled = rules.map { (rule: $0, regexes: regexes($0.patterns)) }
        var findings: [Finding] = []
        var oversized: [String] = []
        for project in projects where project.files.contains(NpmInventory.manifestName) {
            for name in project.files.sorted() {
                let path = "\(project.path)/\(name)"
                let checks = compiled.filter { check in (check.rule.files ?? []).contains { fileName(name, matches: $0) } }
                guard !checks.isEmpty, let file = RegularFile.open(atPath: path, followingSymlinks: false) else { continue }
                let data = (try? file.handle.read(upToCount: maxReadBytes)) ?? Data()
                try? file.handle.close()
                let location = NSString(string: path).abbreviatingWithTildeInPath
                if file.size > maxReadBytes { oversized.append(Finding.displayable(location)) }
                let lines = String(decoding: data, as: UTF8.self).split(omittingEmptySubsequences: false) { $0 == "\n" || $0 == "\r\n" || $0 == "\r" }.map(String.init)
                for check in checks {
                    guard let index = lines.firstIndex(where: { matches(check.regexes, $0) }) else { continue }
                    findings.append(Finding(rule: check.rule, detail: "Line \(index + 1) · \(location)", path: path))
                }
            }
        }
        guard !oversized.isEmpty else { return (findings, nil) }
        return (findings, "Project file check read only the first \(Int64(maxReadBytes).formatted(.byteCount(style: .decimal))) of \(oversized.joined(separator: ", ")).")
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

    static func packageFindings(_ rules: [Rule], packages: [InstalledPackage]) -> [Finding] {
        rules.flatMap { rule in
            let listed = Dictionary(grouping: rule.packages ?? [], by: \.name)
            return packages.compactMap { installed in
                listed[installed.name]?.first { $0.versions.contains(installed.version) }.map { entry in
                    let location = NSString(string: installed.path).abbreviatingWithTildeInPath
                    return Finding(rule: rule, detail: "\(entry.advisory): \(installed.name) \(installed.version) · \(location)", path: installed.path)
                }
            }
        }
    }

    static func versionFindings(_ rules: [Rule], installs: [Installation]) -> [Finding] {
        rules.flatMap { rule in
            installs.filter { $0.product == rule.product }.compactMap { install in
                affectingRange(of: rule, for: install.version).map { range in
                    let fix = range.fixed.map { "fixed in \($0)" } ?? "no fixed release listed"
                    let location = NSString(string: install.path).abbreviatingWithTildeInPath
                    return Finding(rule: rule, detail: "\(rule.advisory ?? rule.id): \(install.product.rawValue) \(install.version) is affected (\(fix)) · \(location)", path: install.path)
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

    public static func installedSoftware() -> [Installation] {
        homebrewCellars.flatMap(cellarInstalls)
            + versionDirectories.flatMap { versionedInstalls(of: $0.product, by: $0.manager, in: expand($0.directory)) }
            + frameworkPythons(in: pythonFrameworkVersions)
            + installerNode(prefix: nodeInstallerPrefix)
    }

    public static func installation(at path: String, in installs: [Installation] = installedSoftware()) -> Installation? {
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

    static func frameworkPythons(in versionsDirectory: String) -> [Installation] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: versionsDirectory)) ?? []
        return names.sorted().compactMap { name in
            let path = "\(versionsDirectory)/\(name)"
            guard
                fileType(atPath: path) == .typeDirectory,
                SoftwareVersion(name, for: .python) != nil,
                let quoted = defines(in: readText("\(path)/include/python\(name)/patchlevel.h"))["PY_VERSION"],
                let version = SoftwareVersion(quoted.trimmingCharacters(in: CharacterSet(charactersIn: "\"")), for: .python)
            else { return nil }
            return Installation(product: .python, version: version, path: path, manager: .pythonOrg)
        }
    }

    static func installerNode(prefix: String) -> [Installation] {
        let binary = "\(prefix)/bin/node"
        let header = defines(in: readText("\(prefix)/include/node/node_version.h"))
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

    static func chromiumExtensions(browser: String, root: String) -> [(descriptor: String, detail: String, path: String)] {
        let fileManager = FileManager.default
        let profiles = (try? fileManager.contentsOfDirectory(atPath: root)) ?? []
        return profiles.flatMap { profile -> [(descriptor: String, detail: String, path: String)] in
            let extensionsRoot = "\(root)/\(profile)/Extensions"
            let ids = (try? fileManager.contentsOfDirectory(atPath: extensionsRoot)) ?? []
            return ids.compactMap { id in
                let versions = ((try? fileManager.contentsOfDirectory(atPath: "\(extensionsRoot)/\(id)")) ?? []).filter { !$0.hasPrefix(".") }
                guard
                    let version = versions.max(by: { $0.compare($1, options: .numeric) == .orderedAscending }),
                    let data = RegularFile.read(atPath: "\(extensionsRoot)/\(id)/\(version)/manifest.json", maxBytes: maxReadBytes, followingSymlinks: true),
                    let manifest = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                else { return nil }
                let directory = "\(extensionsRoot)/\(id)/\(version)"
                let name = localizedName(manifest["name"] as? String ?? id, manifest: manifest, directory: directory)
                let permissions = ["permissions", "host_permissions", "optional_permissions"].flatMap { (manifest[$0] as? [Any] ?? []).compactMap { $0 as? String } }
                let update = manifest["update_url"] as? String ?? "none"
                return extensionRecord(browser: browser, id: id, name: name, update: update, permissions: permissions, path: directory)
            }
        }
    }

    static func firefoxExtensions(profilesRoot: String) -> [(descriptor: String, detail: String, path: String)] {
        let profiles = (try? FileManager.default.contentsOfDirectory(atPath: profilesRoot)) ?? []
        return profiles.flatMap { profile -> [(descriptor: String, detail: String, path: String)] in
            guard
                let data = RegularFile.read(atPath: "\(profilesRoot)/\(profile)/extensions.json", maxBytes: maxExtensionIndexBytes, followingSymlinks: true),
                let addons = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["addons"] as? [[String: Any]]
            else { return [] }
            return addons.compactMap { addon in
                guard let id = addon["id"] as? String, let location = addon["location"] as? String, location == "app-profile" else { return nil }
                let name = (addon["defaultLocale"] as? [String: Any])?["name"] as? String ?? id
                let userPermissions = addon["userPermissions"] as? [String: Any] ?? [:]
                let permissions = ["permissions", "origins"].flatMap { userPermissions[$0] as? [String] ?? [] }
                let isSigned = (addon["signedState"] as? Int ?? 0) >= firefoxSignedState
                return extensionRecord(browser: "Firefox", id: id, name: name, update: isSigned ? "addons.mozilla.org" : "none", permissions: permissions, path: addon["path"] as? String ?? "\(profilesRoot)/\(profile)")
            }
        }
    }

    static func extensionRecord(browser: String, id: String, name: String, update: String, permissions: [String], path: String) -> (descriptor: String, detail: String, path: String) {
        let descriptor = "browser=\(descriptorField(browser)) id=\(descriptorField(id)) name=\(descriptorField(name)) update=\(descriptorField(update)) permissions=\(permissions.map(descriptorField).joined(separator: ","))"
        return (descriptor, "\(browser): \(name) (\(id))", path)
    }

    static func descriptorField(_ value: String) -> String {
        String(value.map { $0.isWhitespace ? "_" : $0 })
    }

    static func localizedName(_ name: String, manifest: [String: Any], directory: String) -> String {
        guard
            name.hasPrefix("__MSG_"), name.hasSuffix("__"),
            let locale = manifest["default_locale"] as? String, locale.range(of: localePattern, options: .regularExpression) != nil
        else { return name }
        let key = String(name.dropFirst(6).dropLast(2)).lowercased()
        guard
            let data = RegularFile.read(atPath: "\(directory)/_locales/\(locale)/messages.json", maxBytes: maxReadBytes, followingSymlinks: false),
            let messages = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let entry = messages.first(where: { $0.key.lowercased() == key })?.value as? [String: Any],
            let message = entry["message"] as? String
        else { return name }
        return message
    }

    static func signatureProblem(at url: URL) -> String? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        let validity = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
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

    static func matchingLines(_ lines: [String], rules: [Rule]) -> [Finding] {
        rules.flatMap { rule in
            let regexes = regexes(rule.patterns)
            return lines.filter { matches(regexes, $0) }.map {
                Finding(rule: rule, detail: $0, path: nil)
            }
        }
    }

    static func expand(_ path: String) -> String {
        NSString(string: path).expandingTildeInPath
    }

    static func regexes(_ patterns: [String]?) -> [NSRegularExpression] {
        (patterns ?? []).compactMap { try? NSRegularExpression(pattern: $0) }
    }

    static func matches(_ regexes: [NSRegularExpression], _ text: String) -> Bool {
        let subject = String(decoding: text.utf16.prefix(maxMatchedLength), as: UTF16.self)
        let range = NSRange(subject.startIndex..., in: subject)
        return regexes.contains { $0.firstMatch(in: subject, range: range) != nil }
    }

    static func lines(of text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func readText(_ path: String) -> String {
        String(decoding: RegularFile.read(atPath: path, maxBytes: maxReadBytes, followingSymlinks: true) ?? Data(), as: UTF8.self)
    }

    static func runTool(_ executable: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return ""
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    static func launchItemCommands() -> [(path: String, program: String?, command: String)] {
        launchItemDirectories.map(expand).flatMap { directory -> [(path: String, program: String?, command: String)] in
            let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            return names.filter { $0.hasSuffix(".plist") }.compactMap { name in
                let path = directory + "/" + name
                guard
                    let data = RegularFile.read(atPath: path, maxBytes: maxReadBytes, followingSymlinks: true),
                    let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
                else { return nil }
                let program = plist["Program"] as? String
                let arguments = plist["ProgramArguments"] as? [String] ?? []
                let command = ([program].compactMap { $0 } + arguments).joined(separator: " ")
                return command.isEmpty ? nil : (path, program ?? arguments.first, command)
            }
        }
    }

    static func listeningPorts() -> [Int: String] {
        var ports: [Int: String] = [:]
        var command = "unknown"
        for line in lines(of: runTool("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fcn"])) {
            if line.hasPrefix("c") {
                command = String(line.dropFirst())
            } else if line.hasPrefix("n"), let port = line.split(separator: ":").last.flatMap({ Int($0) }) {
                ports[port] = command
            }
        }
        return ports
    }

    static func hashedFiles(in directories: [String], budget: Int) -> (hashes: [String: String], notice: String?) {
        var hashes: [String: String] = [:]
        var skipped: [String] = []
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey, .addedToDirectoryDateKey, .creationDateKey]
        let now = Date.now
        for directory in directories {
            guard let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: directory), includingPropertiesForKeys: keys) else { continue }
            var candidates: [(url: URL, arrived: Date)] = []
            for case let url as URL in enumerator {
                if enumerator.level > maxHashDepth { enumerator.skipDescendants() }
                guard
                    let values = try? url.resourceValues(forKeys: Set(keys)), values.isRegularFile == true,
                    (values.fileSize ?? 0) <= maxHashedFileBytes
                else { continue }
                let arrived = values.addedToDirectoryDate ?? values.creationDate ?? .distantPast
                candidates.append((url, arrived <= now ? arrived : .distantPast))
            }
            let newest = candidates.sorted { $0.arrived > $1.arrived }.prefix(budget)
            for candidate in newest {
                hashes[candidate.url.path] = sha256(of: candidate.url)
            }
            let skippedCount = candidates.count - newest.count
            if skippedCount > 0 { skipped.append("\(skippedCount.formatted()) in \(NSString(string: directory).abbreviatingWithTildeInPath)") }
        }
        guard !skipped.isEmpty else { return (hashes, nil) }
        return (hashes, "Fingerprint check covered only the \(budget.formatted()) newest files per folder and skipped \(skipped.joined(separator: ", ")).")
    }

    static func sha256(of url: URL) -> String? {
        guard let file = RegularFile.open(atPath: url.path, followingSymlinks: false), file.size <= maxHashedFileBytes else { return nil }
        defer { try? file.handle.close() }
        var hasher = SHA256()
        var remaining = file.size
        while remaining > 0, let chunk = try? file.handle.read(upToCount: min(hashChunkBytes, remaining)), !chunk.isEmpty {
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func settingProblem(_ setting: SystemSetting) -> String? {
        switch setting {
        case .sip:
            let status = runTool("/usr/bin/csrutil", ["status"])
            return status.contains("disabled") ? "Start up in Recovery and run: csrutil enable" : nil
        case .gatekeeper:
            let status = runTool("/usr/sbin/spctl", ["--status"])
            return status.contains("disabled") ? "Turn on in System Settings › Privacy & Security" : nil
        case .firewall:
            let status = runTool("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
            return status.contains("disabled") ? "Turn on in System Settings › Network › Firewall" : nil
        }
    }
}
