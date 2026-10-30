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
    static let firefoxSignedState = 2
    static let maxExtensionIndexBytes = 10_000_000
    static let adHocSignatureFlag: UInt32 = 0x2
    static let maxReadBytes = 1_000_000
    static let maxHashedFileBytes = 50_000_000
    static let maxHashedFiles = 5_000
    static let maxHashDepth = 6
    static let hashChunkBytes = 1 << 20
    static let maxDetailLength = 200

    public init() {}

    public func scan(_ rulebook: Rulebook, onAreaFinished: @Sendable (CheckKind, [Finding]) -> Void = { _, _ in }) -> [Finding] {
        var findings: [Finding] = []
        for area in CheckKind.allCases {
            let rules = rulebook.rules.filter { $0.check == area }
            guard !rules.isEmpty else { continue }
            let areaFindings = Self.findings(in: area, rules: rules)
            findings += areaFindings
            onAreaFinished(area, areaFindings)
        }
        return findings.sorted { $0.rule.severity > $1.rule.severity }
    }

    static func findings(in area: CheckKind, rules: [Rule]) -> [Finding] {
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
                    Finding(rule: rule, detail: clip($0.command), path: $0.path)
                }
            }
        case .shellProfile:
            let profiles = shellProfileFiles.map(expand).map { (path: $0, lines: lines(of: readText($0))) }
            return rules.flatMap { rule in
                let regexes = regexes(rule.patterns)
                return profiles.flatMap { profile in
                    profile.lines.filter { matches(regexes, $0) }.map {
                        Finding(rule: rule, detail: clip($0), path: profile.path)
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
            let fileHashes = hashedFiles()
            return rules.flatMap { rule in
                let hashes = Set(rule.hashes ?? [])
                return fileHashes.filter { hashes.contains($0.value) }.keys.sorted().map {
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
        }
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
            return (line, clip("\(fields[typeIndex]) \(fingerprint)" + (comment.isEmpty ? "" : " \(comment)") + options))
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
                    let data = fileManager.contents(atPath: "\(extensionsRoot)/\(id)/\(version)/manifest.json"), data.count <= maxReadBytes,
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
                let data = FileManager.default.contents(atPath: "\(profilesRoot)/\(profile)/extensions.json"), data.count <= maxExtensionIndexBytes,
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
        let descriptor = "browser=\(browser) id=\(id) name=\(name) update=\(update) permissions=\(permissions.joined(separator: ","))"
        return (descriptor, clip("\(browser): \(name) (\(id))"), path)
    }

    static func localizedName(_ name: String, manifest: [String: Any], directory: String) -> String {
        guard name.hasPrefix("__MSG_"), name.hasSuffix("__"), let locale = manifest["default_locale"] as? String else { return name }
        let key = String(name.dropFirst(6).dropLast(2)).lowercased()
        guard
            let data = FileManager.default.contents(atPath: "\(directory)/_locales/\(locale)/messages.json"),
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
                Finding(rule: rule, detail: clip($0), path: nil)
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
        let range = NSRange(text.startIndex..., in: text)
        return regexes.contains { $0.firstMatch(in: text, range: range) != nil }
    }

    static func lines(of text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func clip(_ text: String) -> String {
        text.count > maxDetailLength ? String(text.prefix(maxDetailLength)) + "…" : text
    }

    static func readText(_ path: String) -> String {
        guard let handle = FileHandle(forReadingAtPath: path) else { return "" }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: maxReadBytes)) ?? Data()
        return String(decoding: data, as: UTF8.self)
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
                    let data = FileManager.default.contents(atPath: path), data.count <= maxReadBytes,
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

    static func hashedFiles() -> [String: String] {
        var hashes: [String: String] = [:]
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey]
        for directory in hashedDirectories.map(expand) {
            guard let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: directory), includingPropertiesForKeys: keys) else { continue }
            for case let url as URL in enumerator {
                if enumerator.level > maxHashDepth { enumerator.skipDescendants() }
                guard
                    hashes.count < maxHashedFiles,
                    let values = try? url.resourceValues(forKeys: Set(keys)),
                    values.isRegularFile == true,
                    (values.fileSize ?? 0) <= maxHashedFileBytes,
                    let digest = sha256(of: url)
                else { continue }
                hashes[url.path] = digest
            }
        }
        return hashes
    }

    static func sha256(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: hashChunkBytes), !chunk.isEmpty {
            hasher.update(data: chunk)
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
