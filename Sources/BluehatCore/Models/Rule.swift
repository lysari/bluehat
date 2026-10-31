import Foundation

public enum Severity: String, Codable, Sendable, Comparable {
    case info, low, medium, high, critical

    var rank: Int {
        switch self {
        case .info: 0
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }
}

public enum ThreatCategory: String, Codable, Sendable {
    case malware, rce, worm, backdoor, persistence, miner, hardening
}

public enum CheckKind: String, Codable, Sendable, CaseIterable {
    case path, launchItem, shellProfile, process, listeningPort, fileHash, crontab, setting, launchItemSignature, appSignature, sshKey, profile, browserExtension, softwareVersion, npmPackage, projectFile, systemExtension, xprotect
}

public enum SystemSetting: String, Codable, Sendable {
    case sip, gatekeeper, firewall
}

public enum SoftwareProduct: String, Codable, Sendable, CaseIterable {
    case node, php, python, openssl, git, ruby

    var hasLetterReleases: Bool {
        self == .openssl
    }
}

public struct VersionRange: Codable, Sendable {
    public let introduced: String
    public let fixed: String?
    public let lastAffected: String?
}

public struct Rule: Codable, Sendable, Identifiable {
    public let id: String
    public let title: String
    public let severity: Severity
    public let category: ThreatCategory
    public let check: CheckKind
    public let patterns: [String]?
    public let paths: [String]?
    public let ports: [Int]?
    public let hashes: [String]?
    public let setting: SystemSetting?
    public let product: SoftwareProduct?
    public let advisory: String?
    public let ranges: [VersionRange]?
    public let packages: [MaliciousPackage]?
    public let files: [String]?
    public let teams: [String]?
    public let bundles: [String]?
    public let minimumVersion: Int?
    public let summary: String?
    public let remedy: String?
    public let references: [String]?
}

public struct Rulebook: Codable, Sendable, SignedPayload {
    public static let supportedSchema = 1
    public static let validity: TimeInterval = 365 * 24 * 3600
    public static let maxValidity: TimeInterval = 400 * 24 * 3600
    public static let versionDateFormat = "yyyyMMdd'99'"
    public static let expiryWarning: TimeInterval = 30 * 24 * 3600
    static let maxRules = 500
    static let maxEntriesPerRule = 200
    static let maxPatternLength = 256
    static let maxPathLength = 1024
    static let maxFileNames = 20
    static let fileNamePattern = #"^(?=.*[A-Za-z0-9])[A-Za-z0-9._*-]{1,64}$"#
    static let maxExplanationLength = 600
    static let maxReferences = 5
    static let maxReferenceLength = 300
    static let advisoryPattern = "^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._-]{1,48}$"
    static let teamIDPattern = "^[A-Z0-9]{10}$"
    static let bundleIDPattern = #"^[A-Za-z0-9-]{1,64}(\.[A-Za-z0-9-]{1,64}){1,7}$"#

    enum CodingKeys: String, CodingKey {
        case schema, version, rules, issued, expires
    }

    public let schema: Int
    public let version: Int
    public let rules: [Rule]
    public let issued: Date?
    public let expires: Date?
    public private(set) var unsupportedRuleCount = 0

    public static func decode(from data: Data) throws -> Rulebook {
        let rulebook: Rulebook
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            rulebook = try decoder.decode(Rulebook.self, from: data)
        } catch {
            throw RulebookError.malformed
        }
        try rulebook.validate()
        return rulebook
    }

    public static func decodePayload(_ data: Data) throws(RuleFeedError) -> Rulebook {
        do {
            return try decode(from: data)
        } catch let error as RulebookError {
            throw .invalidRules(error)
        } catch {
            throw .invalidRules(.malformed)
        }
    }

    public func expiresSoon(now: Date) -> Bool {
        expires.map { $0.timeIntervalSince(now) <= Self.expiryWarning } ?? false
    }

    public func appending(_ extraRules: [Rule]) -> Rulebook {
        Rulebook(schema: schema, version: version, rules: rules + extraRules, issued: issued, expires: expires, unsupportedRuleCount: unsupportedRuleCount)
    }

    func validate() throws {
        guard schema == Self.supportedSchema else { throw RulebookError.unsupportedSchema(schema) }
        guard version > 0 else { throw RulebookError.invalidVersion }
        guard rules.count + unsupportedRuleCount <= Self.maxRules else { throw RulebookError.tooManyRules }
        var seenIDs = Set<String>()
        for rule in rules {
            guard seenIDs.insert(rule.id).inserted else { throw RulebookError.duplicateID(rule.id) }
            if let reason = Self.problem(in: rule) {
                throw RulebookError.invalidRule(id: rule.id, reason: reason)
            }
        }
    }

    static func problem(in rule: Rule) -> String? {
        if rule.id.range(of: #"^[a-z0-9][a-z0-9.-]{0,63}$"#, options: .regularExpression) == nil {
            return "id must be 1-64 lowercase letters, digits, dots or dashes"
        }
        if rule.title.isEmpty || rule.title.count > 120 {
            return "title must be 1-120 characters"
        }
        if [rule.summary, rule.remedy].contains(where: { ($0?.count ?? 0) > maxExplanationLength }) {
            return "summary and remedy must be at most \(maxExplanationLength) characters"
        }
        if let problem = problem(inReferences: rule.references) {
            return problem
        }
        switch rule.check {
        case .path:
            return problem(inPaths: rule.paths)
        case .launchItem, .shellProfile, .process, .crontab, .browserExtension:
            return problem(inPatterns: rule.patterns)
        case .listeningPort:
            guard let ports = rule.ports, !ports.isEmpty, ports.count <= maxEntriesPerRule else { return "ports must list 1-\(maxEntriesPerRule) ports" }
            return ports.allSatisfy({ (1...65535).contains($0) }) ? nil : "ports must be 1-65535"
        case .fileHash:
            guard let hashes = rule.hashes, !hashes.isEmpty, hashes.count <= maxEntriesPerRule else { return "hashes must list 1-\(maxEntriesPerRule) hashes" }
            let isSHA256 = hashes.allSatisfy { $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
            return isSHA256 ? nil : "hashes must be lowercase SHA-256 hex"
        case .setting:
            return rule.setting == nil ? "setting is required" : nil
        case .launchItemSignature, .appSignature:
            return nil
        case .sshKey, .profile:
            return rule.patterns == nil ? nil : problem(inPatterns: rule.patterns)
        case .softwareVersion:
            return problem(inSoftwareVersion: rule)
        case .npmPackage:
            guard let packages = rule.packages, !packages.isEmpty, packages.count <= maxEntriesPerRule else { return "packages must list 1-\(maxEntriesPerRule) packages" }
            return packages.lazy.compactMap(problem(inPackage:)).first
        case .projectFile:
            return problem(inFileNames: rule.files) ?? problem(inPatterns: rule.patterns)
        case .systemExtension:
            return problem(inVendors: rule)
        case .xprotect:
            return (rule.minimumVersion ?? 0) > 0 ? nil : "minimumVersion must be a positive XProtect version such as 5300"
        }
    }

    static func problem(inVendors rule: Rule) -> String? {
        if let teams = rule.teams {
            guard !teams.isEmpty, teams.count <= maxEntriesPerRule else { return "teams must list 1-\(maxEntriesPerRule) team IDs" }
            if let team = teams.first(where: { $0.range(of: teamIDPattern, options: .regularExpression) == nil }) {
                return "team \(team) must be a 10-character Apple team ID such as W5364U7YZB"
            }
        }
        if let bundles = rule.bundles {
            guard !bundles.isEmpty, bundles.count <= maxEntriesPerRule else { return "bundles must list 1-\(maxEntriesPerRule) bundle IDs" }
            if let bundle = bundles.first(where: { $0.range(of: bundleIDPattern, options: .regularExpression) == nil }) {
                return "bundle \(bundle) must be a bundle ID of 2-8 parts such as io.macfuse"
            }
        }
        return nil
    }

    static func problem(inPackage package: MaliciousPackage) -> String? {
        guard NpmPackage.isName(package.name) else { return "package name must be an npm name such as chalk or @scope/name" }
        guard package.advisory.range(of: advisoryPattern, options: .regularExpression) != nil else { return "advisory must be an id such as MAL-2025-46969" }
        guard case .only(let versions) = package.versions else { return nil }
        guard !versions.isEmpty, versions.count <= NpmPackage.maxVersionsPerPackage else { return "versions must be \"*\" or list 1-\(NpmPackage.maxVersionsPerPackage) versions" }
        return versions.allSatisfy(NpmPackage.isVersion) ? nil : "versions must be semver versions such as 1.2.3"
    }

    static func problem(inSoftwareVersion rule: Rule) -> String? {
        guard let product = rule.product else { return "product is required" }
        guard let advisory = rule.advisory, advisory.range(of: advisoryPattern, options: .regularExpression) != nil else {
            return "advisory must be an id such as CVE-2024-21892"
        }
        guard let ranges = rule.ranges, !ranges.isEmpty, ranges.count <= maxEntriesPerRule else { return "ranges must list 1-\(maxEntriesPerRule) ranges" }
        for range in ranges {
            guard range.fixed == nil || range.lastAffected == nil else { return "a range sets fixed or lastAffected, not both" }
            guard let introduced = SoftwareVersion(range.introduced, for: product) else { return "introduced must be a \(product.rawValue) version such as 1.2.3" }
            if let fixed = range.fixed {
                guard let end = SoftwareVersion(fixed, for: product), introduced < end else { return "fixed must be a \(product.rawValue) version after introduced" }
            }
            if let lastAffected = range.lastAffected {
                guard let end = SoftwareVersion(lastAffected, for: product), introduced <= end else { return "lastAffected must be a \(product.rawValue) version from introduced on" }
            }
        }
        return nil
    }

    static func problem(inReferences references: [String]?) -> String? {
        guard let references else { return nil }
        guard references.count <= maxReferences else { return "references must list at most \(maxReferences) links" }
        for reference in references {
            guard reference.count <= maxReferenceLength, let url = URL(string: reference), url.scheme == "https", url.host() != nil else {
                return "reference \(reference) must be an https link"
            }
        }
        return nil
    }

    static func problem(inPaths paths: [String]?) -> String? {
        guard let paths, !paths.isEmpty, paths.count <= maxEntriesPerRule else { return "paths must list 1-\(maxEntriesPerRule) paths" }
        for path in paths {
            let isRooted = path.hasPrefix("/") || path.hasPrefix("~/")
            let hasParentStep = path.split(separator: "/").contains("..")
            if !isRooted || hasParentStep || path.contains("\0") || path.count > maxPathLength {
                return "path \(path) must start with / or ~/ and contain no .."
            }
        }
        return nil
    }

    static func problem(inFileNames names: [String]?) -> String? {
        guard let names, !names.isEmpty, names.count <= maxFileNames else { return "files must list 1-\(maxFileNames) file names" }
        for name in names where name.contains("..") || name.range(of: fileNamePattern, options: .regularExpression) == nil {
            return "file \(name) must be a file name of letters, digits, ., -, _ and * only"
        }
        return nil
    }

    static func problem(inPatterns patterns: [String]?) -> String? {
        guard let patterns, !patterns.isEmpty, patterns.count <= maxEntriesPerRule else { return "patterns must list 1-\(maxEntriesPerRule) patterns" }
        for pattern in patterns {
            guard pattern.count <= maxPatternLength else { return "pattern longer than \(maxPatternLength) characters" }
            guard (try? NSRegularExpression(pattern: pattern)) != nil else { return "pattern \(pattern) is not a valid regex" }
        }
        return nil
    }
}

extension Rulebook {
    private struct RuleHeader: Decodable {
        let check: String
    }

    private struct SupportedRule: Decodable {
        let rule: Rule?

        init(from decoder: any Decoder) throws {
            let header = try RuleHeader(from: decoder)
            rule = CheckKind(rawValue: header.check) == nil ? nil : try Rule(from: decoder)
        }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(Int.self, forKey: .schema)
        version = try container.decode(Int.self, forKey: .version)
        issued = try container.decodeIfPresent(Date.self, forKey: .issued)
        expires = try container.decodeIfPresent(Date.self, forKey: .expires)
        let decoded = try container.decode([SupportedRule].self, forKey: .rules)
        rules = decoded.compactMap(\.rule)
        unsupportedRuleCount = decoded.count - rules.count
    }
}

public enum RulebookError: LocalizedError, Equatable {
    case malformed
    case unsupportedSchema(Int)
    case invalidVersion
    case tooManyRules
    case duplicateID(String)
    case invalidRule(id: String, reason: String)

    public var errorDescription: String? {
        switch self {
        case .malformed: "Rules file is not valid rulebook JSON."
        case .unsupportedSchema(let schema): "Rules schema \(schema) is not supported."
        case .invalidVersion: "Rules version must be a positive number."
        case .tooManyRules: "Rules file has more than \(Rulebook.maxRules) rules."
        case .duplicateID(let id): "Rule id \(id) is used twice."
        case .invalidRule(let id, let reason): "Rule \(id): \(reason)."
        }
    }
}
