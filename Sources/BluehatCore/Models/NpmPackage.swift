import Foundation

enum NpmPackage {
    static let maxNameLength = 214
    static let maxVersionLength = 256
    static let maxVersionsPerPackage = 100

    static func isName(_ name: String) -> Bool {
        name.utf8.count <= maxNameLength && name.wholeMatch(of: /(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*/) != nil
    }

    static func isVersion(_ version: String) -> Bool {
        version.utf8.count <= maxVersionLength
            && version.wholeMatch(of: /(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?/) != nil
    }
}

public enum PackageVersions: Codable, Sendable, Equatable {
    case every
    case only([String])

    static let everyMarker = "*"

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let marker = try? container.decode(String.self) {
            guard marker == Self.everyMarker else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "versions must be \"*\" or a list of versions")
            }
            self = .every
        } else {
            self = .only(try container.decode([String].self))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .every: try container.encode(Self.everyMarker)
        case .only(let versions): try container.encode(versions)
        }
    }

    func contains(_ version: String) -> Bool {
        switch self {
        case .every: true
        case .only(let versions): versions.contains(version)
        }
    }
}

public struct MaliciousPackage: Codable, Sendable, Equatable {
    public let name: String
    public let versions: PackageVersions
    public let advisory: String
}

struct InstalledPackage: Hashable, Sendable {
    let name: String
    let version: String
    let path: String

    init?(name: String, version: String, path: String) {
        guard NpmPackage.isName(name), NpmPackage.isVersion(version) else { return nil }
        self.name = name
        self.version = version
        self.path = path
    }
}
