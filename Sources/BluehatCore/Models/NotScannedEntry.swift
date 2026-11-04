import Foundation

public enum NotScannedReason: Int, CaseIterable, Sendable, Identifiable {
    case noPermission, couldNotRead, overSizeLimit, partlyRead, overCountLimit, overDepthLimit, cloudOnly, timedOut, signatureCheckSkipped, gatekeeperNotAsked, filePatternNotOpened, notSafeToParse, couldNotParse

    public var id: Self {
        self
    }

    public var title: String {
        switch self {
        case .noPermission: "No permission"
        case .couldNotRead: "Could not read"
        case .overSizeLimit: "Over the size limit"
        case .partlyRead: "Partly read"
        case .overCountLimit: "Over a count limit"
        case .overDepthLimit: "Too many folders deep"
        case .cloudOnly: "Cloud-only, not downloaded"
        case .timedOut: "Timed out"
        case .signatureCheckSkipped: "Signature check skipped"
        case .gatekeeperNotAsked: "Gatekeeper not asked yet"
        case .filePatternNotOpened: "File pattern not opened"
        case .notSafeToParse: "Not safe to parse"
        case .couldNotParse: "Could not parse"
        }
    }

    init?(folderError error: Int32) {
        switch error {
        case ENOENT, ENOTDIR, EDEADLK: return nil
        case EACCES, EPERM: self = .noPermission
        case ETIMEDOUT: self = .timedOut
        default: self = .couldNotRead
        }
    }

    init?(listingError error: any Error) {
        switch (error as? CocoaError)?.code {
        case .fileNoSuchFile, .fileReadNoSuchFile: return nil
        case .fileReadNoPermission: self = .noPermission
        default: self = .couldNotRead
        }
    }
}

public struct NotScannedEntry: Sendable, Identifiable {
    public let id = UUID()
    public let reason: NotScannedReason
    public let path: String?
    public let name: String
    public let explanation: String
    public let isInHome: Bool

    init(reason: NotScannedReason, path: String, explanation: String? = nil, limits: ScanLimits = .defaults, home: String = NSHomeDirectory()) {
        self.reason = reason
        self.path = path
        self.explanation = explanation ?? reason.title
        name = Finding.clip(Finding.displayable(NSString(string: path).abbreviatingWithTildeInPath), limits: limits)
        let location = VolumeWalk.withoutDataVolume(path)
        isInHome = location == home || location.hasPrefix(home + "/")
    }

    init(reason: NotScannedReason, summary: String, explanation: String? = nil, limits: ScanLimits = .defaults) {
        self.reason = reason
        path = nil
        self.explanation = explanation ?? reason.title
        name = Finding.clip(Finding.displayable(summary), limits: limits)
        isInHome = false
    }

    static func oversized(path: String, size: Int, limit: Int, limits: ScanLimits = .defaults) -> NotScannedEntry {
        NotScannedEntry(reason: .overSizeLimit, path: path, explanation: "\(NotScannedReason.overSizeLimit.title) (\(megabytes(size)), limit \(megabytes(limit)))", limits: limits)
    }

    static func readOnlyStart(path: String, check: String, limits: ScanLimits = .defaults) -> NotScannedEntry {
        NotScannedEntry(reason: .partlyRead, path: path, explanation: "Only the first \(megabytes(limits[.maxReadBytes])) was read (\(check))", limits: limits)
    }

    static func notParsed(path: String, check: String, problem: any Error, limits: ScanLimits = .defaults) -> NotScannedEntry {
        NotScannedEntry(reason: .notSafeToParse, path: path, explanation: "\(problem.localizedDescription) (\(check))", limits: limits)
    }

    static func megabytes(_ bytes: Int) -> String {
        let value = Double(bytes) / Double(ScanLimit.bytesPerMegabyte)
        return "\(value.formatted(.number.precision(.fractionLength(0...2)))) MB"
    }
}
