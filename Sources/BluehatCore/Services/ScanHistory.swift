import Foundation

public struct ScanHistory: Sendable {
    public static let maxRecords = 30
    static let maxFileBytes = 20_000_000

    public private(set) var records: [ScanRecord]
    let fileURL: URL

    public init(fileURL: URL = Self.defaultFileURL) {
        self.fileURL = fileURL
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        records = RegularFile.read(atPath: fileURL.path, maxBytes: Self.maxFileBytes, followingSymlinks: false).flatMap { try? decoder.decode([ScanRecord].self, from: $0) } ?? []
    }

    public static var defaultFileURL: URL {
        URL.applicationSupportDirectory.appending(components: "Bluehat", "history.json")
    }

    public var latestChanges: ScanChanges? {
        records.first.map { $0.changes(since: records.dropFirst().first) }
    }

    public func changes(for record: ScanRecord) -> ScanChanges {
        guard let index = records.firstIndex(where: { $0.id == record.id }) else { return ScanChanges(new: [], resolved: []) }
        return record.changes(since: records.dropFirst(index + 1).first)
    }

    public mutating func append(_ record: ScanRecord) throws {
        records = Array(([record] + records).prefix(Self.maxRecords))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(records).write(to: fileURL, options: .atomic)
    }
}
