import Foundation

public struct ScanHistory: Sendable {
    public private(set) var records: [ScanRecord]
    let fileURL: URL

    public init(fileURL: URL = Self.defaultFileURL, limits: ScanLimits = .defaults) {
        self.fileURL = fileURL
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let readLimit = max(limits[.maxHistoryFileBytes], ScanLimit.maxHistoryFileBytes.defaultValue)
        records = RegularFile.read(atPath: fileURL.path, maxBytes: readLimit, followingSymlinks: false).flatMap { try? decoder.decode([ScanRecord].self, from: $0) } ?? []
    }

    public static var defaultFileURL: URL {
        URL.applicationSupportDirectory.appending(components: "Bluehat", "history.json")
    }

    public var latestChanges: ScanChanges? {
        records.first.map(changes(for:))
    }

    public func changes(for record: ScanRecord) -> ScanChanges {
        guard let index = records.firstIndex(where: { $0.id == record.id }) else { return ScanChanges(new: [], resolved: []) }
        return record.changes(since: records.dropFirst(index + 1).first { $0.kind == record.kind && !$0.wasStoppedAtMemoryLimit })
    }

    public mutating func append(_ record: ScanRecord, limits: ScanLimits = .defaults) throws {
        records = Array(([record] + records).prefix(limits[.maxHistoryRecords]))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        var encoded = try encoder.encode(records)
        while encoded.count > limits[.maxHistoryFileBytes], records.count > 1 {
            records.removeLast()
            encoded = try encoder.encode(records)
        }
        try encoded.write(to: fileURL, options: .atomic)
    }
}
