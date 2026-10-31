import Foundation

struct NotarizationCache: Sendable {
    struct Verdict: Codable, Sendable, Equatable {
        let cdhash: String
        let isNotarized: Bool
    }

    static let maxFileBytes = 5_000_000

    private(set) var verdicts: [String: Verdict]
    let fileURL: URL

    init(fileURL: URL = Self.defaultFileURL) {
        self.fileURL = fileURL
        verdicts = RegularFile.read(atPath: fileURL.path, maxBytes: Self.maxFileBytes, followingSymlinks: false).flatMap { try? JSONDecoder().decode([String: Verdict].self, from: $0) } ?? [:]
    }

    static var defaultFileURL: URL {
        URL.applicationSupportDirectory.appending(components: "Bluehat", "notarization.json")
    }

    func isNotarized(path: String, cdhash: String) -> Bool? {
        verdicts[path].flatMap { $0.cdhash == cdhash ? $0.isNotarized : nil }
    }

    mutating func record(_ isNotarized: Bool, path: String, cdhash: String) {
        verdicts[path] = Verdict(cdhash: cdhash, isNotarized: isNotarized)
    }

    mutating func keep(paths: Set<String>) {
        verdicts = verdicts.filter { paths.contains($0.key) }
    }

    func save() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(verdicts).write(to: fileURL, options: .atomic)
    }
}
