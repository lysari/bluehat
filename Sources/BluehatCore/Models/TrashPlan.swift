public struct TrashPlan: Sendable {
    public struct NotMoved: Sendable, Equatable, Identifiable {
        public let path: String
        public let reason: String

        public var id: String {
            path
        }
    }

    public struct Result: Sendable, Equatable {
        public let moved: [String]
        public let notMoved: [NotMoved]
    }

    static let protectedReason = "It's in a protected system location."

    public let movable: [Installation]
    public let refused: [Installation]
    public let findingCount: Int
    public let movableFindingCount: Int
    public let otherFindingCount: Int

    public init(findings: [Finding], installs: [Installation]) {
        var copies: [Installation] = []
        var countsByPath: [String: Int] = [:]
        for finding in findings where finding.rule.check == .softwareVersion {
            guard let path = finding.path, let copy = Scanner.installation(at: path, in: installs), copy.isTrashable else { continue }
            if countsByPath[path] == nil { copies.append(copy) }
            countsByPath[path, default: 0] += 1
        }
        let protected = Set(copies.map(\.path).filter(ProtectedLocation.contains))
        movable = copies.filter { !protected.contains($0.path) }
        refused = copies.filter { protected.contains($0.path) }
        findingCount = countsByPath.values.reduce(0, +)
        movableFindingCount = countsByPath.filter { !protected.contains($0.key) }.values.reduce(0, +)
        otherFindingCount = findings.count - findingCount
    }

    public func run(move: (Installation) throws -> Void) -> Result {
        var moved: [String] = []
        var notMoved = refused.map { NotMoved(path: $0.displayPath, reason: Self.protectedReason) }
        for copy in movable {
            guard !ProtectedLocation.contains(copy.path) else {
                notMoved.append(NotMoved(path: copy.displayPath, reason: Self.protectedReason))
                continue
            }
            do {
                try move(copy)
                moved.append(copy.displayPath)
            } catch {
                notMoved.append(NotMoved(path: copy.displayPath, reason: error.localizedDescription))
            }
        }
        return Result(moved: moved, notMoved: notMoved)
    }
}
