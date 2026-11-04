public struct IgnoredFindingGroup: Sendable, Identifiable {
    public let check: CheckKind?
    public let worstSeverity: Severity?
    public let entries: [IgnoredFinding]

    public var id: CheckKind? {
        check
    }

    public static func groups(of entries: [IgnoredFinding]) -> [IgnoredFindingGroup] {
        let known = entries.compactMap { entry in
            entry.check.flatMap { check in entry.severity.map { (entry: entry, check: check, severity: $0) } }
        }
        let groups = FindingGroup.ordered(known, check: \.check, severity: \.severity).map {
            IgnoredFindingGroup(check: $0.check, worstSeverity: $0.worstSeverity, entries: $0.items.map(\.entry))
        }
        let unknown = entries.filter { $0.check == nil || $0.severity == nil }
        return unknown.isEmpty ? groups : groups + [IgnoredFindingGroup(check: nil, worstSeverity: nil, entries: unknown)]
    }

    public func removed(from entries: [IgnoredFinding]) -> [IgnoredFinding] {
        let ids = Set(self.entries.map(\.id))
        return entries.filter { !ids.contains($0.id) }
    }
}
