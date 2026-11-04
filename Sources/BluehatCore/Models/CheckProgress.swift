public enum CheckStatus: Sendable, Equatable {
    case notRun, waiting, running, finished, stoppedEarly, nothingToCheck
}

public struct CheckProgress: Sendable, Equatable {
    public enum Stage: Sendable {
        case idle, loadingRules, checking, finished
    }

    public let stage: Stage
    public let kind: ScanKind
    public let areas: [CheckKind]
    public let finishedAreas: Set<CheckKind>
    public let wasStoppedAtMemoryLimit: Bool

    public init(stage: Stage, kind: ScanKind, areas: [CheckKind], finishedAreas: Set<CheckKind>, wasStoppedAtMemoryLimit: Bool = false) {
        self.stage = stage
        self.kind = kind
        self.areas = areas
        self.finishedAreas = finishedAreas
        self.wasStoppedAtMemoryLimit = wasStoppedAtMemoryLimit
    }

    public var currentArea: CheckKind? {
        stage == .checking ? areas.first { !finishedAreas.contains($0) } : nil
    }

    public var showsDiskWalk: Bool {
        kind == .deep && stage != .idle
    }

    public var isWalkingDisk: Bool {
        stage == .checking && kind == .deep && hasWalkRules && currentArea == nil
    }

    public var diskWalkStatus: CheckStatus {
        guard hasWalkRules else { return .nothingToCheck }
        if isWalkingDisk { return .running }
        switch stage {
        case .idle: return .notRun
        case .loadingRules, .checking: return .waiting
        case .finished: return wasStoppedAtMemoryLimit ? .stoppedEarly : .finished
        }
    }

    public func status(of area: CheckKind) -> CheckStatus {
        guard areas.contains(area) else { return .nothingToCheck }
        if area == currentArea { return .running }
        if finishedAreas.contains(area) { return .finished }
        return stage == .idle ? .notRun : .waiting
    }

    private var hasWalkRules: Bool {
        areas.contains(.npmPackage) || areas.contains(.projectFile)
    }
}
