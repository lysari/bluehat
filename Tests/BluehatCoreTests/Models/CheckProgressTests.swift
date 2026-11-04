import Testing
@testable import BluehatCore

struct CheckProgressTests {
    let areas: [CheckKind] = [.path, .launchItem, .npmPackage]

    func progress(_ stage: CheckProgress.Stage, kind: ScanKind = .normal, areas: [CheckKind]? = nil, finished: Set<CheckKind> = []) -> CheckProgress {
        CheckProgress(stage: stage, kind: kind, areas: areas ?? self.areas, finishedAreas: finished)
    }

    func runningRows(_ progress: CheckProgress) -> [CheckKind] {
        CheckKind.allCases.filter { progress.status(of: $0) == .running }
    }

    @Test func exactlyOneCheckRunsAtATimeInScannerOrder() {
        #expect(runningRows(progress(.checking)) == [.path])
        #expect(runningRows(progress(.checking, finished: [.path])) == [.launchItem])
        #expect(runningRows(progress(.checking, finished: [.path, .launchItem])) == [.npmPackage])
        #expect(runningRows(progress(.checking, finished: [.path, .launchItem, .npmPackage])).isEmpty)
    }

    @Test func statusSeparatesFinishedRunningWaitingAndAreasWithNoRules() {
        let midScan = progress(.checking, finished: [.path])
        #expect(midScan.status(of: .path) == .finished)
        #expect(midScan.status(of: .launchItem) == .running)
        #expect(midScan.status(of: .npmPackage) == .waiting)
        #expect(midScan.status(of: .notarization) == .nothingToCheck)
    }

    @Test func anAreaWithNoRulesNeverRuns() {
        let scan = progress(.checking, areas: [.launchItem, .process])
        #expect(scan.currentArea == .launchItem)
        #expect(scan.status(of: .path) == .nothingToCheck)
    }

    @Test func nothingRunsWhileRulesLoad() {
        let loading = progress(.loadingRules, kind: .deep)
        #expect(loading.currentArea == nil)
        #expect(!loading.isWalkingDisk)
        #expect(runningRows(loading).isEmpty)
        #expect(loading.status(of: .path) == .waiting)
        #expect(loading.diskWalkStatus == .waiting)
    }

    @Test func aCancelledOrFailedScanLeavesNothingRunning() {
        let backToIdle = progress(.idle, kind: .deep)
        #expect(runningRows(backToIdle).isEmpty)
        #expect(backToIdle.diskWalkStatus != .running)
        #expect(backToIdle.status(of: .path) == .notRun)
        #expect(!backToIdle.showsDiskWalk)

        let backToLastResults = progress(.finished, kind: .deep, finished: Set(areas))
        #expect(runningRows(backToLastResults).isEmpty)
        #expect(backToLastResults.diskWalkStatus == .finished)
    }

    @Test func aFinishedScanHasNoRunningCheck() {
        let finished = progress(.finished, finished: Set(areas))
        #expect(finished.currentArea == nil)
        #expect(runningRows(finished).isEmpty)
        #expect(finished.status(of: .launchItem) == .finished)
    }

    @Test func theDiskWalkRunsOnlyAfterEveryCheckOfADeepScan() {
        #expect(!progress(.checking, kind: .deep).isWalkingDisk)
        #expect(progress(.checking, kind: .deep).diskWalkStatus == .waiting)
        #expect(!progress(.checking, kind: .deep, finished: [.path, .launchItem]).isWalkingDisk)

        let walking = progress(.checking, kind: .deep, finished: Set(areas))
        #expect(walking.isWalkingDisk)
        #expect(walking.diskWalkStatus == .running)
        #expect(runningRows(walking).isEmpty)
        #expect(progress(.finished, kind: .deep, finished: Set(areas)).diskWalkStatus == .finished)
    }

    @Test func aStoppedWalkIsNotShownAsFinished() {
        let stopped = CheckProgress(stage: .finished, kind: .deep, areas: areas, finishedAreas: Set(areas), wasStoppedAtMemoryLimit: true)
        #expect(stopped.diskWalkStatus == .stoppedEarly)
        #expect(areas.allSatisfy { stopped.status(of: $0) == .finished })
    }

    @Test func theDiskWalkShowsOnlyForADeepScan() {
        #expect(!progress(.checking).showsDiskWalk)
        #expect(!progress(.finished, finished: Set(areas)).showsDiskWalk)
        #expect(!progress(.idle).showsDiskWalk)
        #expect(progress(.loadingRules, kind: .deep).showsDiskWalk)
        #expect(progress(.checking, kind: .deep).showsDiskWalk)
        #expect(progress(.finished, kind: .deep, finished: Set(areas)).showsDiskWalk)
    }

    @Test func aNormalScanNeverWalksTheDisk() {
        let done = progress(.checking, finished: Set(areas))
        #expect(!done.isWalkingDisk)
        #expect(done.currentArea == nil)
    }

    @Test func aRulebookWithNothingForTheWalkDoesNotShowItRunning() {
        let finished: Set<CheckKind> = [.path]
        let scan = progress(.checking, kind: .deep, areas: [.path], finished: finished)
        #expect(!scan.isWalkingDisk)
        #expect(scan.diskWalkStatus == .nothingToCheck)
        #expect(progress(.checking, kind: .deep, areas: [.projectFile], finished: [.projectFile]).isWalkingDisk)
    }
}
