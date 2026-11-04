import Foundation
import Testing
@testable import BluehatCore

struct SignatureChecksTests {
    static let trapLimit: TimeInterval = 0.3
    static let bounded: Duration = .seconds(10)

    let directory = FileManager.default.temporaryDirectory.appending(path: "bluehat-signature-checks-\(UUID().uuidString)")

    init() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func trapChecks(maxStuckPaths: Int = 5) -> SignatureChecks {
        SignatureChecks(openLimit: Self.trapLimit, checkLimit: Self.trapLimit, maxStuckPaths: maxStuckPaths)
    }

    func fifoApp(_ name: String) throws -> URL {
        let fifo = directory.appending(path: name)
        #expect(mkfifo(fifo.path, 0o600) == 0)
        return fifo
    }

    func bundleWithFifoExecutable(_ name: String) throws -> (bundle: URL, fifo: URL) {
        let bundle = directory.appending(path: "\(name).app")
        let executables = bundle.appending(path: "Contents/MacOS")
        try FileManager.default.createDirectory(at: executables, withIntermediateDirectories: true)
        let plist: [String: Any] = ["CFBundleExecutable": name, "CFBundleIdentifier": "test.bluehat.\(name)", "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: bundle.appending(path: "Contents/Info.plist"))
        let fifo = executables.appending(path: name)
        #expect(mkfifo(fifo.path, 0o600) == 0)
        return (bundle, fifo)
    }

    func unblock(_ fifo: URL) {
        for _ in 0..<50 {
            let writer = open(fifo.path, O_WRONLY | O_NONBLOCK)
            guard writer >= 0 else { return }
            close(writer)
            usleep(20_000)
        }
    }

    func waitUntilUnblocked(_ path: String) -> Bool {
        for _ in 0..<250 {
            if !SignatureChecks.stillBlockedPaths.withLock({ $0.contains(path) }) { return true }
            usleep(20_000)
        }
        return false
    }

    func rule() -> Rule {
        Rule(id: "app.test", title: "Test", severity: .medium, category: .malware, check: .appSignature, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    @Test func fifoNamedAsAnAppIsReportedInBoundedTime() throws {
        let fifo = try fifoApp("x.app")
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.signatureProblem(at: fifo, checks: trapChecks()) == Scanner.unfinishedSignatureProblem)
        #expect(clock.now - start < Self.bounded)
    }

    @Test func bundleWithFifoExecutableIsReportedInBoundedTime() throws {
        let trap = try bundleWithFifoExecutable("x")
        defer {
            unblock(trap.fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.signatureProblem(at: trap.bundle, checks: trapChecks()) == Scanner.unfinishedSignatureProblem)
        #expect(clock.now - start < Self.bounded)
    }

    @Test func fifoAppBecomesAFinding() throws {
        let fifo = try fifoApp("x.app")
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let findings = Scanner.appSignatureFindings([rule()], apps: [fifo], checks: trapChecks())
        #expect(findings.map(\.detail) == ["x.app \(Scanner.unfinishedSignatureProblem)"])
        #expect(findings.map(\.path) == [fifo.path])
    }

    @Test func fifoAsALaunchItemProgramBecomesAFinding() throws {
        let fifo = try fifoApp("agent")
        let agents = directory.appending(path: "agents")
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        let plist = agents.appending(path: "evil.plist")
        try PropertyListSerialization.data(fromPropertyList: ["Program": fifo.path], format: .xml, options: 0).write(to: plist)
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let items = Scanner.launchItemCommands(in: [agents.path]).items
        let clock = ContinuousClock()
        let start = clock.now
        let findings = Scanner.launchItemSignatureFindings([rule()], items: items, checks: trapChecks())
        #expect(clock.now - start < Self.bounded)
        #expect(findings.map(\.detail) == ["\(fifo.path) \(Scanner.unfinishedSignatureProblem)"])
        #expect(findings.map(\.path) == [plist.path])
    }

    @Test func notarizationSkipsAStuckAppAndListsIt() throws {
        let fifo = try fifoApp("x.app")
        let normal = directory.appending(path: "normal")
        try Data("#!/bin/sh\n".utf8).write(to: normal)
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let checks = trapChecks()
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.developerIDApp(at: fifo, checks: checks) == nil)
        #expect(clock.now - start < Self.bounded)
        #expect(Scanner.developerIDApp(at: normal, checks: SignatureChecks()) == nil)
        let entries = checks.notScannedEntries()
        #expect(entries.map(\.path) == [fifo.path])
        #expect(entries.map(\.reason) == [.timedOut])
        #expect(entries.first?.explanation == "Reading it never finished, so its signature and notarization weren't checked")
    }

    @Test func checksPastTheLimitAreSkippedAndCounted() throws {
        let fifos = try (0..<4).map { try fifoApp("trap\($0).app") }
        let normal = directory.appending(path: "normal")
        try Data("#!/bin/sh\n".utf8).write(to: normal)
        defer {
            fifos.forEach(unblock)
            try? FileManager.default.removeItem(at: directory)
        }
        let checks = trapChecks(maxStuckPaths: 2)
        #expect(checks.notScannedEntries().isEmpty)
        let clock = ContinuousClock()
        let start = clock.now
        #expect(fifos.map { Scanner.signatureProblem(at: $0, checks: checks) } == [Scanner.unfinishedSignatureProblem, Scanner.unfinishedSignatureProblem, nil, nil])
        #expect(Scanner.signatureProblem(at: normal, checks: checks) == nil)
        #expect(clock.now - start < Self.bounded)
        #expect(checks.stuckPaths == Set(fifos.prefix(2).map(\.path)))
        #expect(checks.skippedPaths == Set(fifos.suffix(2).map(\.path) + [normal.path]))
        let skipped = checks.notScannedEntries().filter { $0.reason == .signatureCheckSkipped }
        #expect(skipped.count == 3)
        #expect(skipped.allSatisfy { $0.explanation == "Signature checks stopped after 2 items couldn't be read" })
    }

    @Test func aDeepScanCannotRaiseTheStuckPathLimit() {
        #expect(Scanner(kind: .normal).signatureChecks.maxStuckPaths == ScanLimits.defaults[.maxStuckPathsPerScan])
        #expect(Scanner(kind: .deep).signatureChecks.maxStuckPaths == ScanLimits.defaults[.maxStuckPathsPerScan])
    }

    @Test func aCancelledScanStartsNoCheck() throws {
        let cancellation = ScanCancellation()
        cancellation.cancel()
        let checks = SignatureChecks(cancellation: cancellation)
        #expect(Scanner.signatureProblem(at: URL(fileURLWithPath: "/bin/ls"), checks: checks) == nil)
        #expect(checks.skippedPaths == ["/bin/ls"])
        #expect(checks.stuckPaths.isEmpty)
    }

    @Test func cancellingStopsWaitingForACheckThatIsStuck() throws {
        let fifo = try fifoApp("x.app")
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let cancellation = ScanCancellation()
        let checks = SignatureChecks(openLimit: 60, checkLimit: 60, maxStuckPaths: ScanLimits.defaults[.maxStuckPathsPerScan], cancellation: cancellation)
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.trapLimit) { cancellation.cancel() }
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.signatureProblem(at: fifo, checks: checks) == Scanner.unfinishedSignatureProblem)
        #expect(clock.now - start < Self.bounded)
    }

    @Test func thousandsOfTrapsCannotLeakAThreadEach() throws {
        let fifos = try (0..<200).map { try fifoApp("trap\($0).app") }
        defer {
            fifos.forEach(unblock)
            try? FileManager.default.removeItem(at: directory)
        }
        let checks = trapChecks(maxStuckPaths: 2)
        let clock = ContinuousClock()
        let start = clock.now
        let findings = Scanner.appSignatureFindings([rule()], apps: fifos, checks: checks)
        #expect(clock.now - start < Self.bounded)
        #expect(findings.count <= 2 + ProcessInfo.processInfo.activeProcessorCount)
        #expect(findings.count + checks.skippedPaths.count == fifos.count)
        #expect(checks.notScannedEntries().count { $0.reason == .signatureCheckSkipped } == fifos.count - findings.count)
    }

    @Test func aStuckPathCheckedAgainCountsOnceAndDoesNotWaitAgain() throws {
        let fifo = try fifoApp("x.app")
        let other = try fifoApp("y.app")
        defer {
            unblock(fifo)
            unblock(other)
            try? FileManager.default.removeItem(at: directory)
        }
        let checks = SignatureChecks(openLimit: Self.trapLimit, checkLimit: Self.trapLimit, maxStuckPaths: 2)
        #expect(Scanner.signatureProblem(at: fifo, checks: checks) == Scanner.unfinishedSignatureProblem)
        let patient = SignatureChecks(openLimit: 60, checkLimit: 60, maxStuckPaths: 2)
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.developerIDApp(at: fifo, checks: patient) == nil)
        #expect(Scanner.signatureProblem(at: fifo, checks: patient) == Scanner.unfinishedSignatureProblem)
        #expect(clock.now - start < Self.bounded)
        #expect(patient.stuckPaths == [fifo.path])
        #expect(patient.skippedPaths.isEmpty)
        #expect(Scanner.signatureProblem(at: fifo, checks: checks) == Scanner.unfinishedSignatureProblem)
        #expect(checks.stuckPaths == [fifo.path])
        #expect(Scanner.signatureProblem(at: other, checks: checks) == Scanner.unfinishedSignatureProblem)
        #expect(checks.skippedPaths.isEmpty)
    }

    @Test func aNewScanDoesNotStartAnotherThreadOnAPathStillBlocked() throws {
        let fifo = try fifoApp("x.app")
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        #expect(Scanner.signatureProblem(at: fifo, checks: trapChecks()) == Scanner.unfinishedSignatureProblem)
        #expect(SignatureChecks.stillBlockedPaths.withLock { $0.contains(fifo.path) })
        let nextScan = SignatureChecks(openLimit: 60, checkLimit: 60, maxStuckPaths: 5)
        let clock = ContinuousClock()
        let start = clock.now
        #expect(Scanner.signatureProblem(at: fifo, checks: nextScan) == Scanner.unfinishedSignatureProblem)
        #expect(clock.now - start < Self.bounded)
    }

    @Test func aPathIsCheckedAgainOnceItsThreadFinished() throws {
        let fifo = try fifoApp("x.app")
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        let checks = trapChecks()
        #expect(Scanner.signatureProblem(at: fifo, checks: checks) == Scanner.unfinishedSignatureProblem)
        unblock(fifo)
        #expect(waitUntilUnblocked(fifo.path))
        try FileManager.default.removeItem(at: fifo)
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: fifo)
        #expect(Scanner.signatureProblem(at: fifo, checks: SignatureChecks()) == "is not signed")
    }

    @Test func normalFilesKeepTheirResultsWhileAnotherCheckIsStuck() throws {
        let fifo = try fifoApp("x.app")
        let script = directory.appending(path: "payload")
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: script)
        defer {
            unblock(fifo)
            try? FileManager.default.removeItem(at: directory)
        }
        #expect(Scanner.signatureProblem(at: fifo, checks: trapChecks()) == Scanner.unfinishedSignatureProblem)
        let checks = SignatureChecks()
        #expect(Scanner.signatureProblem(at: script, checks: checks) == "is not signed")
        #expect(Scanner.signatureProblem(at: script, checks: checks) == "is not signed")
        #expect(Scanner.signatureProblem(at: URL(fileURLWithPath: "/bin/ls"), checks: checks) == nil)
        #expect(Scanner.developerIDApp(at: URL(fileURLWithPath: "/bin/ls"), checks: checks) == nil)
        #expect(checks.stuckPaths.isEmpty)
        #expect(checks.notScannedEntries().isEmpty)
    }

    @Test func checksAppsConcurrentlyWithTheirUsualResults() throws {
        let scripts = try (0..<8).map { index -> URL in
            let script = directory.appending(path: "payload\(index)")
            try Data("#!/bin/sh\necho hi\n".utf8).write(to: script)
            return script
        }
        defer { try? FileManager.default.removeItem(at: directory) }
        let checks = SignatureChecks()
        let findings = Scanner.appSignatureFindings([rule()], apps: scripts + [URL(fileURLWithPath: "/bin/ls")], checks: checks)
        #expect(findings.map(\.path) == scripts.map(\.path))
        #expect(findings.allSatisfy { $0.detail.hasSuffix(" is not signed") })
        #expect(checks.stuckPaths.isEmpty)
    }
}
