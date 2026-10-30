import Foundation
import Testing
@testable import BluehatCore

struct ScanScheduleTests {
    let now = Date(timeIntervalSinceReferenceDate: 800_000_000)

    @Test func offIsNeverDue() {
        #expect(!ScanSchedule.off.isDue(lastScan: nil, now: now))
        #expect(ScanSchedule.off.nextScan(after: now, now: now) == nil)
    }

    @Test func firstScanIsDueImmediately() {
        #expect(ScanSchedule.daily.isDue(lastScan: nil, now: now))
    }

    @Test func dueOnlyAfterInterval() {
        let lastScan = now.addingTimeInterval(-5 * 3600)
        #expect(!ScanSchedule.everySixHours.isDue(lastScan: lastScan, now: now))
        #expect(ScanSchedule.hourly.isDue(lastScan: lastScan, now: now))
        #expect(ScanSchedule.everySixHours.nextScan(after: lastScan, now: now) == now.addingTimeInterval(3600))
    }
}
