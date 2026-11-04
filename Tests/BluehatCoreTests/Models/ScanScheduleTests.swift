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

    @Test func lastScanInTheFutureCountsAsNoScan() {
        let future = now.addingTimeInterval(365 * 24 * 3600)
        #expect(ScanSchedule.daily.isDue(lastScan: future, now: now))
        #expect(ScanSchedule.daily.nextScan(after: future, now: now) == now)
    }

    @Test func dueOnlyAfterInterval() {
        let lastScan = now.addingTimeInterval(-5 * 3600)
        #expect(!ScanSchedule.everySixHours.isDue(lastScan: lastScan, now: now))
        #expect(ScanSchedule.hourly.isDue(lastScan: lastScan, now: now))
        #expect(ScanSchedule.everySixHours.nextScan(after: lastScan, now: now) == now.addingTimeInterval(3600))
    }

    @Test func customScanIsNotDueBeforeItsTime() {
        let customScanAt = now.addingTimeInterval(60)
        #expect(!ScanSchedule.custom.isDue(lastScan: nil, customScanAt: customScanAt, now: now))
        #expect(ScanSchedule.custom.nextScan(after: nil, customScanAt: customScanAt, now: now) == customScanAt)
    }

    @Test func customScanIsDueAtItsTime() {
        #expect(ScanSchedule.custom.isDue(lastScan: nil, customScanAt: now, now: now))
    }

    @Test func missedCustomScanIsDueAfterWakeOrRelaunch() {
        let threeDaysAgo = now.addingTimeInterval(-3 * 24 * 3600)
        #expect(ScanSchedule.custom.isDue(lastScan: nil, customScanAt: threeDaysAgo, now: now))
    }

    @Test func customScanIgnoresTheLastScan() {
        let customScanAt = now.addingTimeInterval(3600)
        let fiveMinutes: TimeInterval = 300
        #expect(!ScanSchedule.custom.isDue(lastScan: now, customScanAt: customScanAt, now: now))
        #expect(!ScanSchedule.custom.isDue(lastScan: now.addingTimeInterval(365 * 24 * 3600), customScanAt: customScanAt, now: now))
        #expect(ScanSchedule.custom.isDue(lastScan: now, customScanAt: customScanAt, now: customScanAt))
        let deepScanFinishedLater = customScanAt.addingTimeInterval(fiveMinutes)
        #expect(ScanSchedule.custom.isDue(lastScan: deepScanFinishedLater, customScanAt: customScanAt, now: deepScanFinishedLater))
    }

    @Test func customScanWithNoTimeIsNeverDue() {
        #expect(!ScanSchedule.custom.isDue(lastScan: nil, customScanAt: nil, now: now))
        #expect(ScanSchedule.custom.nextScan(after: nil, customScanAt: nil, now: now) == nil)
    }

    @Test func finishedCustomScanTurnsOffAndNeverRunsAgain() {
        let schedule = ScanSchedule.custom.afterCustomScan(for: now, customScanAt: now)
        #expect(schedule == .off)
        #expect(!schedule.isDue(lastScan: now, customScanAt: now, now: now.addingTimeInterval(3600)))
        #expect(schedule.nextScan(after: now, customScanAt: now, now: now) == nil)
    }

    @Test func customScanChosenDuringARunStaysScheduled() {
        let later = now.addingTimeInterval(24 * 3600)
        #expect(ScanSchedule.custom.afterCustomScan(for: now, customScanAt: later) == .custom)
        #expect(ScanSchedule.hourly.afterCustomScan(for: now, customScanAt: nil) == .hourly)
        #expect(ScanSchedule.off.afterCustomScan(for: now, customScanAt: nil) == .off)
    }

    @Test func intervalSchedulesIgnoreTheCustomTime() {
        let lastScan = now.addingTimeInterval(-5 * 3600)
        #expect(!ScanSchedule.everySixHours.isDue(lastScan: lastScan, customScanAt: now, now: now))
        #expect(ScanSchedule.hourly.nextScan(after: lastScan, customScanAt: now, now: now) == lastScan.addingTimeInterval(3600))
        #expect(!ScanSchedule.off.isDue(lastScan: nil, customScanAt: now, now: now))
        #expect(ScanSchedule.custom.interval == nil)
    }

    @Test func savedSchedulesFromEarlierVersionsStillLoad() {
        #expect(ScanSchedule(savedValue: 0, customScanAt: nil) == .off)
        #expect(ScanSchedule(savedValue: 1, customScanAt: nil) == .hourly)
        #expect(ScanSchedule(savedValue: 6, customScanAt: nil) == .everySixHours)
        #expect(ScanSchedule(savedValue: 12, customScanAt: nil) == .everyTwelveHours)
        #expect(ScanSchedule(savedValue: 24, customScanAt: nil) == .daily)
        #expect(ScanSchedule(savedValue: 7, customScanAt: nil) == .off)
    }

    @Test func savedCustomScheduleLoadsOnlyWithItsTime() {
        #expect(ScanSchedule(savedValue: ScanSchedule.custom.rawValue, customScanAt: now) == .custom)
        #expect(ScanSchedule(savedValue: ScanSchedule.custom.rawValue, customScanAt: nil) == .off)
    }

    @Test func customScanStartsOnALocalHourInTheFuture() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try #require(TimeZone(identifier: "Asia/Kolkata"))
        let start = try #require(calendar.date(from: DateComponents(year: 2026, month: 11, day: 3, hour: 14, minute: 20, second: 15)))
        let expected = try #require(calendar.date(from: DateComponents(year: 2026, month: 11, day: 3, hour: 15, minute: 0, second: 0)))
        let late = try #require(calendar.date(from: DateComponents(year: 2026, month: 11, day: 3, hour: 14, minute: 40)))
        let nextHour = try #require(calendar.date(from: DateComponents(year: 2026, month: 11, day: 3, hour: 16, minute: 0, second: 0)))
        #expect(ScanSchedule.defaultCustomScan(after: start, calendar: calendar) == expected)
        #expect(ScanSchedule.defaultCustomScan(after: late, calendar: calendar) == nextHour)
    }

    @Test func earliestCustomScanIsInTheFuture() {
        #expect(ScanSchedule.earliestCustomScan(after: now) > now)
    }
}
