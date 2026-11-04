import Foundation

public enum ScanSchedule: Int, Codable, Sendable, CaseIterable, Identifiable {
    case off = 0
    case hourly = 1
    case everySixHours = 6
    case everyTwelveHours = 12
    case daily = 24
    case custom = -1

    static let secondsPerHour: TimeInterval = 3600
    static let earliestCustomScanDelay: TimeInterval = 60
    static let defaultCustomScanDelay: TimeInterval = 1800

    public init(savedValue: Int, customScanAt: Date?) {
        let saved = ScanSchedule(rawValue: savedValue) ?? .off
        self = saved == .custom && customScanAt == nil ? .off : saved
    }

    public var id: Int {
        rawValue
    }

    public var interval: TimeInterval? {
        self == .off || self == .custom ? nil : TimeInterval(rawValue) * Self.secondsPerHour
    }

    public static func earliestCustomScan(after now: Date) -> Date {
        now.addingTimeInterval(earliestCustomScanDelay)
    }

    public static func defaultCustomScan(after now: Date, calendar: Calendar = .current) -> Date {
        let earliest = now.addingTimeInterval(defaultCustomScanDelay)
        return calendar.nextDate(after: earliest, matching: DateComponents(minute: 0, second: 0), matchingPolicy: .nextTime) ?? earliest
    }

    public func nextScan(after lastScan: Date?, customScanAt: Date? = nil, now: Date) -> Date? {
        if self == .custom { return customScanAt }
        guard let interval else { return nil }
        guard let lastScan, lastScan <= now else { return now }
        return lastScan.addingTimeInterval(interval)
    }

    public func isDue(lastScan: Date?, customScanAt: Date? = nil, now: Date) -> Bool {
        nextScan(after: lastScan, customScanAt: customScanAt, now: now).map { $0 <= now } ?? false
    }

    public func afterCustomScan(for finished: Date, customScanAt: Date?) -> ScanSchedule {
        self == .custom && customScanAt == finished ? .off : self
    }
}
