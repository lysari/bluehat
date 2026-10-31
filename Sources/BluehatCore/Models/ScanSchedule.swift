import Foundation

public enum ScanSchedule: Int, Codable, Sendable, CaseIterable, Identifiable {
    case off = 0
    case hourly = 1
    case everySixHours = 6
    case everyTwelveHours = 12
    case daily = 24

    static let secondsPerHour: TimeInterval = 3600

    public var id: Int {
        rawValue
    }

    public var interval: TimeInterval? {
        self == .off ? nil : TimeInterval(rawValue) * Self.secondsPerHour
    }

    public func nextScan(after lastScan: Date?, now: Date) -> Date? {
        guard let interval else { return nil }
        guard let lastScan, lastScan <= now else { return now }
        return lastScan.addingTimeInterval(interval)
    }

    public func isDue(lastScan: Date?, now: Date) -> Bool {
        nextScan(after: lastScan, now: now).map { $0 <= now } ?? false
    }
}
