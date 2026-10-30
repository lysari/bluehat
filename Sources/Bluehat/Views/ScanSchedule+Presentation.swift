import BluehatCore

extension ScanSchedule {
    var title: String {
        switch self {
        case .off: "Off"
        case .hourly: "Every hour"
        case .everySixHours: "Every 6 hours"
        case .everyTwelveHours: "Every 12 hours"
        case .daily: "Every day"
        }
    }
}
