import BluehatCore

extension Severity {
    var symbol: String {
        switch self {
        case .critical: "xmark.octagon.fill"
        case .high, .medium: "exclamationmark.triangle.fill"
        case .low, .info: "info.circle.fill"
        }
    }

    var emblemSymbol: String {
        switch self {
        case .critical: "xmark"
        case .high, .medium: "exclamationmark"
        case .low, .info: "info"
        }
    }
}
