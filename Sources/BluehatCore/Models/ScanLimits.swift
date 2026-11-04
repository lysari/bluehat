import Foundation

public struct ScanLimits: Sendable, Equatable {
    public static let defaults = ScanLimits()

    private var changedValues: [String: Int] = [:]

    private init() {}

    init(unchecked values: [ScanLimit: Int]) {
        for (limit, value) in values where value != limit.defaultValue {
            changedValues[limit.key] = value
        }
    }

    public subscript(limit: ScanLimit) -> Int {
        changedValues[limit.key] ?? limit.defaultValue
    }

    public var savedValues: [String: Int] {
        changedValues
    }

    public var isDefault: Bool {
        changedValues.isEmpty
    }

    public func setting(_ limit: ScanLimit, to value: Int) -> ScanLimits? {
        guard limit.range.contains(value) else { return nil }
        var limits = self
        limits.changedValues[limit.key] = value == limit.defaultValue ? nil : value
        return limits
    }

    public func resetting(_ limit: ScanLimit) -> ScanLimits {
        var limits = self
        limits.changedValues[limit.key] = nil
        return limits
    }

    public static func load(saved: Any?) -> (limits: ScanLimits, notice: String?) {
        guard let saved else { return (.defaults, nil) }
        guard let values = saved as? [String: Any] else {
            return (.defaults, "Bluehat couldn't read the saved limits and used the defaults for all of them.")
        }
        var limits = ScanLimits()
        var refused: [String] = []
        for limit in ScanLimit.all {
            guard let value = values[limit.key] else { continue }
            guard let number = wholeNumber(value), limit.range.contains(number) else {
                refused.append(limit.title)
                continue
            }
            limits.changedValues[limit.key] = number == limit.defaultValue ? nil : number
        }
        guard !refused.isEmpty else { return (limits, nil) }
        return (limits, "Bluehat used the default for saved limits that were out of range or the wrong type: \(refused.joined(separator: ", ")).")
    }

    private static func wholeNumber(_ value: Any) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), !CFNumberIsFloatType(number) else { return nil }
        return Int(exactly: number)
    }

    public var changedNotice: String? {
        let changed = ScanLimit.all.filter { self[$0] != $0.defaultValue }
        guard !changed.isEmpty else { return nil }
        let lowered = changed.filter { self[$0] < $0.defaultValue }.map(description(of:))
        let raised = changed.filter { self[$0] > $0.defaultValue }.map(description(of:))
        return [
            "This scan used limits changed in Settings › Limits.",
            lowered.isEmpty ? nil : "Lowered, so it may have missed things: \(lowered.joined(separator: ", ")).",
            raised.isEmpty ? nil : "Raised: \(raised.joined(separator: ", ")).",
        ].compactMap { $0 }.joined(separator: " ")
    }

    private func description(of limit: ScanLimit) -> String {
        "\(limit.area.title) › \(limit.title) \(limit.text(for: self[limit])) (default \(limit.text(for: limit.defaultValue)))"
    }
}
