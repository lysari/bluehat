import Foundation

public struct SoftwareVersion: Sendable, Comparable, CustomStringConvertible {
    let numbers: [Int]
    let letters: String

    init?(_ text: String, for product: SoftwareProduct) {
        guard
            let match = text.wholeMatch(of: /v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})([a-z]{1,2})?/),
            match.2 == nil || product.hasLetterReleases
        else { return nil }
        numbers = match.1.split(separator: ".").compactMap { Int($0) }
        letters = match.2.map(String.init) ?? ""
    }

    public var description: String {
        numbers.map(String.init).joined(separator: ".") + letters
    }

    public static func < (lhs: SoftwareVersion, rhs: SoftwareVersion) -> Bool {
        for index in 0..<max(lhs.numbers.count, rhs.numbers.count) {
            let left = index < lhs.numbers.count ? lhs.numbers[index] : 0
            let right = index < rhs.numbers.count ? rhs.numbers[index] : 0
            if left != right { return left < right }
        }
        return lhs.letters < rhs.letters
    }

    public static func == (lhs: SoftwareVersion, rhs: SoftwareVersion) -> Bool {
        !(lhs < rhs) && !(rhs < lhs)
    }
}
