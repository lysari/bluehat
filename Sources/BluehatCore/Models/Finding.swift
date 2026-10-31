import CryptoKit
import Foundation

public struct Finding: Sendable, Identifiable {
    static let maxDetailLength = 200

    public let id = UUID()
    public let rule: Rule
    public let detail: String
    public let path: String?
    public let fingerprint: String

    public init(rule: Rule, detail: String, path: String?) {
        self.rule = rule
        self.detail = Self.clip(Self.displayable(detail))
        self.path = path
        let subject = "\(detail.utf8.count):\(detail)\(path ?? "")"
        fingerprint = rule.id + "|" + SHA256.hash(data: Data(subject.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func displayable(_ text: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator:
                if scalar.properties.isWhitespace { scalars.append(" ") }
            default:
                scalars.append(scalar)
            }
        }
        return String(scalars)
    }

    static func clip(_ text: String) -> String {
        text.count > maxDetailLength ? String(text.prefix(maxDetailLength)) + "…" : text
    }
}
