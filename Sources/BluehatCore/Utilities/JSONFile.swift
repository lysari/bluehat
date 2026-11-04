import Foundation

enum JSONFile {
    enum Refusal: LocalizedError {
        case tooDeep, notUTF8

        var errorDescription: String? {
            switch self {
            case .tooDeep: "Nested more than \(maxNesting.formatted()) levels deep, so it wasn't parsed"
            case .notUTF8: "Not UTF-8 text, so it wasn't parsed"
            }
        }
    }

    /// Fixed below the 470 nested objects that crash `JSONSerialization` on a 512 KiB stack, and never a `ScanLimit`, so no setting can raise it.
    static let maxNesting = 300

    private static let quote = UInt8(ascii: "\"")
    private static let backslash = UInt8(ascii: "\\")
    private static let openBrace = UInt8(ascii: "{")
    private static let openBracket = UInt8(ascii: "[")
    private static let closeBrace = UInt8(ascii: "}")
    private static let closeBracket = UInt8(ascii: "]")

    /// Parses a file a scan read into its top-level object, or returns nil for invalid JSON or any other top-level type.
    /// Throws a `Refusal`, before parsing, for text that could crash the parser. Use it for every JSON file an attacker can influence, never `JSONSerialization` directly.
    static func object(from data: Data) throws -> [String: Any]? {
        if let refusal = refusal(of: data) { throw refusal }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// Says why a file's text must not be parsed, or returns nil when it is safe to parse. Reads each byte at most once and allocates nothing.
    static func refusal(of data: Data) -> Refusal? {
        data.withUnsafeBytes { bytes in
            var depth = 0
            var isInString = false
            var isEscaped = false
            for byte in bytes {
                // UTF-16 and UTF-32 parse too but can hide a quote inside a character; each of their structural characters holds a NUL byte, which UTF-8 JSON can't.
                if byte == 0 { return .notUTF8 }
                if isInString {
                    if isEscaped {
                        isEscaped = false
                    } else if byte == backslash {
                        isEscaped = true
                    } else if byte == quote {
                        isInString = false
                    }
                } else if byte == quote {
                    isInString = true
                } else if byte == openBrace || byte == openBracket {
                    depth += 1
                    if depth > maxNesting { return .tooDeep }
                } else if byte == closeBrace || byte == closeBracket {
                    depth -= 1
                }
            }
            return nil
        }
    }
}
