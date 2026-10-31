import Foundation

public struct TerminalCommand: Sendable, Equatable {
    let setup: String?
    let command: String
    let values: [String]

    public var text: String {
        ([command] + values.map(Self.quoted)).joined(separator: " ")
    }

    public var script: String {
        [
            "#!/bin/zsh",
            #"rm -f -- "$0"; rmdir -- "${0:h}" 2>/dev/null"#,
            "print -r -- 'Bluehat prepared this command:'",
            "print -r -- ''",
            "print -r -- \(Self.quoted("    " + text))",
            "print -r -- ''",
            "read -r '?Press Return to run it, or Control-C to cancel. ' || exit 1",
            setup,
            text,
            "print -r -- ''",
            "print -r -- 'Finished. Scan again in Bluehat to check this copy.'",
        ]
        .compactMap { $0 }
        .joined(separator: "\n") + "\n"
    }

    static func quoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
    }
}
