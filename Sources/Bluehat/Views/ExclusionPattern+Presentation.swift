import BluehatCore

extension ExclusionPattern.Problem {
    var message: String {
        switch self {
        case .empty: "Type a pattern first."
        case .tooLong: "That pattern is longer than a path can be."
        case .negated: "! patterns aren't supported, because an exclusion can't add a path back. Remove or narrow the pattern that covers it."
        case .wholeDisk: "That would skip everything a Deep Scan walks. Name something more specific."
        case .dotFolder: ". and .. can't be folder names. Write the full path instead, like ~/Projects/app."
        case .emptyFolder: "A pattern can't have two slashes in a row."
        case .danglingEscape: "A \\ must be followed by the character it escapes, and it can't escape a /."
        case .invalidClass: "A [ needs a closing ], and a range must run low to high, like [a-z]."
        case .duplicate: "That's already in the list."
        }
    }
}
