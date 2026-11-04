import Foundation

public struct ExclusionPattern: Equatable, Sendable {
    public enum Problem: Error, Equatable {
        case empty
        case tooLong
        case negated
        case wholeDisk
        case dotFolder
        case emptyFolder
        case danglingEscape
        case invalidClass
        case duplicate
    }

    private enum Token: Equatable, Sendable {
        case literal(Character)
        case anyCharacter
        case anyRun
        case characterClass(ranges: [ClosedRange<Character>], isNegated: Bool)

        func accepts(_ character: Character) -> Bool {
            switch self {
            case .literal(let literal): literal == character
            case .anyCharacter: true
            case .anyRun: false
            case .characterClass(let ranges, let isNegated): ranges.contains { $0.contains(character) } != isNegated
            }
        }

        var isLiteral: Bool {
            if case .literal = self { true } else { false }
        }
    }

    private enum Segment: Equatable, Sendable {
        case anyFolders
        case name([Token])

        var hasLiteral: Bool {
            if case .name(let tokens) = self { tokens.contains(where: \.isLiteral) } else { false }
        }
    }

    private static let anyFoldersText = "**"

    public let text: String
    private let isFolderOnly: Bool
    private let literalRoot: [String]
    private var segments: [Segment]

    public init(parsing input: String) throws(Problem) {
        text = Self.trimmed(input)
        guard !text.isEmpty else { throw .empty }
        guard text.utf8.count <= Int(PATH_MAX) else { throw .tooLong }
        guard !text.hasPrefix("!") else { throw .negated }
        let isUnderHome = text == "~" || text.hasPrefix("~/")
        let body = isUnderHome ? text.dropFirst() : text[...]
        let isAnchored = isUnderHome || body.hasPrefix("/")
        var names = try Self.folderNames(in: isAnchored ? body.dropFirst() : body)
        var endsInFolder = false
        while let last = names.last, last.isEmpty || last == Self.anyFoldersText {
            names.removeLast()
            endsInFolder = true
        }
        isFolderOnly = endsInFolder
        guard !names.contains("") else { throw .emptyFolder }

        var parsed: [Segment] = []
        var literalNames = isUnderHome ? NSHomeDirectory().split(separator: "/").map(String.init) : []
        var isLiteralSoFar = isAnchored
        for name in names {
            guard name != Self.anyFoldersText else {
                isLiteralSoFar = false
                if parsed.last != .anyFolders { parsed.append(.anyFolders) }
                continue
            }
            let tokens = try Self.tokens(of: name.lowercased())
            guard tokens != [.literal(".")], tokens != [.literal("."), .literal(".")] else { throw .dotFolder }
            parsed.append(.name(tokens))
            isLiteralSoFar = isLiteralSoFar && tokens.allSatisfy(\.isLiteral)
            if isLiteralSoFar { literalNames.append(try Self.unescaped(name)) }
        }
        guard parsed.contains(where: \.hasLiteral) else { throw .wholeDisk }

        literalRoot = isAnchored ? literalNames : []
        if isUnderHome {
            segments = Self.literalSegments(Self.components(of: NSHomeDirectory())) + parsed
        } else {
            segments = isAnchored || parsed.first == .anyFolders ? parsed : [.anyFolders] + parsed
        }
    }

    public static func == (lhs: ExclusionPattern, rhs: ExclusionPattern) -> Bool {
        lhs.segments == rhs.segments && lhs.isFolderOnly == rhs.isFolderOnly
    }

    public static func coversWholeDisk(folder path: String) -> Bool {
        VolumeWalk.canonical(path) == "/"
    }

    public func isListed(inFolders folders: [String], patterns: [String]) -> Bool {
        folders.contains { Self.literalSegments(Self.components(of: $0)) == segments }
            || patterns.contains { (try? ExclusionPattern(parsing: $0)) == self }
    }

    func resolvingLinks() throws(Problem) -> ExclusionPattern {
        guard !literalRoot.isEmpty, let resolved = VolumeWalk.canonical("/" + literalRoot.joined(separator: "/")) else { return self }
        var pattern = self
        pattern.segments = Self.literalSegments(Self.components(of: resolved)) + segments.dropFirst(literalRoot.count)
        guard pattern.segments.contains(where: \.hasLiteral) else { throw .wholeDisk }
        return pattern
    }

    static func components(of path: String) -> [[Character]] {
        path.split(separator: "/").map { folded(String($0)) }
    }

    static func folded(_ name: String) -> [Character] {
        Array(name.lowercased())
    }

    func matches(_ components: ArraySlice<[Character]>, isDirectory: Bool) -> Bool {
        guard isDirectory || !isFolderOnly else { return false }
        var segment = segments.count - 1
        var component = components.endIndex - 1
        var retry: (segment: Int, component: Int)?
        while true {
            if segment < 0 {
                if component < components.startIndex { return true }
            } else if case .name(let tokens) = segments[segment] {
                if component >= components.startIndex, Self.name(components[component], matches: tokens) {
                    segment -= 1
                    component -= 1
                    continue
                }
            } else {
                guard segment > 0 else { return true }
                segment -= 1
                retry = (segment, component)
                continue
            }
            guard let last = retry, last.component >= components.startIndex else { return false }
            retry = (last.segment, last.component - 1)
            segment = last.segment
            component = last.component - 1
        }
    }

    private static func name(_ name: [Character], matches tokens: [Token]) -> Bool {
        var token = 0
        var character = 0
        var retry: (token: Int, character: Int)?
        while character < name.count {
            if token < tokens.count, tokens[token] == .anyRun {
                token += 1
                retry = (token, character)
            } else if token < tokens.count, tokens[token].accepts(name[character]) {
                token += 1
                character += 1
            } else if let last = retry {
                retry = (last.token, last.character + 1)
                token = last.token
                character = last.character + 1
            } else {
                return false
            }
        }
        return tokens[token...].allSatisfy { $0 == .anyRun }
    }

    private static func literalSegments(_ components: [[Character]]) -> [Segment] {
        components.map { .name($0.map(Token.literal)) }
    }

    private static func trimmed(_ input: String) -> String {
        let characters = Array(input.drop(while: \.isWhitespace))
        var end = 0
        var index = 0
        while index < characters.count {
            let isEscape = characters[index] == "\\"
            if isEscape || !characters[index].isWhitespace {
                end = min(index + (isEscape ? 2 : 1), characters.count)
            }
            index += isEscape ? 2 : 1
        }
        return String(characters.prefix(end))
    }

    private static func folderNames(in body: Substring) throws(Problem) -> [String] {
        var names = [""]
        var isEscaped = false
        for character in body {
            if isEscaped {
                guard character != "/" else { throw .danglingEscape }
                isEscaped = false
            } else if character == "/" {
                names.append("")
                continue
            } else if character == "\\" {
                isEscaped = true
            }
            names[names.count - 1].append(character)
        }
        return names
    }

    private static func unescaped(_ name: String) throws(Problem) -> String {
        var literal = ""
        for token in try tokens(of: name) {
            if case .literal(let character) = token { literal.append(character) }
        }
        return literal
    }

    private static func tokens(of name: String) throws(Problem) -> [Token] {
        let characters = Array(name)
        var tokens: [Token] = []
        var index = 0
        while index < characters.count {
            let character = characters[index]
            index += 1
            switch character {
            case "\\":
                guard index < characters.count else { throw .danglingEscape }
                tokens.append(.literal(characters[index]))
                index += 1
            case "?":
                tokens.append(.anyCharacter)
            case "*":
                if tokens.last != .anyRun { tokens.append(.anyRun) }
            case "[":
                tokens.append(try characterClass(in: characters, from: &index))
            default:
                tokens.append(.literal(character))
            }
        }
        return tokens
    }

    private static func characterClass(in characters: [Character], from index: inout Int) throws(Problem) -> Token {
        var position = index
        let isNegated = position < characters.count && (characters[position] == "!" || characters[position] == "^")
        if isNegated { position += 1 }
        var ranges: [ClosedRange<Character>] = []
        while position < characters.count, ranges.isEmpty || characters[position] != "]" {
            guard characters[position] != "[" || position + 1 >= characters.count || characters[position + 1] != ":" else { throw .invalidClass }
            let lower = try classCharacter(in: characters, at: &position)
            guard position + 1 < characters.count, characters[position] == "-", characters[position + 1] != "]" else {
                ranges.append(lower...lower)
                continue
            }
            position += 1
            let upper = try classCharacter(in: characters, at: &position)
            guard lower <= upper else { throw .invalidClass }
            ranges.append(lower...upper)
        }
        guard position < characters.count else { throw .invalidClass }
        index = position + 1
        return .characterClass(ranges: ranges, isNegated: isNegated)
    }

    private static func classCharacter(in characters: [Character], at position: inout Int) throws(Problem) -> Character {
        if characters[position] == "\\" {
            position += 1
            guard position < characters.count else { throw .danglingEscape }
        }
        defer { position += 1 }
        return characters[position]
    }
}
