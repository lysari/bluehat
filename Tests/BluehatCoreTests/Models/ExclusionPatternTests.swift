import Foundation
import Testing
@testable import BluehatCore

struct ExclusionPatternTests {
    func matches(_ pattern: String, _ path: String, isDirectory: Bool = false) throws -> Bool {
        let components = ExclusionPattern.components(of: path)
        return try ExclusionPattern(parsing: pattern).matches(components[...], isDirectory: isDirectory)
    }

    func problem(_ pattern: String) -> ExclusionPattern.Problem? {
        do {
            _ = try ExclusionPattern(parsing: pattern)
            return nil
        } catch {
            return error
        }
    }

    @Test(arguments: [
        ("*.log", "/a/b.log", true),
        ("*.log", "/a/.log", true),
        ("*.log", "/a/b.logs", false),
        ("a*c", "/x/abbc", true),
        ("a*c", "/x/ac", true),
        ("a*c", "/x/ab/c", false),
        ("a?c", "/x/abc", true),
        ("a?c", "/x/ac", false),
        ("a?c", "/x/a/c", false),
        ("a[bc]d", "/x/acd", true),
        ("a[bc]d", "/x/aed", false),
        ("a[b-d]e", "/x/ace", true),
        ("a[b-d]e", "/x/afe", false),
        ("a[!b]c", "/x/adc", true),
        ("a[!b]c", "/x/abc", false),
        ("a[^b]c", "/x/abc", false),
        ("a[]b]c", "/x/a]c", true),
        ("a[-b]c", "/x/a-c", true),
        ("a[\\]]c", "/x/a]c", true),
        ("a/**/c", "/a/c", true),
        ("a/**/c", "/a/b/c", true),
        ("a/**/c", "/x/a/b/d/c", true),
        ("a/**/c", "/x/c", false),
        ("a/**/a/c", "/a/a/c", true),
        ("/a/**/c", "/a/a/b/c", true),
        ("/a/**/c", "/x/a/b/c", false),
        ("/a/**/a", "/a/a/a", true),
        ("**/name", "/x/y/name", true),
        ("a**b", "/x/acb", true),
        ("a**b", "/a/c/b", false),
        ("\\*.log", "/x/*.log", true),
        ("\\*.log", "/x/a.log", false),
        ("a\\?c", "/x/a?c", true),
        ("a\\?c", "/x/abc", false),
        ("\\[abc\\]", "/x/[abc]", true),
        ("\\[abc\\]", "/x/a", false),
        ("a\\\\b", "/x/a\\b", true),
        ("\\!keep", "/x/!keep", true),
        ("\\~", "/x/~", true),
        ("~name", "/x/~name", true),
        ("*~", "/x/backup~", true),
    ])
    func matchesEachSyntaxForm(pattern: String, path: String, isMatch: Bool) throws {
        #expect(try matches(pattern, path) == isMatch)
    }

    @Test(arguments: [
        ("node_modules", "/a/node_modules", true),
        ("node_modules", "/node_modules", true),
        ("node_modules", "/a/node_modules/b", false),
        ("src/generated", "/src/generated", true),
        ("src/generated", "/a/b/src/generated", true),
        ("src/generated", "/a/generated", false),
        ("src/generated", "/a/src/other/generated", false),
        ("/a/b", "/a/b", true),
        ("/a/b", "/x/a/b", false),
        ("/a/b", "/a", false),
        ("/a/b", "/a/b/c", false),
        ("/a/*/c", "/a/b/c", true),
        ("/a/*/c", "/x/a/b/c", false),
    ])
    func anchorsOnlyAPatternStartingAtTheRootOrHome(pattern: String, path: String, isMatch: Bool) throws {
        #expect(try matches(pattern, path, isDirectory: true) == isMatch)
    }

    @Test func aTildePatternIsAnchoredAtTheHomeFolder() throws {
        let home = NSHomeDirectory()
        #expect(try matches("~/Library/Caches", "\(home)/Library/Caches"))
        #expect(try !matches("~/Library/Caches", "/elsewhere/Library/Caches"))
        #expect(try !matches("~/Library/Caches", "/elsewhere\(home)/Library/Caches"))
        #expect(try matches("~/*.log", "\(home)/a.log"))
    }

    @Test(arguments: ["build/", "build/**", "build/**/", "**/build/"])
    func aTrailingSlashOrDoubleStarMatchesOnlyFolders(pattern: String) throws {
        #expect(try matches(pattern, "/a/build", isDirectory: true))
        #expect(try !matches(pattern, "/a/build", isDirectory: false))
    }

    @Test func aPatternWithoutATrailingSlashMatchesFilesAndFolders() throws {
        #expect(try matches("build", "/a/build", isDirectory: true))
        #expect(try matches("build", "/a/build", isDirectory: false))
    }

    @Test(arguments: [
        ("NODE_MODULES", "/a/node_modules"),
        ("node_modules", "/a/Node_Modules"),
        ("*.LOG", "/a/b.log"),
        ("*.log", "/a/B.LOG"),
        ("/USERS/ME", "/Users/me"),
        ("[A-C]x", "/a/bX"),
        ("[a-c]x", "/a/BX"),
        ("Éa", "/x/éA"),
        ("e\u{301}a", "/x/\u{E9}a"),
    ])
    func ignoresCase(pattern: String, path: String) throws {
        #expect(try matches(pattern, path))
    }

    @Test(arguments: [
        ("", ExclusionPattern.Problem.empty),
        ("   ", .empty),
        (String(repeating: "a", count: Int(PATH_MAX) + 1), .tooLong),
        ("!foo", .negated),
        ("  !foo", .negated),
        (".", .dotFolder),
        ("..", .dotFolder),
        ("./foo", .dotFolder),
        ("foo/..", .dotFolder),
        ("foo/../bar", .dotFolder),
        ("/foo/.", .dotFolder),
        ("~/..", .dotFolder),
        ("\\.\\.", .dotFolder),
        ("a//b", .emptyFolder),
        ("foo\\", .danglingEscape),
        ("foo\\/bar", .danglingEscape),
        ("a[b\\", .danglingEscape),
        ("[abc", .invalidClass),
        ("[", .invalidClass),
        ("[]", .invalidClass),
        ("[!]", .invalidClass),
        ("[z-a]", .invalidClass),
        ("[a/b]", .invalidClass),
        ("[[:alpha:]]", .invalidClass),
    ])
    func refusesAnInvalidPattern(pattern: String, expected: ExclusionPattern.Problem) {
        #expect(problem(pattern) == expected)
    }

    @Test(arguments: ["*", "**", "***", "/", "//", "/*", "/**", "*/", "**/", "**/*", "*/*", "/*/*", "?", "?*", "[a-z]*", "[a-z]*/", "[!a]*", "~", "~/", "~/*", "~/**", "~/*/*"])
    func refusesAWholeDiskPattern(pattern: String) {
        #expect(problem(pattern) == .wholeDisk)
    }

    @Test(arguments: ["/Users", "/Users/*", "~/foo", "~/foo/*", "*.*", ".*", "*/foo", "\\*"])
    func acceptsABroadPatternThatStillNamesSomething(pattern: String) {
        #expect(problem(pattern) == nil)
    }

    @Test func keepsTheTextAsTypedWithoutOuterSpaces() throws {
        #expect(try ExclusionPattern(parsing: "  ~/Foo/*.Log \n").text == "~/Foo/*.Log")
    }

    @Test func anEscapedTrailingSpaceStaysInTheName() throws {
        #expect(try ExclusionPattern(parsing: "foo\\ ").text == "foo\\ ")
        #expect(try matches("foo\\ ", "/a/foo "))
        #expect(try !matches("foo\\ ", "/a/foo"))
        #expect(try ExclusionPattern(parsing: "foo\\\\ ").text == "foo\\\\")
    }

    @Test(arguments: [
        ("foo", "foo"),
        ("FOO", "foo"),
        ("foo/**", "foo/"),
        ("**/foo", "foo"),
        ("a/**/**/b", "a/**/b"),
        ("x**", "x*"),
        ("~/x", "\(NSHomeDirectory())/x"),
    ])
    func findsTheSamePatternWrittenAnotherWay(pattern: String, listed: String) throws {
        #expect(try ExclusionPattern(parsing: pattern).isListed(inFolders: [], patterns: [listed]))
    }

    @Test(arguments: [
        ("foo", "foo/"),
        ("foo", "/foo"),
        ("foo", "bar"),
        ("*.log", "*.txt"),
    ])
    func keepsDifferentPatternsApart(pattern: String, listed: String) throws {
        #expect(try !ExclusionPattern(parsing: pattern).isListed(inFolders: [], patterns: [listed]))
    }

    @Test func findsAPatternThatNamesAListedFolder() throws {
        let folder = "\(NSHomeDirectory())/Foo"
        #expect(try ExclusionPattern(parsing: "~/foo").isListed(inFolders: [folder], patterns: []))
        #expect(try ExclusionPattern(parsing: "\(NSHomeDirectory())/foo/").isListed(inFolders: [folder], patterns: []))
        #expect(try !ExclusionPattern(parsing: "foo").isListed(inFolders: [folder], patterns: []))
        #expect(try !ExclusionPattern(parsing: "~/fo*").isListed(inFolders: [folder], patterns: []))
    }

    @Test func aPathologicalPatternFinishesQuickly() throws {
        let manyStars = String(repeating: "a*", count: 500) + "b"
        let manyLiterals = "*" + String(repeating: "a", count: 200) + "b"
        let manyFolders = "x/" + String(repeating: "**/a*/", count: 160) + "a*"
        let longName = String(repeating: "a", count: 255)
        let deepPath = "/" + Array(repeating: "aaaa", count: 200).joined(separator: "/")

        let started = ContinuousClock.now
        #expect(try !matches(manyStars, "/\(longName)"))
        #expect(try !matches(manyLiterals, "/\(longName)"))
        #expect(try !matches(manyFolders, deepPath))
        #expect(ContinuousClock.now - started < .seconds(2))
    }

    @Test func refusesAFolderThatIsTheWholeDisk() {
        #expect(ExclusionPattern.coversWholeDisk(folder: "/"))
        #expect(ExclusionPattern.coversWholeDisk(folder: "/.."))
        #expect(!ExclusionPattern.coversWholeDisk(folder: "/Users"))
        #expect(!ExclusionPattern.coversWholeDisk(folder: "relative"))
    }
}
