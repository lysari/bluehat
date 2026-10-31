import Foundation
import Testing
@testable import BluehatCore

struct XProtectTests {
    static func infoPlist(version: String) -> Data {
        Data("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>CFBundleIdentifier</key>
                <string>com.apple.XProtect</string>
                <key>CFBundleShortVersionString</key>
                <string>\(version)</string>
                <key>CFBundleVersion</key>
                <string>1</string>
            </dict>
            </plist>
            """.utf8)
    }

    static func rule(minimumVersion: Int) -> Rule {
        Rule(id: "xprotect.outdated", title: "Outdated", severity: .medium, category: .hardening, check: .xprotect, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: minimumVersion, hosts: nil, summary: nil, remedy: nil, references: nil)
    }

    @Test func readsTheShortVersionFromInfoPlist() {
        #expect(Scanner.xprotectVersion(fromInfoPlist: Self.infoPlist(version: "5368")) == 5368)
    }

    @Test(arguments: ["", "5368a", "5.3", "latest"])
    func ignoresAVersionThatIsNotANumber(version: String) {
        #expect(Scanner.xprotectVersion(fromInfoPlist: Self.infoPlist(version: version)) == nil)
    }

    @Test func ignoresAFileThatIsNotAPlist() {
        #expect(Scanner.xprotectVersion(fromInfoPlist: Data("not a plist".utf8)) == nil)
        #expect(Scanner.xprotectVersion(fromInfoPlist: Data(#"<plist version="1.0"><array/></plist>"#.utf8)) == nil)
    }

    @Test func flagsAVersionBelowTheMinimumOnly() {
        let findings = Scanner.xprotectFindings([Self.rule(minimumVersion: 5360)], version: 5301)
        #expect(findings.map(\.detail) == ["XProtect version 5301 is older than 5360"])
        #expect(Scanner.xprotectFindings([Self.rule(minimumVersion: 5360)], version: 5360).isEmpty)
        #expect(Scanner.xprotectFindings([Self.rule(minimumVersion: 5360)], version: 5368).isEmpty)
    }

    @Test func unreadableVersionGivesNoFinding() {
        #expect(Scanner.xprotectFindings([Self.rule(minimumVersion: 5360)], version: nil).isEmpty)
    }
}
