import Foundation
import Testing
@testable import BluehatCore

struct FindingTests {
    func finding(_ detail: String, path: String? = nil) -> Finding {
        let rule = Rule(id: "process.test", title: "Test", severity: .high, category: .malware, check: .process, patterns: ["x"], paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, summary: nil, remedy: nil, references: nil)
        return Finding(rule: rule, detail: detail, path: path)
    }

    @Test func clipsLongDetails() {
        #expect(finding(String(repeating: "a", count: 500)).detail.count == Finding.maxDetailLength + 1)
    }

    @Test(arguments: [
        ("invoice\u{202E}fdp.app", "invoicefdp.app"),
        ("a\u{2066}b\u{2069}c\u{200B}d\u{FEFF}e", "abcde"),
        ("\u{1B}[31mred\u{7}", "[31mred"),
        ("line\u{2028}next\u{2029}para", "line next para"),
        ("tab\tand\r\nnewline\u{85}", "tab and  newline "),
        ("Ромашка 👋 é", "Ромашка 👋 é"),
    ])
    func stripsControlAndFormatCharactersFromDetails(raw: String, shown: String) {
        #expect(finding(raw).detail == shown)
    }

    @Test func fingerprintCoversFullDetailAndPath() {
        let long = String(repeating: "a", count: 300)
        #expect(finding(long + "1").fingerprint != finding(long + "2").fingerprint)
        #expect(finding("cmd", path: "/a.plist").fingerprint != finding("cmd", path: "/b.plist").fingerprint)
        #expect(finding("cmd", path: "/a.plist").fingerprint == finding("cmd", path: "/a.plist").fingerprint)
        #expect(finding("cmd/a", path: nil).fingerprint != finding("cmd", path: "/a").fingerprint)
        #expect(finding("cmd").fingerprint.hasPrefix("process.test|"))
    }
}
