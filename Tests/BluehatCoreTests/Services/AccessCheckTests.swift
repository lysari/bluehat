import Foundation
import Testing
@testable import BluehatCore

struct AccessCheckTests {
    func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    @Test func fingerprintsMatchSSHKeygen() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "bluehat-ssh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keyPath = directory.appending(path: "id_test").path
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "attacker@evil", "-f", keyPath])
        let publicKey = try String(contentsOfFile: keyPath + ".pub", encoding: .utf8)
        let expected = try run("/usr/bin/ssh-keygen", ["-l", "-f", keyPath + ".pub"]).split(separator: " ")[1]

        let keys = Scanner.authorizedKeys(in: "# my keys\n\n" + publicKey)

        #expect(keys.count == 1)
        #expect(keys.first?.summary == "ssh-ed25519 \(expected) attacker@evil")
    }

    @Test func showsForcedCommandOptions() {
        let line = #"command="/tmp/x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGd6 backup"#
        #expect(Scanner.authorizedKeys(in: line).first?.summary.hasSuffix(#"· options: command="/tmp/x""#) == true)
    }

    @Test func ignoresMalformedLines() {
        #expect(Scanner.authorizedKeys(in: "ssh-rsa not-base64!!\nhello world").isEmpty)
    }

    @Test func parsesProfilesAndSkipsInternalOnes() {
        let output = """
        lysari[1] attribute: name: ManagedSettings User Settings
        lysari[1] attribute: profileIdentifier: com.apple.ManagedSettings.macOS.7BE22211
        lysari[1] attribute: internaldata: TRUE
        lysari[1]            payload[1] type\t\t\t= com.apple.appstore
        lysari[2] attribute: name: Free VPN Helper
        lysari[2] attribute: profileIdentifier: com.freevpn.helper
        lysari[2] attribute: internaldata: FALSE
        lysari[2]            payload[1] type\t\t\t= com.apple.proxy.http.global
        lysari[2]            payload[2] type\t\t\t= com.apple.security.root
        """
        let profiles = Scanner.profiles(fromProfilesOutput: output)
        #expect(profiles.map(\.identifier) == ["com.freevpn.helper"])
        #expect(profiles.first?.name == "Free VPN Helper")
        #expect(profiles.first?.payloadTypes == ["com.apple.proxy.http.global", "com.apple.security.root"])
    }

    @Test func acceptsAccessRulesWithoutPatterns() throws {
        let data = Data(#"{"schema": 1, "version": 1, "rules": [{"id": "ssh.any", "title": "t", "severity": "medium", "category": "backdoor", "check": "sshKey"}]}"#.utf8)
        #expect(try Rulebook.decode(from: data).rules.first?.patterns == nil)
    }

    @Test func validatesAccessRulePatternsWhenPresent() {
        let data = Data(#"{"schema": 1, "version": 1, "rules": [{"id": "profile.bad", "title": "t", "severity": "high", "category": "persistence", "check": "profile", "patterns": ["(unclosed"]}]}"#.utf8)
        #expect(throws: RulebookError.self) { try Rulebook.decode(from: data) }
    }
}
