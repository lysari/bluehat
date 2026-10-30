import Foundation
import Testing
@testable import BluehatCore

struct SignatureTests {
    let directory = FileManager.default.temporaryDirectory.appending(path: "bluehat-signature-\(UUID().uuidString)")

    init() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func copy(_ path: String, as name: String) throws -> URL {
        let target = directory.appending(path: name)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: path), to: target)
        return target
    }

    func adHocSign(_ url: URL) throws {
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--force", "--sign", "-", url.path]
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        #expect(codesign.terminationStatus == 0)
    }

    @Test func acceptsAppleSignedBinary() {
        #expect(Scanner.signatureProblem(at: URL(fileURLWithPath: "/bin/ls")) == nil)
    }

    @Test func reportsUnsignedFile() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let script = directory.appending(path: "payload")
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: script)
        #expect(Scanner.signatureProblem(at: script) == "is not signed")
    }

    @Test func reportsAdHocSignedBinary() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = try copy("/usr/bin/true", as: "true-adhoc")
        try adHocSign(binary)
        #expect(Scanner.signatureProblem(at: binary) == "is ad-hoc signed, with no developer identity")
    }

    @Test func reportsTamperedBinary() throws {
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = try copy("/bin/ls", as: "ls-tampered")
        var bytes = try Data(contentsOf: binary)
        let codeOffset = 0x4000 + 0x200
        bytes[codeOffset] ^= 0xFF
        try bytes.write(to: binary)
        #expect(Scanner.signatureProblem(at: binary) == "has a broken signature")
    }

    @Test func signatureChecksNeedNoRuleFields() throws {
        let data = Data(#"{"schema": 1, "version": 1, "rules": [{"id": "app.test", "title": "Test", "severity": "medium", "category": "malware", "check": "appSignature"}]}"#.utf8)
        #expect(try Rulebook.decode(from: data).rules.first?.check == .appSignature)
    }
}
