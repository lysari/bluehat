import BluehatCore
import CryptoKit
import Foundation

let keychainService = "bluehat-rules-signing"
let keychainAccount = "bluehat"

func runSecurity(_ arguments: [String]) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return (-1, "") }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
}

func storedKey() -> Curve25519.Signing.PrivateKey? {
    let result = runSecurity(["find-generic-password", "-s", keychainService, "-a", keychainAccount, "-w"])
    guard result.status == 0, let raw = Data(base64Encoded: result.output) else { return nil }
    return try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func keygen() {
    if let key = storedKey() {
        print("Signing key already exists in Keychain. Public key:")
        print(key.publicKey.rawRepresentation.base64EncodedString())
        return
    }
    let key = Curve25519.Signing.PrivateKey()
    let secret = key.rawRepresentation.base64EncodedString()
    let result = runSecurity(["add-generic-password", "-s", keychainService, "-a", keychainAccount, "-w", secret])
    guard result.status == 0 else { fail("Could not save the signing key to Keychain.") }
    print("Created signing key in Keychain (service \(keychainService)). Public key:")
    print(key.publicKey.rawRepresentation.base64EncodedString())
}

func sign(_ path: String) {
    guard let key = storedKey() else { fail("No signing key in Keychain. Run: bluehat-sign keygen") }
    let source = URL(fileURLWithPath: path)
    guard
        let sourceData = try? Data(contentsOf: source),
        var object = (try? JSONSerialization.jsonObject(with: sourceData)) as? [String: Any]
    else { fail("Cannot read \(path) as a JSON object.") }
    object["issued"] = ISO8601DateFormatter().string(from: .now)
    guard let payload = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else {
        fail("Cannot encode the rules.")
    }
    let rulebook: Rulebook
    do {
        rulebook = try Rulebook.decode(from: payload)
    } catch {
        fail("Refusing to sign: \(error.localizedDescription)")
    }
    guard let signature = try? key.signature(for: payload) else { fail("Signing failed.") }
    let envelope = SignedEnvelope(rules: payload.base64EncodedString(), signature: signature.base64EncodedString())
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let target = source.deletingPathExtension().appendingPathExtension("signed.json")
    guard let encoded = try? encoder.encode(envelope), (try? encoded.write(to: target, options: .atomic)) != nil else {
        fail("Cannot write \(target.path).")
    }
    print("Signed v\(rulebook.version) with \(rulebook.rules.count) rules, issued \(object["issued"] ?? "") -> \(target.path)")
}

let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case "keygen" where arguments.count == 1:
    keygen()
case "sign" where arguments.count == 2:
    sign(arguments[1])
default:
    fail("Usage: bluehat-sign keygen | bluehat-sign sign <rules.json>")
}
