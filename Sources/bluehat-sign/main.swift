import BluehatCore
import CryptoKit
import Foundation

let keychainService = "bluehat-rules-signing"
let keychainAccount = "bluehat"
let usage = "Usage: bluehat-sign keygen | bluehat-sign backup-keygen <key file> | bluehat-sign sign <rules.json> [--key-file <key file>]"

func runSecurity(_ arguments: [String], input: String? = nil) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    process.arguments = arguments
    let output = Pipe()
    let stdin = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    process.standardInput = stdin
    guard (try? process.run()) != nil else { return (-1, "") }
    if let input {
        stdin.fileHandleForWriting.write(Data(input.utf8))
    }
    try? stdin.fileHandleForWriting.close()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
}

func storedKey() -> Curve25519.Signing.PrivateKey? {
    let result = runSecurity(["find-generic-password", "-s", keychainService, "-a", keychainAccount, "-w"])
    guard result.status == 0, let raw = Data(base64Encoded: result.output) else { return nil }
    return try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
}

func fileKey(_ path: String) -> Curve25519.Signing.PrivateKey? {
    guard
        let text = try? String(contentsOfFile: path, encoding: .utf8),
        let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
    else { return nil }
    return try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func describe(_ key: Curve25519.Signing.PrivateKey) {
    print("Public key: \(key.publicKey.rawRepresentation.base64EncodedString())")
    print("Fingerprint: \(RuleFeed.fingerprint(of: key.publicKey))")
    let isTrusted = RuleFeed.trustedKeys.contains { $0.rawRepresentation == key.publicKey.rawRepresentation }
    print(isTrusted ? "The app trusts this key." : "The app does not trust this key yet. Add the public key to RuleFeed.trustedKeys and rebuild.")
}

func keygen() {
    if let key = storedKey() {
        print("Signing key already exists in Keychain (service \(keychainService)).")
        describe(key)
        return
    }
    let key = Curve25519.Signing.PrivateKey()
    let secret = key.rawRepresentation.base64EncodedString()
    let result = runSecurity(["add-generic-password", "-s", keychainService, "-a", keychainAccount, "-w"], input: "\(secret)\n\(secret)\n")
    guard result.status == 0, storedKey()?.rawRepresentation == key.rawRepresentation else { fail("Could not save the signing key to Keychain.") }
    print("Created signing key in Keychain (service \(keychainService)).")
    describe(key)
}

func backupKeygen(_ path: String) {
    let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else {
        fail(errno == EEXIST ? "\(path) already exists. Refusing to overwrite a key." : "Cannot create \(path).")
    }
    let key = Curve25519.Signing.PrivateKey()
    let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
        try file.write(contentsOf: Data((key.rawRepresentation.base64EncodedString() + "\n").utf8))
        try file.close()
    } catch {
        fail("Cannot write \(path).")
    }
    print("Created backup signing key at \(path) (readable only by you). Keep it offline, for example on an encrypted USB drive, and never commit it.")
    describe(key)
}

func sign(_ path: String, keyFile: String?) {
    let loadedKey = keyFile.map(fileKey) ?? storedKey()
    guard let key = loadedKey else {
        fail(keyFile.map { "Cannot read a signing key from \($0)." } ?? "No signing key in Keychain. Run: bluehat-sign keygen")
    }
    guard RuleFeed.trustedKeys.contains(where: { $0.rawRepresentation == key.publicKey.rawRepresentation }) else {
        fail("Refusing to sign: the app does not trust key \(RuleFeed.fingerprint(of: key.publicKey)), so installed apps would reject these rules.")
    }
    let source = URL(fileURLWithPath: path)
    guard
        let sourceData = try? Data(contentsOf: source),
        var object = (try? JSONSerialization.jsonObject(with: sourceData)) as? [String: Any]
    else { fail("Cannot read \(path) as a JSON object.") }
    let issued = Date.now
    let formatter = ISO8601DateFormatter()
    object["issued"] = formatter.string(from: issued)
    object["expires"] = formatter.string(from: issued.addingTimeInterval(Rulebook.validity))
    guard let payload = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else {
        fail("Cannot encode the rules.")
    }
    let rulebook: Rulebook
    do {
        rulebook = try Rulebook.decode(from: payload)
    } catch {
        fail("Refusing to sign: \(error.localizedDescription)")
    }
    guard rulebook.version >= RuleFeed.minimumVersion else {
        fail("Refusing to sign: version \(rulebook.version) is below the app's minimum \(RuleFeed.minimumVersion).")
    }
    do {
        try RuleFeed.checkDates(of: rulebook, now: issued)
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
    print("Signed v\(rulebook.version) with \(rulebook.rules.count) rules using key \(RuleFeed.fingerprint(of: key.publicKey)), issued \(object["issued"] ?? ""), expires \(object["expires"] ?? "") -> \(target.path)")
}

let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case "keygen" where arguments.count == 1:
    keygen()
case "backup-keygen" where arguments.count == 2:
    backupKeygen(arguments[1])
case "sign" where arguments.count == 2:
    sign(arguments[1], keyFile: nil)
case "sign" where arguments.count == 4 && arguments[2] == "--key-file":
    sign(arguments[1], keyFile: arguments[3])
default:
    fail(usage)
}
