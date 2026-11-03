import BluehatCore
import CryptoKit
import Foundation

let keychainService = "bluehat-rules-signing"
let updateKeychainService = "bluehat-update-signing"
let keychainAccount = "bluehat"
let noUpdateKeyStatus: Int32 = 3
let usage = "Usage: bluehat-sign keygen | bluehat-sign backup-keygen <key file> | bluehat-sign sign <rules.json> [--key-file <key file>] | bluehat-sign update-keygen | bluehat-sign update-keygen --backup <key file> | bluehat-sign sign-update <dmg> <version> [--key-file <key file>]"

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

func storedKey(service: String = keychainService) -> Curve25519.Signing.PrivateKey? {
    let result = runSecurity(["find-generic-password", "-s", service, "-a", keychainAccount, "-w"])
    guard result.status == 0, let raw = Data(base64Encoded: result.output) else { return nil }
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

func createStoredKey(service: String) -> Curve25519.Signing.PrivateKey {
    let key = Curve25519.Signing.PrivateKey()
    let secret = key.rawRepresentation.base64EncodedString()
    let result = runSecurity(["add-generic-password", "-s", service, "-a", keychainAccount, "-T", "", "-w"], input: "\(secret)\n\(secret)\n")
    guard result.status == 0, storedKey(service: service)?.rawRepresentation == key.rawRepresentation else { fail("Could not save the signing key to Keychain.") }
    print("Created signing key in Keychain (service \(service)).")
    return key
}

func keygen() {
    if let key = storedKey() {
        print("Signing key already exists in Keychain (service \(keychainService)).")
        describe(key)
        return
    }
    describe(createStoredKey(service: keychainService))
}

func describeUpdateKey(_ key: Curve25519.Signing.PrivateKey) {
    print("Public key: \(key.publicKey.rawRepresentation.base64EncodedString())")
    print("Fingerprint: \(RuleFeed.fingerprint(of: key.publicKey))")
    let isTrusted = AppUpdater.trustedKeys.contains { $0.rawRepresentation == key.publicKey.rawRepresentation }
    print(isTrusted ? "The app trusts this key for updates." : "The app does not trust this key yet. Add the public key to AppUpdater.trustedKeys and rebuild.")
}

func updateKeygen() {
    if let key = storedKey(service: updateKeychainService) {
        print("Update signing key already exists in Keychain (service \(updateKeychainService)).")
        describeUpdateKey(key)
        return
    }
    describeUpdateKey(createStoredKey(service: updateKeychainService))
}

func updateBackupKeygen(_ path: String) {
    let key: Curve25519.Signing.PrivateKey
    do {
        key = try KeyFile.create(atPath: path)
    } catch {
        fail(error.localizedDescription)
    }
    print("Public key: \(key.publicKey.rawRepresentation.base64EncodedString())")
    print("Fingerprint: \(RuleFeed.fingerprint(of: key.publicKey))")
    print("Move \(path) offline now, for example to an encrypted USB drive, and keep it out of every repository.")
}

func signUpdate(_ path: String, version: String, keyFile: String?) {
    guard !AppUpdater.trustedKeys.isEmpty else {
        FileHandle.standardError.write(Data("This build has no update key in AppUpdater.trustedKeys. Run: bluehat-sign update-keygen, then add its public key and rebuild.\n".utf8))
        exit(noUpdateKeyStatus)
    }
    let loadedKey = keyFile.map(KeyFile.read(atPath:)) ?? storedKey(service: updateKeychainService)
    guard let key = loadedKey else {
        fail(keyFile.map { "Cannot read a signing key from \($0)." } ?? "No update signing key in Keychain. Run: bluehat-sign update-keygen")
    }
    guard AppUpdater.trustedKeys.contains(where: { $0.rawRepresentation == key.publicKey.rawRepresentation }) else {
        fail("Refusing to sign: the app does not trust update key \(RuleFeed.fingerprint(of: key.publicKey)), so installed apps would reject this update.")
    }
    let image = URL(fileURLWithPath: path)
    let target = URL(fileURLWithPath: path + AppUpdater.signatureSuffix)
    do throws(AppUpdateError) {
        let signed = try AppUpdater.sign(imageAt: image, version: version, with: key)
        try AppUpdater.standard.confirmSigned(signed, imageAt: image, version: version)
        guard (try? signed.write(to: target, options: .atomic)) != nil else { fail("Cannot write \(target.path).") }
    } catch {
        fail("Refusing to sign \(path) as version \(version): \(error.localizedDescription)")
    }
    print("Signed update \(version) using key \(RuleFeed.fingerprint(of: key.publicKey)) -> \(target.path)")
}

func backupKeygen(_ path: String) {
    let key: Curve25519.Signing.PrivateKey
    do {
        key = try KeyFile.create(atPath: path)
    } catch {
        fail(error.localizedDescription)
    }
    print("Created backup signing key at \(path) (readable only by you). Keep it offline, for example on an encrypted USB drive, and never commit it.")
    describe(key)
}

func sign(_ path: String, keyFile: String?) {
    let loadedKey = keyFile.map(KeyFile.read(atPath:)) ?? storedKey()
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
case "update-keygen" where arguments.count == 1:
    updateKeygen()
case "update-keygen" where arguments.count == 3 && arguments[1] == "--backup":
    updateBackupKeygen(arguments[2])
case "sign-update" where arguments.count == 3:
    signUpdate(arguments[1], version: arguments[2], keyFile: nil)
case "sign-update" where arguments.count == 5 && arguments[3] == "--key-file":
    signUpdate(arguments[1], version: arguments[2], keyFile: arguments[4])
default:
    fail(usage)
}
