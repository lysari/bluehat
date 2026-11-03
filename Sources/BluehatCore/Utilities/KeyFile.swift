import CryptoKit
import Foundation

public enum KeyFileError: LocalizedError, Equatable {
    case noFileName(String)
    case folderNotFound(String)
    case insideRepository(String)
    case alreadyExists(String)
    case notOwnerOnly(String)
    case couldNotWrite(String)

    public var errorDescription: String? {
        switch self {
        case .noFileName(let path): "\(path) doesn't name a file."
        case .folderNotFound(let path): "The folder for \(path) doesn't exist."
        case .insideRepository(let folder): "Refusing to write a private key inside the repository at \(folder). Choose a path outside it."
        case .alreadyExists(let path): "\(path) already exists. Refusing to overwrite a key."
        case .notOwnerOnly(let path): "\(path) can't be made readable only by you here, so no key was written. Choose a folder on an APFS or Mac OS Extended volume."
        case .couldNotWrite(let path): "Cannot create \(path)."
        }
    }
}

public enum KeyFile {
    static let repositoryMarkers = [".git", "Package.swift"]

    /// Creates a new Ed25519 signing key in a new owner-only (0600) file and returns it. Pass a path outside every repository.
    /// Refuses an existing file or symlink, and a folder inside a Git repository or Swift package once symlinks are resolved. Never touches the Keychain.
    public static func create(atPath path: String) throws(KeyFileError) -> Curve25519.Signing.PrivateKey {
        let file = try resolvedTarget(of: path)
        let descriptor = open(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw errno == EEXIST ? .alreadyExists(path) : .couldNotWrite(path) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & 0o777 == 0o600 else {
            unlink(file)
            throw .notOwnerOnly(path)
        }
        let key = Curve25519.Signing.PrivateKey()
        do {
            try handle.write(contentsOf: Data((key.rawRepresentation.base64EncodedString() + "\n").utf8))
            try handle.synchronize()
            try handle.close()
        } catch {
            unlink(file)
            throw .couldNotWrite(path)
        }
        guard read(atPath: file)?.rawRepresentation == key.rawRepresentation else {
            unlink(file)
            throw .couldNotWrite(path)
        }
        return key
    }

    /// Reads a signing key from a file `create(atPath:)` wrote. Returns nil when the file is unreadable or holds no key.
    public static func read(atPath path: String) -> Curve25519.Signing.PrivateKey? {
        guard
            let text = try? String(contentsOfFile: path, encoding: .utf8),
            let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    }

    private static func resolvedTarget(of path: String) throws(KeyFileError) -> String {
        let name = (path as NSString).lastPathComponent
        guard !path.hasSuffix("/"), !["", ".", ".."].contains(name) else { throw .noFileName(path) }
        let parent = (path as NSString).deletingLastPathComponent
        guard let resolved = realpath(parent.isEmpty ? "." : parent, nil) else { throw .folderNotFound(path) }
        defer { free(resolved) }
        let folder = String(cString: resolved)
        // Looks for markers on disk instead of comparing path text, so letter case and firmlinks can't slip past it.
        let ancestors = sequence(first: folder) { $0 == "/" ? nil : ($0 as NSString).deletingLastPathComponent }
        let repository = ancestors.first { ancestor in
            repositoryMarkers.contains { FileManager.default.fileExists(atPath: (ancestor as NSString).appendingPathComponent($0)) }
        }
        if let repository { throw .insideRepository(repository) }
        return (folder as NSString).appendingPathComponent(name)
    }
}
