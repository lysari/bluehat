import Foundation

public enum ProtectedLocation {
    static let roots = ["/System", "/usr", "/bin", "/sbin", "/Library", "/private/var", "/var"]

    /// Says whether moving a path would disturb a critical system location. Call it right before a move; it checks the path as written and with the symlinks in its parent folders resolved.
    public static func contains(_ path: String) -> Bool {
        isListed(path) || resolvedPath(path).map(isListed) == true
    }

    /// Says whether a path as written is a critical system location, is inside one, or holds one. Compares without case, since the startup disk usually ignores it.
    static func isListed(_ path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path.replacing(/\/+/, with: "/")).standardized.path.lowercased()
        let folder = standardized.hasSuffix("/") ? standardized : standardized + "/"
        return roots.contains { root in
            let rootFolder = root.lowercased() + "/"
            return folder.hasPrefix(rootFolder) || rootFolder.hasPrefix(folder)
        }
    }

    /// Resolves the symlinks in a path's parent folders and keeps its last component as written, since a move takes a link itself rather than its target. Gives nil when the parent doesn't exist.
    static func resolvedPath(_ path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        guard let resolved = realpath(url.deletingLastPathComponent().path, nil) else { return nil }
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved), isDirectory: true).appending(path: url.lastPathComponent).path
    }
}
