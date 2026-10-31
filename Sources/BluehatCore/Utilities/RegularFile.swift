import Foundation

enum RegularFile {
    /// Opens a regular file for reading and returns it with its size, or nil for anything else (missing, FIFO, device, directory).
    /// Never blocks on a FIFO. Pass followingSymlinks false to refuse a symlink as the last path component.
    static func open(atPath path: String, followingSymlinks: Bool) -> (handle: FileHandle, size: Int)? {
        let flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | (followingSymlinks ? 0 : O_NOFOLLOW)
        let descriptor = Darwin.open(path, flags)
        guard descriptor >= 0 else { return nil }
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            return nil
        }
        return (FileHandle(fileDescriptor: descriptor, closeOnDealloc: true), Int(status.st_size))
    }

    /// Reads a whole regular file, or returns nil when it can't be opened with `open(atPath:followingSymlinks:)` or is larger than maxBytes.
    /// The size is checked before any byte is read.
    static func read(atPath path: String, maxBytes: Int, followingSymlinks: Bool) -> Data? {
        guard let file = open(atPath: path, followingSymlinks: followingSymlinks), file.size <= maxBytes else { return nil }
        defer { try? file.handle.close() }
        do {
            return try file.handle.read(upToCount: maxBytes) ?? Data()
        } catch {
            return nil
        }
    }
}
