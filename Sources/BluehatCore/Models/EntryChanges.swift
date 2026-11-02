public struct EntryChanges<Entry: Sendable & Equatable>: Sendable {
    public let added: [Entry]
    public let changed: [Entry]
    public let removed: [Entry]

    public var isEmpty: Bool {
        added.isEmpty && changed.isEmpty && removed.isEmpty
    }

    init(from local: [Entry], to remote: [Entry], key: (Entry) -> String) {
        let localByKey = Dictionary(local.map { (key($0), $0) }, uniquingKeysWith: { first, _ in first })
        let remoteKeys = Set(remote.map(key))
        var seen = Set<String>()
        var added: [Entry] = []
        var changed: [Entry] = []
        for entry in remote where seen.insert(key(entry)).inserted {
            guard let localEntry = localByKey[key(entry)] else {
                added.append(entry)
                continue
            }
            if localEntry != entry { changed.append(entry) }
        }
        self.added = added
        self.changed = changed
        var seenRemoved = Set<String>()
        removed = local.filter { !remoteKeys.contains(key($0)) && seenRemoved.insert(key($0)).inserted }
    }
}

public struct MalwareFeedChanges: Sendable {
    public let hashes: EntryChanges<MalwareHash>
    public let packages: EntryChanges<MalwarePackage>
    public let hosts: EntryChanges<MalwareHost>
}
