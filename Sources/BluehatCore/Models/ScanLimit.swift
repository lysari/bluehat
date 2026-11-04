import Foundation

public struct ScanLimit: Sendable, Hashable, Identifiable {
    public enum Area: CaseIterable, Sendable, Identifiable {
        case files, fingerprints, projectFolders, signing, systemTools, deepScan, history

        public var id: Self {
            self
        }

        public var title: String {
            switch self {
            case .files: "Files"
            case .fingerprints: "Fingerprints"
            case .projectFolders: "Project folders"
            case .signing: "Signing and Gatekeeper"
            case .systemTools: "System tools"
            case .deepScan: "Deep Scan"
            case .history: "History and notices"
            }
        }
    }

    public enum Unit: Sendable, Hashable {
        case megabytes
        case seconds
        case count(noun: String)
    }

    static let bytesPerMegabyte = 1_000_000
    static let megabyteFractionDigits = 6
    static let longestEnteredWholePart = 12

    public let key: String
    public let area: Area
    public let title: String
    public let help: String
    public let unit: Unit
    public let defaultValue: Int
    public let range: ClosedRange<Int>

    public var id: String {
        key
    }

    public var unitLabel: String {
        switch unit {
        case .megabytes: "MB"
        case .seconds: "seconds"
        case .count(let noun): "\(noun)s"
        }
    }

    public var refusalMessage: String {
        "Enter a number from \(editableText(for: range.lowerBound)) to \(text(for: range.upperBound))."
    }

    public func text(for value: Int, locale: Locale = .current) -> String {
        let number = editableText(for: value, locale: locale)
        switch unit {
        case .megabytes: return "\(number) MB"
        case .seconds: return "\(number) second\(value == 1 ? "" : "s")"
        case .count(let noun): return "\(number) \(noun)\(value == 1 ? "" : "s")"
        }
    }

    public func editableText(for value: Int, locale: Locale = .current) -> String {
        switch unit {
        case .megabytes:
            let style = FloatingPointFormatStyle<Double>.number.precision(.fractionLength(0...Self.megabyteFractionDigits)).grouping(.never).locale(locale)
            return (Double(value) / Double(Self.bytesPerMegabyte)).formatted(style)
        case .seconds, .count:
            return value.formatted(.number.locale(locale))
        }
    }

    public func value(entered text: String, locale: Locale = .current) -> Int? {
        var whole = ""
        var fraction = ""
        var isInFraction = false
        for character in text.trimmingCharacters(in: .whitespacesAndNewlines) {
            if character.unicodeScalars.count == 1, character.unicodeScalars.first?.properties.generalCategory == .decimalNumber, let digit = character.wholeNumberValue {
                if isInFraction { fraction += String(digit) } else { whole += String(digit) }
            } else if unit == .megabytes, !isInFraction, character == "." || String(character) == locale.decimalSeparator {
                isInFraction = true
            } else if unit == .megabytes || !(character.isWhitespace || String(character) == locale.groupingSeparator) {
                return nil
            }
        }
        guard !(whole + fraction).isEmpty, whole.count <= Self.longestEnteredWholePart else { return nil }
        let wholeValue = Int(whole) ?? 0
        guard unit == .megabytes else { return wholeValue }
        let digits = fraction.prefix(Self.megabyteFractionDigits).padding(toLength: Self.megabyteFractionDigits, withPad: "0", startingAt: 0)
        return wholeValue * Self.bytesPerMegabyte + (Int(digits) ?? 0)
    }

    public static let maxReadBytes = ScanLimit(
        key: "maxReadBytes",
        area: .files,
        title: "Text and plist files",
        help: "How much of a shell profile, launch item, extension manifest or config file is read. Raising costs memory and time. Lowering can skip a launch item or leave the end of a file unread.",
        unit: .megabytes,
        defaultValue: 1_000_000,
        range: 250_000...5_000_000
    )
    public static let maxManifestBytes = ScanLimit(
        key: "maxManifestBytes",
        area: .files,
        title: "package.json files",
        help: "Largest package.json that is read. Raising costs about 3.5 times the file's size while it is parsed. Lowering skips bigger packages, so their versions aren't checked.",
        unit: .megabytes,
        defaultValue: 1_000_000,
        range: 250_000...10_000_000
    )
    public static let maxLockfileBytes = ScanLimit(
        key: "maxLockfileBytes",
        area: .files,
        title: "Lockfiles",
        help: "Largest npm, Yarn or pnpm lockfile that is read. Raising costs about 3.5 times the file's size while it is parsed. Lowering skips bigger lockfiles and lists them under Not Scanned.",
        unit: .megabytes,
        defaultValue: 30_000_000,
        range: 5_000_000...100_000_000
    )
    public static let maxExtensionIndexBytes = ScanLimit(
        key: "maxExtensionIndexBytes",
        area: .files,
        title: "Firefox extension lists",
        help: "Largest extensions.json that is read. Raising costs memory while it is parsed. Lowering skips bigger lists, so those Firefox extensions aren't checked.",
        unit: .megabytes,
        defaultValue: 10_000_000,
        range: 1_000_000...50_000_000
    )
    public static let maxMatchedLength = ScanLimit(
        key: "maxMatchedLength",
        area: .files,
        title: "Line length matched by rules",
        help: "How much of each line the rules look at. Raising lets a crafted line slow the scan sharply: double the length can take about 8 times as long. Lowering lets malware hide behind a shorter padded line.",
        unit: .count(noun: "character"),
        defaultValue: 8_192,
        range: 4_096...16_384
    )
    public static let maxDependencyDepth = ScanLimit(
        key: "maxDependencyDepth",
        area: .files,
        title: "Lockfile nesting",
        help: "How many levels of an old-format npm lockfile are followed. Raising costs a little time on a crafted file. Lowering leaves deeply nested packages unchecked.",
        unit: .count(noun: "level"),
        defaultValue: 32,
        range: 8...128
    )
    public static let maxHashedFileBytes = ScanLimit(
        key: "maxHashedFileBytes",
        area: .fingerprints,
        title: "Largest file fingerprinted",
        help: "Largest file in Downloads, Desktop, Shared and tmp that gets a fingerprint. Raising costs disk reads and time. Lowering skips bigger files and lists them under Not Scanned, so a large malware sample could go unseen.",
        unit: .megabytes,
        defaultValue: 50_000_000,
        range: 10_000_000...500_000_000
    )
    public static let maxHashedFilesPerDirectory = ScanLimit(
        key: "maxHashedFilesPerDirectory",
        area: .fingerprints,
        title: "Files per folder",
        help: "How many of the newest files in each folder get a fingerprint. Raising costs disk reads and time. Lowering leaves older files unchecked and lists the folder under Not Scanned.",
        unit: .count(noun: "file"),
        defaultValue: 50_000,
        range: 1_000...200_000
    )
    public static let maxHashDepth = ScanLimit(
        key: "maxHashDepth",
        area: .fingerprints,
        title: "Folder depth",
        help: "How many folder levels are looked through for fingerprints. Raising costs time and memory on large folders. Lowering skips deeper files and lists their folders under Not Scanned.",
        unit: .count(noun: "level"),
        defaultValue: 6,
        range: 2...12
    )
    public static let maxProjectDepth = ScanLimit(
        key: "maxProjectDepth",
        area: .projectFolders,
        title: "Folder depth",
        help: "How many levels below each project folder are searched for projects. Raising costs time. Lowering misses deeper projects and lists their folders under Not Scanned.",
        unit: .count(noun: "level"),
        defaultValue: 6,
        range: 2...16
    )
    public static let maxFoldersPerProjectFolder = ScanLimit(
        key: "maxFoldersPerProjectFolder",
        area: .projectFolders,
        title: "Folders per project folder",
        help: "How many folders are listed in each project folder. Raising costs memory and time. Lowering stops the search earlier and lists the folder under Not Scanned.",
        unit: .count(noun: "folder"),
        defaultValue: 50_000,
        range: 1_000...250_000
    )
    public static let maxFileNamesPerProjectFolder = ScanLimit(
        key: "maxFileNamesPerProjectFolder",
        area: .projectFolders,
        title: "File names per project folder",
        help: "How many file names of projects are remembered in each project folder. Raising costs memory. Lowering stops the search earlier and lists the folder under Not Scanned.",
        unit: .count(noun: "file name"),
        defaultValue: 200_000,
        range: 10_000...1_000_000
    )
    public static let maxModuleDepth = ScanLimit(
        key: "maxModuleDepth",
        area: .projectFolders,
        title: "Global package nesting",
        help: "How many nested node_modules are followed under global npm packages. Raising costs time. Lowering leaves deeply nested packages unchecked with no notice.",
        unit: .count(noun: "level"),
        defaultValue: 8,
        range: 2...32
    )
    public static let maxGlobalPackages = ScanLimit(
        key: "maxGlobalPackages",
        area: .projectFolders,
        title: "Global packages",
        help: "How many global npm packages are read. Raising costs time and memory. Lowering leaves the rest unchecked and lists the folder under Not Scanned.",
        unit: .count(noun: "package"),
        defaultValue: 20_000,
        range: 1_000...200_000
    )
    public static let signatureOpenTimeout = ScanLimit(
        key: "signatureOpenTimeout",
        area: .signing,
        title: "Time to open an item",
        help: "How long opening an item for a signature check may take. Raising makes a planted trap cost more scan time. Lowering can report a slow disk as a problem.",
        unit: .seconds,
        defaultValue: 20,
        range: 5...120
    )
    public static let signatureCheckTimeout = ScanLimit(
        key: "signatureCheckTimeout",
        area: .signing,
        title: "Time to check a signature",
        help: "How long checking a large app's signature may take. Raising makes a stuck check cost more scan time. Lowering can report a large app such as Xcode as a problem.",
        unit: .seconds,
        defaultValue: 300,
        range: 60...1_800
    )
    public static let maxStuckPathsPerScan = ScanLimit(
        key: "maxStuckPathsPerScan",
        area: .signing,
        title: "Stuck items per scan",
        help: "How many items may get stuck before the other signature checks in that scan are skipped. Raising costs scan time and a blocked thread each. Lowering skips the checks sooner and lists them under Not Scanned.",
        unit: .count(noun: "item"),
        defaultValue: 5,
        range: 1...25
    )
    public static let maxNotarizationAssessments = ScanLimit(
        key: "maxNotarizationAssessments",
        area: .signing,
        title: "Gatekeeper questions per scan",
        help: "How many new or changed apps Gatekeeper is asked about in one scan. Raising makes a scan take longer. Lowering leaves more apps for later scans and lists them under Not Scanned.",
        unit: .count(noun: "app"),
        defaultValue: 5,
        range: 1...50
    )
    public static let notarizationTimeout = ScanLimit(
        key: "notarizationTimeout",
        area: .signing,
        title: "Time for a Gatekeeper answer",
        help: "How long one Gatekeeper answer may take. Raising makes a slow network cost more scan time. Lowering ends that scan's questions sooner and lists the apps under Not Scanned.",
        unit: .seconds,
        defaultValue: 20,
        range: 5...120
    )
    public static let networkPathTimeout = ScanLimit(
        key: "networkPathTimeout",
        area: .signing,
        title: "Time to check the network",
        help: "How long Bluehat waits to learn whether the network is up before asking Gatekeeper. Raising costs scan time when offline. Lowering can treat a slow answer as offline, and the apps wait for a later scan.",
        unit: .seconds,
        defaultValue: 2,
        range: 1...30
    )
    public static let maxNotarizationCacheBytes = ScanLimit(
        key: "maxNotarizationCacheBytes",
        area: .signing,
        title: "Saved Gatekeeper answers",
        help: "Largest file of saved Gatekeeper answers that is read. Raising costs memory on a crafted file. Lowering can discard the answers, so Gatekeeper is asked again over later scans.",
        unit: .megabytes,
        defaultValue: 5_000_000,
        range: 1_000_000...20_000_000
    )
    public static let toolTimeout = ScanLimit(
        key: "toolTimeout",
        area: .systemTools,
        title: "Time for a system tool",
        help: "How long a tool such as ps or lsof may run. Raising makes a stuck tool cost more scan time. Lowering can cut off a slow tool: its check then finds nothing, and the tool is listed under Not Scanned.",
        unit: .seconds,
        defaultValue: 60,
        range: 15...300
    )
    public static let toolKillDelay = ScanLimit(
        key: "toolKillDelay",
        area: .systemTools,
        title: "Time to stop a tool",
        help: "How long a tool past its time gets to quit before it is killed. Raising costs scan time on a stuck tool. Lowering gives it less time to clean up.",
        unit: .seconds,
        defaultValue: 2,
        range: 1...30
    )
    public static let maxFindings = ScanLimit(
        key: "maxFindings",
        area: .deepScan,
        title: "Findings kept from the disk",
        help: "How many matches a Deep Scan keeps from its walk of the disk, most severe first. Raising costs memory and leaves room for fewer past scans in history. Lowering leaves more out and says so in a notice.",
        unit: .count(noun: "finding"),
        defaultValue: 1_000,
        range: 100...10_000
    )
    public static let maxHistoryRecords = ScanLimit(
        key: "maxHistoryRecords",
        area: .history,
        title: "Scans kept",
        help: "How many past scans are kept. Raising costs memory and disk space. Lowering removes the oldest scans at the next scan.",
        unit: .count(noun: "scan"),
        defaultValue: 30,
        range: 5...200
    )
    public static let maxHistoryFileBytes = ScanLimit(
        key: "maxHistoryFileBytes",
        area: .history,
        title: "History file",
        help: "Largest size of the saved history. Raising costs memory for as long as Bluehat is open. Lowering removes the oldest scans at the next scan.",
        unit: .megabytes,
        defaultValue: 20_000_000,
        range: 1_000_000...50_000_000
    )
    public static let maxDetailLength = ScanLimit(
        key: "maxDetailLength",
        area: .history,
        title: "Finding detail length",
        help: "How much of a finding's detail is kept and shown. Raising costs a little memory. Lowering cuts long paths shorter. Changing it can show long findings once as new and resolved in History.",
        unit: .count(noun: "character"),
        defaultValue: 200,
        range: 100...1_000
    )
    public static let maxNoticePaths = ScanLimit(
        key: "maxNoticePaths",
        area: .history,
        title: "Paths named in a notice",
        help: "How many names a scan notice lists before it says \"and N more\". Raising makes notices longer. Lowering names fewer, but the count stays. The Not Scanned list has its own limit.",
        unit: .count(noun: "path"),
        defaultValue: 3,
        range: 1...20
    )
    public static let maxNotScannedEntries = ScanLimit(
        key: "maxNotScannedEntries",
        area: .history,
        title: "Not Scanned list size",
        help: "How many items the Not Scanned list keeps for the latest scan. Raising costs memory and a slower search. Lowering lists fewer, keeping your home folder first, but the total stays true and the list says how many were left out.",
        unit: .count(noun: "item"),
        defaultValue: 10_000,
        range: 1_000...50_000
    )

    public static let all: [ScanLimit] = [
        maxReadBytes, maxManifestBytes, maxLockfileBytes, maxExtensionIndexBytes, maxMatchedLength, maxDependencyDepth,
        maxHashedFileBytes, maxHashedFilesPerDirectory, maxHashDepth,
        maxProjectDepth, maxFoldersPerProjectFolder, maxFileNamesPerProjectFolder, maxModuleDepth, maxGlobalPackages,
        signatureOpenTimeout, signatureCheckTimeout, maxStuckPathsPerScan, maxNotarizationAssessments, notarizationTimeout, networkPathTimeout, maxNotarizationCacheBytes,
        toolTimeout, toolKillDelay,
        maxFindings,
        maxHistoryRecords, maxHistoryFileBytes, maxDetailLength, maxNoticePaths, maxNotScannedEntries,
    ]
}
