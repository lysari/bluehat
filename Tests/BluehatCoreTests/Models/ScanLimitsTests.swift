import Foundation
import Testing
@testable import BluehatCore

struct ScanLimitsTests {
    static let oldConstants: [String: Int] = [
        "maxReadBytes": 1_000_000,
        "maxManifestBytes": 1_000_000,
        "maxLockfileBytes": 30_000_000,
        "maxExtensionIndexBytes": 10_000_000,
        "maxMatchedLength": 8_192,
        "maxDependencyDepth": 32,
        "maxHashedFileBytes": 50_000_000,
        "maxHashedFilesPerDirectory": 50_000,
        "maxHashDepth": 6,
        "maxProjectDepth": 6,
        "maxFoldersPerProjectFolder": 50_000,
        "maxFileNamesPerProjectFolder": 200_000,
        "maxModuleDepth": 8,
        "maxGlobalPackages": 20_000,
        "signatureOpenTimeout": 20,
        "signatureCheckTimeout": 300,
        "maxStuckPathsPerScan": 5,
        "maxNotarizationAssessments": 5,
        "notarizationTimeout": 20,
        "networkPathTimeout": 2,
        "maxNotarizationCacheBytes": 5_000_000,
        "toolTimeout": 60,
        "toolKillDelay": 2,
        "maxFindings": 1_000,
        "maxDeepScanMemoryBytes": 1_500_000_000,
        "maxHistoryRecords": 30,
        "maxHistoryFileBytes": 20_000_000,
        "maxDetailLength": 200,
        "maxNoticePaths": 3,
        "maxNotScannedEntries": 10_000,
    ]

    let englishUS = Locale(identifier: "en_US")
    let german = Locale(identifier: "de_DE")

    @Test func theDeepScanMemoryLimitHasItsDefaultAndRange() {
        let limit = ScanLimit.maxDeepScanMemoryBytes
        #expect(limit.area == .deepScan)
        #expect(limit.title == "Deep Scan memory limit")
        #expect(limit.defaultValue == 1_500_000_000)
        #expect(limit.range == 512_000_000...8_000_000_000)
        #expect(ScanLimits.defaults.setting(limit, to: limit.range.lowerBound - 1) == nil)
        #expect(ScanLimits.defaults.setting(limit, to: limit.range.upperBound + 1) == nil)
        #expect(ScanLimits.load(saved: [limit.key: limit.range.upperBound + 1]).limits[limit] == limit.defaultValue)
        #expect(limit.text(for: limit.defaultValue, locale: englishUS) == "1500 MB")
    }

    @Test func defaultsMatchTheOldConstantsExactly() {
        #expect(Dictionary(uniqueKeysWithValues: ScanLimit.all.map { ($0.key, $0.defaultValue) }) == Self.oldConstants)
        #expect(ScanLimit.all.count == Self.oldConstants.count)
        #expect(ScanLimits.defaults.isDefault)
        #expect(ScanLimits.defaults.savedValues.isEmpty)
        for limit in ScanLimit.all {
            #expect(ScanLimits.defaults[limit] == Self.oldConstants[limit.key])
        }
    }

    @Test func everyLimitHasARangeThatHoldsItsDefaultAndCanNotReachZero() {
        for limit in ScanLimit.all {
            #expect(limit.range.lowerBound > 0, "\(limit.key)")
            #expect(limit.range.lowerBound < limit.defaultValue, "\(limit.key)")
            #expect(limit.defaultValue < limit.range.upperBound, "\(limit.key)")
        }
    }

    @Test func everyLimitIsDescribedAndGrouped() {
        for limit in ScanLimit.all {
            #expect(!limit.title.isEmpty, "\(limit.key)")
            #expect(limit.help.contains("Raising"), "\(limit.key)")
            #expect(limit.help.contains("Lowering"), "\(limit.key)")
        }
        #expect(Set(ScanLimit.all.map(\.area)) == Set(ScanLimit.Area.allCases))
    }

    @Test func notSavedLoadsTheDefaultsWithNoNotice() {
        let loaded = ScanLimits.load(saved: nil)
        #expect(loaded.limits == .defaults)
        #expect(loaded.notice == nil)
    }

    @Test func aMissingLimitIsTheDefaultWithNoNotice() {
        let loaded = ScanLimits.load(saved: ["maxManifestBytes": 2_000_000])
        #expect(loaded.limits[.maxManifestBytes] == 2_000_000)
        #expect(loaded.limits[.maxLockfileBytes] == ScanLimit.maxLockfileBytes.defaultValue)
        #expect(loaded.notice == nil)
    }

    @Test func savedValuesLoadBackTheSame() throws {
        let limits = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 2_000_000)?.setting(.toolTimeout, to: 90))
        let loaded = ScanLimits.load(saved: limits.savedValues)
        #expect(loaded.limits == limits)
        #expect(loaded.notice == nil)
    }

    @Test func eachBoundLoads() {
        for limit in ScanLimit.all {
            for value in [limit.range.lowerBound, limit.range.upperBound] {
                let loaded = ScanLimits.load(saved: [limit.key: value])
                #expect(loaded.limits[limit] == value, "\(limit.key)")
                #expect(loaded.notice == nil, "\(limit.key)")
            }
        }
    }

    @Test func outOfRangeFallsBackToTheDefaultNeverAClampedValue() {
        for limit in ScanLimit.all {
            for value in [limit.range.lowerBound - 1, limit.range.upperBound + 1, 0, -1, Int.max] {
                let loaded = ScanLimits.load(saved: [limit.key: value])
                #expect(loaded.limits[limit] == limit.defaultValue, "\(limit.key) \(value)")
                #expect(loaded.notice?.contains(limit.title) == true, "\(limit.key) \(value)")
            }
        }
    }

    @Test func wrongTypesFallBackToTheDefaultWithANotice() {
        let wrongTypes: [Any] = ["2000000", true, false, 2_000_000.0, 2_000_000.5, [2_000_000], ["value": 2_000_000], NSNull(), Date.now, Data(), UInt64.max]
        for saved in wrongTypes {
            let loaded = ScanLimits.load(saved: ["maxManifestBytes": saved, "toolTimeout": 90])
            #expect(loaded.limits[.maxManifestBytes] == ScanLimit.maxManifestBytes.defaultValue, "\(saved)")
            #expect(loaded.limits[.toolTimeout] == 90, "\(saved)")
            #expect(loaded.notice == "Bluehat used the default for saved limits that were out of range or the wrong type: package.json files.", "\(saved)")
        }
    }

    @Test func aSavedValueThatIsNoDictionaryFallsBackWithANotice() {
        let wrongTypes: [Any] = ["text", 5, ["maxManifestBytes"], Data()]
        for saved in wrongTypes {
            let loaded = ScanLimits.load(saved: saved)
            #expect(loaded.limits == .defaults, "\(saved)")
            #expect(loaded.notice == "Bluehat couldn't read the saved limits and used the defaults for all of them.", "\(saved)")
        }
    }

    @Test func anUnknownSavedLimitIsLeftOut() {
        let loaded = ScanLimits.load(saved: ["maxAppUpdateBytes": 1])
        #expect(loaded.limits == .defaults)
        #expect(loaded.notice == nil)
    }

    @Test func settingRefusesAValueOutOfRange() {
        let limit = ScanLimit.maxManifestBytes
        #expect(ScanLimits.defaults.setting(limit, to: limit.range.lowerBound - 1) == nil)
        #expect(ScanLimits.defaults.setting(limit, to: limit.range.upperBound + 1) == nil)
        #expect(ScanLimits.defaults.setting(limit, to: limit.range.upperBound)?[limit] == limit.range.upperBound)
    }

    @Test func settingTheDefaultAndResettingLeaveNothingChanged() throws {
        let limit = ScanLimit.maxManifestBytes
        let raised = try #require(ScanLimits.defaults.setting(limit, to: 2_000_000))
        #expect(!raised.isDefault)
        #expect(raised.setting(limit, to: limit.defaultValue) == .defaults)
        #expect(raised.resetting(limit) == .defaults)
    }

    @Test func resettingOneLimitKeepsTheOthers() throws {
        let limits = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 2_000_000)?.setting(.toolTimeout, to: 90))
        #expect(limits.resetting(.maxManifestBytes).savedValues == ["toolTimeout": 90])
    }

    @Test func showsEachUnitInFriendlyForm() {
        #expect(ScanLimit.maxManifestBytes.text(for: 1_000_000, locale: englishUS) == "1 MB")
        #expect(ScanLimit.maxManifestBytes.text(for: 250_000, locale: englishUS) == "0.25 MB")
        #expect(ScanLimit.maxManifestBytes.text(for: 1_091_575, locale: englishUS) == "1.091575 MB")
        #expect(ScanLimit.toolTimeout.text(for: 60, locale: englishUS) == "60 seconds")
        #expect(ScanLimit.toolKillDelay.text(for: 1, locale: englishUS) == "1 second")
        #expect(ScanLimit.maxHashedFilesPerDirectory.text(for: 50_000, locale: englishUS) == "50,000 files")
        #expect(ScanLimit.maxNoticePaths.text(for: 1, locale: englishUS) == "1 path")
        #expect(ScanLimit.maxManifestBytes.unitLabel == "MB")
        #expect(ScanLimit.toolTimeout.unitLabel == "seconds")
        #expect(ScanLimit.maxFindings.unitLabel == "findings")
    }

    @Test func theRefusalStatesTheAllowedRange() {
        #expect(ScanLimit.maxManifestBytes.refusalMessage.contains(ScanLimit.maxManifestBytes.editableText(for: 250_000)))
        #expect(ScanLimit.maxManifestBytes.refusalMessage.contains(ScanLimit.maxManifestBytes.text(for: 10_000_000)))
        #expect(ScanLimit.maxStuckPathsPerScan.refusalMessage == "Enter a number from 1 to 25 items.")
    }

    @Test func enteredMegabytesBecomeBytes() {
        let limit = ScanLimit.maxManifestBytes
        #expect(limit.value(entered: "1.1", locale: englishUS) == 1_100_000)
        #expect(limit.value(entered: " 2 ", locale: englishUS) == 2_000_000)
        #expect(limit.value(entered: ".5", locale: englishUS) == 500_000)
        #expect(limit.value(entered: "1.091575", locale: englishUS) == 1_091_575)
        #expect(limit.value(entered: "1,5", locale: german) == 1_500_000)
        #expect(limit.value(entered: "1.5", locale: german) == 1_500_000)
    }

    @Test func enteredCountsAcceptGroupingAndAnyScriptsDigits() {
        let limit = ScanLimit.maxHashedFilesPerDirectory
        #expect(limit.value(entered: "50,000", locale: englishUS) == 50_000)
        #expect(limit.value(entered: "50.000", locale: german) == 50_000)
        #expect(limit.value(entered: "១២៣", locale: englishUS) == 123)
        #expect(limit.value(entered: "٤٥", locale: englishUS) == 45)
        #expect(ScanLimit.maxManifestBytes.value(entered: "១.៥", locale: englishUS) == 1_500_000)
    }

    @Test(arguments: ["", " ", "abc", "-5", "+5", "1e3", "1.2.3", "5 MB", ".", "99999999999999999999", "万", "½"])
    func enteredTextThatIsNoNumberIsRefused(text: String) {
        #expect(ScanLimit.maxManifestBytes.value(entered: text, locale: englishUS) == nil)
        #expect(ScanLimit.toolTimeout.value(entered: text, locale: englishUS) == nil)
    }

    @Test func aCountOrTimeRefusesADecimal() {
        #expect(ScanLimit.toolTimeout.value(entered: "1.5", locale: englishUS) == nil)
        #expect(ScanLimit.maxFindings.value(entered: "1.5", locale: englishUS) == nil)
    }

    @Test func everyBoundSurvivesBeingShownAndEntered() {
        for limit in ScanLimit.all {
            for value in [limit.range.lowerBound, limit.defaultValue, limit.range.upperBound] {
                #expect(limit.value(entered: limit.editableText(for: value, locale: englishUS), locale: englishUS) == value, "\(limit.key)")
                #expect(limit.value(entered: limit.editableText(for: value, locale: german), locale: german) == value, "\(limit.key)")
            }
        }
    }

    @Test func noNoticeAtTheDefaults() {
        #expect(ScanLimits.defaults.changedNotice == nil)
    }

    @Test func theNoticeNamesWhatChangedAndSaysWhatWasLowered() throws {
        let limits = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 2_000_000)?.setting(.toolTimeout, to: 30)?.setting(.maxHashDepth, to: 3))
        let notice = try #require(limits.changedNotice)
        let manifest = ScanLimit.maxManifestBytes
        let tool = ScanLimit.toolTimeout
        let depth = ScanLimit.maxHashDepth
        #expect(notice.contains("Files › \(manifest.title) \(manifest.text(for: 2_000_000)) (default \(manifest.text(for: 1_000_000)))"))
        #expect(notice.contains("System tools › \(tool.title) \(tool.text(for: 30)) (default \(tool.text(for: 60)))"))
        #expect(notice.contains("Fingerprints › \(depth.title) \(depth.text(for: 3)) (default \(depth.text(for: 6)))"))
        let lowered = try #require(notice.range(of: "Lowered"))
        let raised = try #require(notice.range(of: "Raised"))
        #expect(lowered.lowerBound < raised.lowerBound)
        #expect(notice.range(of: tool.title)!.lowerBound < raised.lowerBound)
        #expect(notice.range(of: manifest.title)!.lowerBound > raised.lowerBound)
    }

    @Test func aNoticeOfOnlyRaisedLimitsDoesNotClaimAnythingWasMissed() throws {
        let limits = try #require(ScanLimits.defaults.setting(.maxManifestBytes, to: 2_000_000))
        let notice = try #require(limits.changedNotice)
        #expect(!notice.contains("Lowered"))
        #expect(!notice.contains("missed"))
    }
}
