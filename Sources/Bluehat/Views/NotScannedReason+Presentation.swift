import BluehatCore

extension NotScannedReason {
    var symbol: String {
        switch self {
        case .noPermission: "lock"
        case .couldNotRead: "questionmark.folder"
        case .overSizeLimit: "scalemass"
        case .partlyRead: "doc.plaintext"
        case .overCountLimit: "number"
        case .overDepthLimit: "arrow.down.to.line"
        case .cloudOnly: "icloud"
        case .timedOut: "clock"
        case .signatureCheckSkipped: "signature"
        case .gatekeeperNotAsked: "checkmark.seal"
        case .filePatternNotOpened: "asterisk"
        case .notSafeToParse: "curlybraces"
        case .couldNotParse: "doc.questionmark"
        }
    }
}
