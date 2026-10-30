import BluehatCore
import SwiftUI

struct AboutSettingsTab: View {
    let store: ScanStore

    private var appVersion: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String).map { "Version \($0)" } ?? "Development build"
    }

    var body: some View {
        Form {
            Section {
                VStack(spacing: Metrics.spaceSmall) {
                    ShieldEmblem(tint: Palette.brand, face: .symbol("checkmark"), size: Metrics.aboutEmblem, isFloating: false)
                        .padding(.vertical, Metrics.spaceMedium)
                    Text("Bluehat")
                        .font(Typography.welcomeTitle)
                    Text(appVersion)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                .frame(maxWidth: .infinity)
            }
            Section("Rules") {
                LabeledContent("Source") {
                    Link(String(RuleFeed.repositoryURL.path().dropFirst()), destination: RuleFeed.repositoryURL)
                }
                LabeledContent("Verified version", value: store.rulebook.map { String($0.version) } ?? "Not loaded yet")
                LabeledContent("Signed", value: store.rulebook?.issued?.formatted(date: .abbreviated, time: .shortened) ?? "Unknown")
                LabeledContent("Expires", value: store.rulebook?.expires?.formatted(date: .abbreviated, time: .shortened) ?? "Unknown")
                LabeledContent(RuleFeed.trustedKeys.count == 1 ? "Trusted key" : "Trusted keys") {
                    VStack(alignment: .trailing, spacing: Metrics.spaceTight) {
                        ForEach(RuleFeed.trustedKeys.map(RuleFeed.fingerprint(of:)), id: \.self) { fingerprint in
                            Text(fingerprint)
                                .font(Typography.detail)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}
