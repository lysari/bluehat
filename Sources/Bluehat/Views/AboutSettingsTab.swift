import SwiftUI

struct AboutSettingsTab: View {
    let store: ScanStore

    private var appVersion: String {
        store.appUpdate.currentVersion.map { "Version \($0)" } ?? "Development build"
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
            .overlayScrollers(flashesOnAppear: true)
            AppUpdateSection(store: store)
        }
        .formStyle(.grouped)
        .animation(Motion.standard, value: store.appUpdate.activity)
    }
}
