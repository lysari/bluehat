import SwiftUI

struct GeneralSettingsTab: View {
    let settings: SettingsStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Form {
            Section {
                Toggle("Open Bluehat at login", isOn: Binding(get: { settings.launchesAtLogin }, set: { settings.setLaunchesAtLogin($0) }))
                if let problem = settings.loginItemProblem {
                    Text(problem)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.notice)
                } else if !settings.isInstalled {
                    Text("Bluehat isn't in Applications. Install it with devbox run install so the login item keeps working.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
            Section {
                Button("Show Welcome Again") { openWindow(id: WelcomeView.windowID) }
            }
        }
        .formStyle(.grouped)
        .onAppear { settings.refreshLoginItem() }
    }
}
