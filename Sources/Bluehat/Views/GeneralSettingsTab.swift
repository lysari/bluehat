import BluehatCore
import SwiftUI

struct GeneralSettingsTab: View {
    let settings: SettingsStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        @Bindable var settings = settings
        ScrollViewReader { scroller in
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
                .overlayScrollers(flashesOnAppear: true)
                Section {
                    Toggle("Keep panel on top of other windows", isOn: $settings.keepsPanelOnTop)
                } footer: {
                    Text("When this is off, other apps' windows can cover the panel. Click the shield in the menu bar to bring it back to the front, and click again to close it.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                Section {
                    Picker("Findings list", selection: $settings.findingsLayout) {
                        Text("Normal").tag(FindingsLayout.normal)
                        Text("Grouped").tag(FindingsLayout.grouped)
                    }
                } footer: {
                    Text("Normal lists every finding by severity. Grouped puts findings under their check area, most severe area first.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                Section {
                    Button("Show Welcome Again") { openWindow(id: WelcomeView.windowID) }
                }
                DeepScanExclusionsSection(settings: settings, scroller: scroller)
            }
            .formStyle(.grouped)
        }
        .onAppear { settings.refreshLoginItem() }
    }
}
