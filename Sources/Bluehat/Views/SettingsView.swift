import SwiftUI

struct SettingsView: View {
    let store: ScanStore

    var body: some View {
        TabView {
            GeneralSettingsTab(settings: store.settings)
                .tabItem { Label("General", systemImage: "gearshape") }
            ScheduleSettingsTab(store: store)
                .tabItem { Label("Schedule", systemImage: "clock") }
            HistorySettingsTab(history: store.history)
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
            IgnoredSettingsTab(settings: store.settings)
                .tabItem { Label("Ignored", systemImage: "eye.slash") }
            AboutSettingsTab(store: store)
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: Metrics.settingsWidth)
        .frame(minHeight: Metrics.settingsMinHeight)
    }
}
