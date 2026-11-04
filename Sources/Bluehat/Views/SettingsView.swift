import AppKit
import SwiftUI

struct SettingsView: View {
    let store: ScanStore
    @State private var visibleScreenHeight = NSScreen.main?.visibleFrame.height

    private var contentHeight: CGFloat {
        guard let visibleScreenHeight else { return Metrics.settingsHeight }
        return max(Metrics.settingsMinHeight, min(Metrics.settingsHeight, visibleScreenHeight - Metrics.settingsToolbarHeight))
    }

    var body: some View {
        TabView {
            GeneralSettingsTab(settings: store.settings)
                .tabItem { Label("General", systemImage: "gearshape") }
            ScheduleSettingsTab(store: store)
                .tabItem { Label("Schedule", systemImage: "clock") }
            ProjectsSettingsTab(settings: store.settings)
                .tabItem { Label("Projects", systemImage: "folder") }
            LimitsSettingsTab(settings: store.settings)
                .tabItem { Label("Limits", systemImage: "slider.horizontal.3") }
            HistorySettingsTab(history: store.history, maxRecords: store.settings.scanLimits[.maxHistoryRecords])
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
            IgnoredSettingsTab(settings: store.settings, rules: store.rulesReview, malwareFeed: store.malwareFeedReview)
                .tabItem { Label("Ignored", systemImage: "eye.slash") }
            RulesSettingsTab(rules: store.rulesReview, malwareFeed: store.malwareFeedReview)
                .tabItem { Label("Rules", systemImage: "checkmark.seal") }
            AboutSettingsTab(store: store)
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: Metrics.settingsWidth, height: contentHeight)
        .onAppear(perform: measureScreen)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didChangeScreenParametersNotification)) { _ in measureScreen() }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didChangeScreenNotification)) { _ in measureScreen() }
    }

    private func measureScreen() {
        visibleScreenHeight = NSScreen.main?.visibleFrame.height
    }
}
