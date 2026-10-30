import SwiftUI

@main
struct BluehatApp: App {
    @State private var store = ScanStore(settings: SettingsStore())

    var body: some Scene {
        MenuBarExtra {
            ScanPanel(store: store)
        } label: {
            Image(systemName: store.menuBarSymbol)
                .accessibilityLabel("Bluehat")
        }
        .menuBarExtraStyle(.window)

        Window("Welcome to Bluehat", id: WelcomeView.windowID) {
            WelcomeView(store: store)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(store.settings.hasSeenWelcome ? .suppressed : .presented)
        .restorationBehavior(.disabled)

        Settings {
            SettingsView(store: store)
        }
    }
}
