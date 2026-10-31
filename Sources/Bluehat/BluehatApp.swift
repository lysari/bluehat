import SwiftUI

@main
struct BluehatApp: App {
    @NSApplicationDelegateAdaptor private var appDelegate: AppDelegate

    var body: some Scene {
        Window("Welcome to Bluehat", id: WelcomeView.windowID) {
            WelcomeView(store: appDelegate.store)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(appDelegate.store.settings.hasSeenWelcome ? .suppressed : .presented)
        .restorationBehavior(.disabled)

        Settings {
            SettingsView(store: appDelegate.store)
        }
    }
}
