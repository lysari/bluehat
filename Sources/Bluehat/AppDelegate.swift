import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let store = ScanStore(settings: SettingsStore())
    private var menuBar: MenuBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        menuBar = MenuBarController(store: store)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
