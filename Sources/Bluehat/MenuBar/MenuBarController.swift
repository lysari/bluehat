import AppKit
import Observation

@MainActor
final class MenuBarController: NSObject {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let panel: MenuBarPanel
    private var stateTask: Task<Void, Never>?

    init(store: ScanStore) {
        panel = MenuBarPanel(rootView: ScanPanel(store: store))
        super.init()
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePanel)
        statusItem.button?.imagePosition = .imageLeading
        statusItem.button?.font = Typography.menuBarCount
        stateTask = Task { [statusItem] in
            for await state in Observations({ store.menuBarState }) {
                statusItem.button?.image = state.image
                statusItem.button?.title = state.title
                statusItem.button?.setAccessibilityLabel(state.accessibilityLabel)
            }
        }
        NotificationCenter.default.addObserver(self, selector: #selector(updatePanelLevel), name: NSWindow.didBecomeKeyNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(updatePanelLevel), name: NSApplication.didBecomeActiveNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(updatePanelLevel), name: NSApplication.didResignActiveNotification, object: nil)
    }

    isolated deinit {
        stateTask?.cancel()
    }

    @objc private func togglePanel() {
        if panel.isVisible {
            panel.orderOut(nil)
        } else if let anchor = statusItem.button?.window {
            panel.show(below: anchor)
        }
        Task { [statusItem, panel] in
            statusItem.button?.highlight(panel.isVisible)
        }
    }

    @objc private func updatePanelLevel() {
        let ownWindow = NSApp.isActive ? NSApp.keyWindow.flatMap { $0 === panel || $0.sheetParent === panel ? nil : $0 } : nil
        panel.level = ownWindow == nil ? .floating : .normal
        if let ownWindow, panel.isVisible {
            panel.order(.below, relativeTo: ownWindow.windowNumber)
        }
    }
}
