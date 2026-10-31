import AppKit
import SwiftUI

final class MenuBarPanel: NSPanel {
    private weak var anchor: NSWindow?

    init(rootView: some View) {
        super.init(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        isFloatingPanel = true
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        isMovable = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        animationBehavior = .utilityWindow
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]

        let background = NSVisualEffectView()
        background.material = Palette.panelMaterial
        background.blendingMode = .behindWindow
        background.state = .active
        background.wantsLayer = true
        background.layer?.cornerRadius = Metrics.panelCornerRadius
        background.layer?.cornerCurve = .continuous
        background.layer?.masksToBounds = true

        let hostingView = NSHostingView(rootView: rootView
            .containerShape(.rect(cornerRadius: Metrics.panelCornerRadius))
            .fixedSize()
            .onGeometryChange(for: CGSize.self, of: \.size) { [weak self] size in
                self?.place(size: size)
            })
        hostingView.sizingOptions = []
        hostingView.autoresizingMask = [.width, .height]
        background.addSubview(hostingView)
        contentView = background

        NotificationCenter.default.addObserver(self, selector: #selector(screensChanged), name: NSApplication.didChangeScreenParametersNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(windowMoved), name: NSWindow.didMoveNotification, object: nil)
    }

    override var canBecomeKey: Bool {
        true
    }

    func show(below anchor: NSWindow) {
        self.anchor = anchor
        place(size: frame.size)
        makeKeyAndOrderFront(nil)
    }

    @objc private func screensChanged() {
        place(size: frame.size)
    }

    @objc private func windowMoved(_ notification: Notification) {
        guard let anchor, notification.object as? NSWindow === anchor else { return }
        place(size: frame.size)
    }

    private func place(size: CGSize) {
        var placed = NSRect(origin: frame.origin, size: size)
        if let anchor, let visible = anchor.screen?.visibleFrame {
            let top = min(anchor.frame.minY, visible.maxY) - Metrics.panelMenuBarGap
            placed.origin.x = min(max(anchor.frame.minX, visible.minX), visible.maxX - size.width)
            placed.origin.y = max(top - size.height, visible.minY)
        }
        setFrame(placed, display: true)
        invalidateShadow()
    }
}
