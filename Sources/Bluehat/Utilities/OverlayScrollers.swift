import AppKit
import SwiftUI

extension View {
    /// Draws the enclosing scroll view's scrollers as thin overlays that show only while scrolling, whatever the system "Show scroll bars" setting. Apply it to the content inside a `ScrollView`, or to a `Section` inside a `Form`.
    func overlayScrollers() -> some View {
        background(OverlayScrollerStyle())
    }
}

private struct OverlayScrollerStyle: NSViewRepresentable {
    func makeNSView(context: Context) -> OverlayScrollerStyleView {
        OverlayScrollerStyleView()
    }

    func updateNSView(_ nsView: OverlayScrollerStyleView, context: Context) {}
}

private final class OverlayScrollerStyleView: NSView {
    override init(frame: NSRect) {
        super.init(frame: frame)
        NotificationCenter.default.addObserver(self, selector: #selector(preferredStyleChanged), name: NSScroller.preferredScrollerStyleDidChangeNotification, object: nil)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        enclosingScrollView?.scrollerStyle = .overlay
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        nil
    }

    @objc private func preferredStyleChanged() {
        // AppKit resets every scroll view to the new preferred style in its own observer, which can run after this one.
        DispatchQueue.main.async { self.enclosingScrollView?.scrollerStyle = .overlay }
    }
}
