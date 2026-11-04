import AppKit
import SwiftUI

extension View {
    /// Draws the enclosing scroll view's scrollers as thin overlays that show only while scrolling, whatever the system "Show scroll bars" setting. Apply it to the content inside a `ScrollView`, or to a `Section` inside a `Form`. Pass `flashesOnAppear` to show the thumb briefly when the content appears, so people can tell there is more below.
    func overlayScrollers(flashesOnAppear: Bool = false) -> some View {
        background(OverlayScrollerStyle(flashesOnAppear: flashesOnAppear))
    }
}

private struct OverlayScrollerStyle: NSViewRepresentable {
    let flashesOnAppear: Bool

    func makeNSView(context: Context) -> OverlayScrollerStyleView {
        OverlayScrollerStyleView(flashesOnAppear: flashesOnAppear)
    }

    func updateNSView(_ nsView: OverlayScrollerStyleView, context: Context) {}
}

private final class OverlayScrollerStyleView: NSView {
    private let flashesOnAppear: Bool

    init(flashesOnAppear: Bool) {
        self.flashesOnAppear = flashesOnAppear
        super.init(frame: .zero)
        NotificationCenter.default.addObserver(self, selector: #selector(preferredStyleChanged), name: NSScroller.preferredScrollerStyleDidChangeNotification, object: nil)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        enclosingScrollView?.scrollerStyle = .overlay
        guard flashesOnAppear, window != nil else { return }
        // The content has no height yet, so the scroller has no thumb to flash until layout has run.
        DispatchQueue.main.async { self.enclosingScrollView?.flashScrollers() }
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        nil
    }

    @objc private func preferredStyleChanged() {
        // AppKit resets every scroll view to the new preferred style in its own observer, which can run after this one.
        DispatchQueue.main.async { self.enclosingScrollView?.scrollerStyle = .overlay }
    }
}
