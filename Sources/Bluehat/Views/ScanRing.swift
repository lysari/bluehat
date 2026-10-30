import BluehatCore
import SwiftUI

struct ScanRing: View {
    let store: ScanStore
    let tint: Color
    let face: ShieldEmblem.Face
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.animation(paused: !store.isBusy || reduceMotion)) { timeline in
            let seconds = timeline.date.timeIntervalSinceReferenceDate
            ZStack {
                Circle()
                    .fill(tint)
                    .padding(Metrics.ringGlowInset)
                    .blur(radius: Metrics.ringGlowBlur)
                    .opacity(Palette.ringGlowOpacity)
                Circle()
                    .stroke(Palette.ringTrack, lineWidth: Metrics.cardStrokeWidth)
                    .padding(Metrics.ringSweepInset)
                Circle()
                    .fill(AngularGradient(colors: [Palette.brand.opacity(0), Palette.brand.opacity(Palette.sweepOpacity)], center: .center))
                    .padding(Metrics.ringSweepInset)
                    .rotationEffect(.degrees(seconds * Motion.sweepDegreesPerSecond))
                    .opacity(store.isBusy && !reduceMotion ? 1 : 0)
                ForEach(Array(store.areas.enumerated()), id: \.element) { index, area in
                    Circle()
                        .trim(from: segmentStart(index), to: segmentStart(index + 1) - Metrics.ringSegmentGap)
                        .stroke(segmentColor(area), style: StrokeStyle(lineWidth: Metrics.ringLineWidth, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                        .shadow(color: store.finishedAreas.contains(area) ? segmentColor(area).opacity(Palette.segmentGlowOpacity) : .clear, radius: Metrics.segmentGlowRadius)
                        .opacity(area == store.currentArea ? Motion.pulseFloor + (1 - Motion.pulseFloor) * abs(sin(seconds * Motion.pulseSpeed)) : 1)
                }
                ShieldEmblem(tint: tint, face: face, size: Metrics.heroEmblem, isFloating: store.isBusy)
            }
        }
        .frame(width: Metrics.ringDiameter, height: Metrics.ringDiameter)
        .accessibilityElement()
        .accessibilityLabel("Scan progress")
        .accessibilityValue(store.isBusy ? "\(Int(store.progress * 100)) percent" : statusValue)
    }

    private var statusValue: String {
        store.phase == .finished ? counted(store.issues.count, "issue") : "Not scanned"
    }

    private func segmentStart(_ index: Int) -> CGFloat {
        CGFloat(index) / CGFloat(max(store.areas.count, 1)) + Metrics.ringSegmentGap / 2
    }

    private func segmentColor(_ area: CheckKind) -> Color {
        if area == store.currentArea { return Palette.brand }
        guard store.finishedAreas.contains(area) else { return Palette.ringTrack }
        let worst = store.visibleFindings.filter { $0.rule.check == area }.map(\.rule.severity).max()
        return worst.map(Palette.severity) ?? Palette.safe
    }
}
