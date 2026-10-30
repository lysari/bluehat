import SwiftUI

struct ShieldEmblem: View {
    enum Face: Equatable {
        case symbol(String)
        case text(String)
    }

    let tint: Color
    let face: Face?
    let size: CGFloat
    let isFloating: Bool
    @State private var hoverTilt = CGSize.zero
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.animation(paused: !isFloating || reduceMotion)) { timeline in
            emblem(tilt: isFloating && !reduceMotion ? floatTilt(at: timeline.date) : hoverTilt)
        }
        .frame(width: size, height: size)
        .onContinuousHover { phase in
            guard !reduceMotion else { return }
            withAnimation(Motion.standard) {
                switch phase {
                case .active(let point):
                    hoverTilt = CGSize(width: point.x / size * 2 - 1, height: point.y / size * 2 - 1)
                case .ended:
                    hoverTilt = .zero
                }
            }
        }
        .accessibilityHidden(true)
    }

    private var shield: some View {
        Image(systemName: "shield.fill").resizable().scaledToFit()
    }

    private func emblem(tilt: CGSize) -> some View {
        let magnitude = min(hypot(tilt.width, tilt.height), 1)
        let depth = size * Metrics.emblemDepthRatio
        let shift = CGSize(width: -tilt.width * depth, height: depth * (1 - tilt.height * Metrics.emblemDepthTiltShare))
        return ZStack {
            Ellipse()
                .fill(Color.black.opacity(Palette.emblemGroundShadowOpacity))
                .frame(width: size * Metrics.emblemGroundWidthRatio, height: size * Metrics.emblemGroundHeightRatio)
                .blur(radius: size * Metrics.emblemGroundBlurRatio)
                .offset(x: shift.width, y: size / 2)
            ForEach(1...Metrics.emblemDepthLayers, id: \.self) { layer in
                let step = CGFloat(layer) / CGFloat(Metrics.emblemDepthLayers)
                shield
                    .foregroundStyle(tint.mix(with: .black, by: Palette.emblemSideShade))
                    .offset(x: shift.width * step, y: shift.height * step)
            }
            shield
                .foregroundStyle(LinearGradient(colors: [tint.mix(with: .white, by: Palette.emblemFaceLift), tint], startPoint: .top, endPoint: .bottom))
            Image(systemName: "shield").resizable().scaledToFit()
                .foregroundStyle(LinearGradient(colors: [Color.white.opacity(Palette.emblemBevelOpacity), .clear], startPoint: .top, endPoint: .center))
            Ellipse()
                .fill(LinearGradient(colors: [Color.white.opacity(Palette.emblemGlossOpacity), .clear], startPoint: .top, endPoint: .bottom))
                .frame(width: size * Metrics.emblemGlossWidthRatio, height: size * Metrics.emblemGlossHeightRatio)
                .offset(x: -tilt.width * depth, y: -size * Metrics.emblemGlossOffsetRatio)
                .mask(shield)
            faceContent
                .foregroundStyle(Palette.onBrand)
                .shadow(color: .black.opacity(Palette.emblemGlyphShadowOpacity), radius: Metrics.emblemGlyphShadowRadius, y: Metrics.emblemGlyphShadowRadius)
                .offset(y: -size * Metrics.emblemFaceRaiseRatio)
        }
        .rotation3DEffect(
            .degrees(Metrics.emblemTiltDegrees * magnitude),
            axis: magnitude > 0 ? (x: -tilt.height, y: tilt.width, z: 0) : (x: 1, y: 0, z: 0),
            perspective: Metrics.emblemPerspective
        )
    }

    @ViewBuilder
    private var faceContent: some View {
        switch face {
        case .symbol(let name):
            Image(systemName: name)
                .font(.system(size: size * Metrics.emblemSymbolRatio, weight: .bold))
                .contentTransition(.symbolEffect(.replace))
        case .text(let value):
            Text(value)
                .font(.system(size: size * Metrics.emblemTextRatio, weight: .bold, design: .rounded).monospacedDigit())
                .contentTransition(.numericText())
                .minimumScaleFactor(Metrics.emblemTextMinimumScale)
                .lineLimit(1)
                .padding(.horizontal, size * Metrics.emblemTextInsetRatio)
        case nil:
            EmptyView()
        }
    }

    private func floatTilt(at date: Date) -> CGSize {
        let seconds = date.timeIntervalSinceReferenceDate
        return CGSize(width: sin(seconds * Motion.floatSpeed) * Motion.floatAmount, height: cos(seconds * Motion.floatSpeed * Motion.floatVerticalRatio) * Motion.floatAmount * Motion.floatVerticalRatio)
    }
}
