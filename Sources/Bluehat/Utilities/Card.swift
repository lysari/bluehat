import SwiftUI

extension View {
    /// Draws the panel card surface: fill, hairline border and corners concentric with the window. Pass a status color for a soft top wash.
    func card(wash: Color? = nil) -> some View {
        let shape = ConcentricRectangle(corners: .concentric(minimum: .fixed(Metrics.cardMinimumRadius)), isUniform: true)
        let washGradient = LinearGradient(colors: [(wash ?? .clear).opacity(Palette.heroWashOpacity), .clear], startPoint: .top, endPoint: .bottom)
        return background(washGradient, in: shape)
            .background(Palette.cardFill, in: shape)
            .overlay(shape.stroke(Palette.cardStroke, lineWidth: Metrics.cardStrokeWidth))
    }
}
