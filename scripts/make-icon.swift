import AppKit
import SwiftUI

let canvas: CGFloat = 1024
let tileSize: CGFloat = 824
let tileRadius: CGFloat = 185
let ringDiameter: CGFloat = 640
let ringLineWidth: CGFloat = 34
let ringSegments = 8
let ringGap: CGFloat = 0.05
let shieldSize: CGFloat = 400
let depthLayers = 14
let depth: CGFloat = 34
let navyTop = Color(red: 0.09, green: 0.20, blue: 0.40)
let navyBottom = Color(red: 0.03, green: 0.08, blue: 0.19)
let shieldBlue = Color(nsColor: .systemBlue)
let segmentBlue = Color(red: 0.36, green: 0.62, blue: 1.0)
let segmentGreen = Color(nsColor: .systemGreen)

struct IconArt: View {
    var shield: some View {
        Image(systemName: "shield.fill").resizable().scaledToFit()
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: tileRadius, style: .continuous)
                .fill(LinearGradient(colors: [navyTop, navyBottom], startPoint: .top, endPoint: .bottom))
                .frame(width: tileSize, height: tileSize)
                .overlay(
                    RoundedRectangle(cornerRadius: tileRadius, style: .continuous)
                        .stroke(LinearGradient(colors: [.white.opacity(0.28), .white.opacity(0.04)], startPoint: .top, endPoint: .bottom), lineWidth: 4)
                )
                .shadow(color: .black.opacity(0.35), radius: 24, y: 12)
            Circle()
                .fill(shieldBlue)
                .frame(width: ringDiameter * 0.6, height: ringDiameter * 0.6)
                .blur(radius: 90)
                .opacity(0.55)
            Circle()
                .stroke(.white.opacity(0.10), lineWidth: 3)
                .frame(width: ringDiameter - 120, height: ringDiameter - 120)
            ForEach(0..<ringSegments, id: \.self) { index in
                let start = CGFloat(index) / CGFloat(ringSegments) + ringGap / 2
                Circle()
                    .trim(from: start, to: start + 1 / CGFloat(ringSegments) - ringGap)
                    .stroke(index == ringSegments - 1 ? segmentGreen : segmentBlue, style: StrokeStyle(lineWidth: ringLineWidth, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .shadow(color: (index == ringSegments - 1 ? segmentGreen : segmentBlue).opacity(0.6), radius: 14)
                    .frame(width: ringDiameter, height: ringDiameter)
            }
            Ellipse()
                .fill(.black.opacity(0.45))
                .frame(width: shieldSize * 0.7, height: shieldSize * 0.14)
                .blur(radius: 22)
                .offset(y: shieldSize * 0.55)
            ForEach(1...depthLayers, id: \.self) { layer in
                shield
                    .foregroundStyle(shieldBlue.mix(with: .black, by: 0.42))
                    .frame(width: shieldSize, height: shieldSize)
                    .offset(y: depth * CGFloat(layer) / CGFloat(depthLayers))
            }
            shield
                .foregroundStyle(LinearGradient(colors: [shieldBlue.mix(with: .white, by: 0.3), shieldBlue], startPoint: .top, endPoint: .bottom))
                .frame(width: shieldSize, height: shieldSize)
            Image(systemName: "shield").resizable().scaledToFit()
                .foregroundStyle(LinearGradient(colors: [.white.opacity(0.6), .clear], startPoint: .top, endPoint: .center))
                .frame(width: shieldSize, height: shieldSize)
            Ellipse()
                .fill(LinearGradient(colors: [.white.opacity(0.4), .clear], startPoint: .top, endPoint: .bottom))
                .frame(width: shieldSize * 0.9, height: shieldSize * 0.5)
                .offset(y: -shieldSize * 0.26)
                .mask(shield.frame(width: shieldSize, height: shieldSize))
            Image(systemName: "checkmark")
                .font(.system(size: shieldSize * 0.34, weight: .heavy))
                .foregroundStyle(.white)
                .shadow(color: .black.opacity(0.3), radius: 6, y: 6)
                .offset(y: -shieldSize * 0.04)
        }
        .frame(width: canvas, height: canvas)
    }
}

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let iconset = FileManager.default.temporaryDirectory.appending(path: "AppIcon-\(UUID().uuidString).iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: iconset) }

MainActor.assumeIsolated {
    for points in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
            let renderer = ImageRenderer(content: IconArt())
            renderer.scale = CGFloat(points * scale) / canvas
            guard
                let tiff = renderer.nsImage?.tiffRepresentation,
                let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:])
            else { fatalError("Rendering \(points)@\(scale)x failed") }
            let name = scale == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"
            try! png.write(to: iconset.appending(path: name))
        }
    }
}

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", output.path]
try iconutil.run()
iconutil.waitUntilExit()
guard iconutil.terminationStatus == 0 else { fatalError("iconutil failed") }
print("Wrote \(output.path)")
