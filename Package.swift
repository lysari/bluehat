// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Bluehat",
    platforms: [.macOS("26.0")],
    targets: [
        .target(name: "BluehatCore"),
        .executableTarget(name: "Bluehat", dependencies: ["BluehatCore"]),
        .executableTarget(name: "bluehat-sign", dependencies: ["BluehatCore"]),
        .testTarget(name: "BluehatCoreTests", dependencies: ["BluehatCore"]),
    ]
)
