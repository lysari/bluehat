import SwiftUI

enum Motion {
    static let standard = Animation.spring(duration: 0.3, bounce: 0.1)
    static let sweepDegreesPerSecond = 150.0
    static let pulseFloor = 0.45
    static let pulseSpeed = 3.0
    static let floatSpeed = 1.6
    static let floatAmount = 0.7
    static let floatVerticalRatio = 0.6
}
