import SwiftUI

struct FindingsEmptyView: View {
    let title: String
    let symbol: String
    let message: String
    var onClear: (() -> Void)?

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: symbol)
        } description: {
            Text(message)
        } actions: {
            if let onClear {
                Button("Clear", action: onClear)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }
}
