import Foundation

struct Connection: Sendable {
    static let establishedState = "ESTABLISHED"

    let host: String
    let address: [UInt8]
    let port: Int
    let transport: String
    let state: String?
    let process: String?

    var endpoint: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    var peer: String {
        "\(transport) \(endpoint) \(process ?? "")"
    }

    var detail: String {
        let status = state.map { "\(transport) \($0)" } ?? transport
        return "\(endpoint) · \(status) · \(process ?? "unknown process")"
    }
}
