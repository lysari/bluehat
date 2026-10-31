import Foundation

struct RemoteHost: Sendable {
    static let maxLength = 64
    static let portRange = 1...65535
    static let minimumIPv4Prefix = 16
    static let minimumIPv6Prefix = 32
    static let mappedIPv4Prefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]

    let address: [UInt8]
    let prefixLength: Int
    let port: Int?

    init?(_ entry: String) {
        guard entry.count <= Self.maxLength else { return nil }
        var range = Substring(entry)
        var port: Int?
        if range.hasPrefix("["), let close = range.firstIndex(of: "]") {
            let suffix = range[range.index(after: close)...]
            if !suffix.isEmpty {
                guard suffix.hasPrefix(":"), let value = Self.number(suffix.dropFirst(), in: Self.portRange) else { return nil }
                port = value
            }
            range = range[range.index(after: range.startIndex)..<close]
        } else if range.count(where: { $0 == ":" }) == 1, let colon = range.firstIndex(of: ":") {
            guard let value = Self.number(range[range.index(after: colon)...], in: Self.portRange) else { return nil }
            port = value
            range = range[..<colon]
        }
        let parts = range.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard !parts[0].contains("%"), let address = Self.address(of: parts[0]), !Self.isLocal(address) else { return nil }
        guard parts[0].contains(":") || address.map(String.init).joined(separator: ".") == parts[0] else { return nil }
        let bits = address.count * 8
        let minimum = address.count == 4 ? Self.minimumIPv4Prefix : Self.minimumIPv6Prefix
        guard let prefixLength = parts.count == 2 ? Self.number(parts[1], in: minimum...bits) : bits else { return nil }
        self.address = address
        self.prefixLength = prefixLength
        self.port = port
    }

    var isSingleAddress: Bool {
        prefixLength == address.count * 8
    }

    func matches(_ remote: [UInt8], port remotePort: Int) -> Bool {
        guard remote.count == address.count, port.map({ $0 == remotePort }) ?? true else { return false }
        let wholeBytes = prefixLength / 8
        let restBits = prefixLength % 8
        guard remote.prefix(wholeBytes).elementsEqual(address.prefix(wholeBytes)) else { return false }
        guard restBits > 0 else { return true }
        let mask = UInt8(0xff) << (8 - restBits)
        return remote[wholeBytes] & mask == address[wholeBytes] & mask
    }

    static func address(of text: some StringProtocol) -> [UInt8]? {
        let text = String(text)
        var ipv4 = in_addr()
        if inet_pton(AF_INET, text, &ipv4) == 1 {
            return withUnsafeBytes(of: &ipv4) { Array($0) }
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, text, &ipv6) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        return bytes.starts(with: mappedIPv4Prefix) ? Array(bytes.suffix(4)) : bytes
    }

    static func isLocal(_ address: [UInt8]) -> Bool {
        if address.count == 4 {
            return address[0] == 0 || address[0] == 127 || address.starts(with: [169, 254])
        }
        let isUnspecifiedOrLoopback = address.dropLast().allSatisfy { $0 == 0 } && (address.last ?? 0) <= 1
        let isLinkLocal = address[0] == 0xfe && address[1] & 0xc0 == 0x80
        return isUnspecifiedOrLoopback || isLinkLocal
    }

    static func number(_ text: Substring, in range: ClosedRange<Int>) -> Int? {
        guard (1...5).contains(text.count), text.first != "0", text.allSatisfy({ ("0"..."9").contains($0) }), let value = Int(text), range.contains(value) else { return nil }
        return value
    }
}
