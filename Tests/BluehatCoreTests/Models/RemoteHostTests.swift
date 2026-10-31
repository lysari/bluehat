import Foundation
import Testing
@testable import BluehatCore

struct RemoteHostTests {
    @Test(arguments: [
        ("203.0.113.5", 4, 32, Int?.none),
        ("203.0.113.5:443", 4, 32, 443),
        ("203.0.113.0/24", 4, 24, nil),
        ("203.0.0.0/16:8080", 4, 16, 8080),
        ("2001:db8::1", 16, 128, nil),
        ("[2001:db8::1]:443", 16, 128, 443),
        ("2001:db8::/32", 16, 32, nil),
        ("[2001:db8::/48]:4444", 16, 48, 4444),
        ("::ffff:203.0.113.5", 4, 32, nil),
    ])
    func parsesAddressesRangesAndPorts(entry: String, bytes: Int, prefixLength: Int, port: Int?) throws {
        let host = try #require(RemoteHost(entry))
        #expect(host.address.count == bytes)
        #expect(host.prefixLength == prefixLength)
        #expect(host.port == port)
    }

    @Test(arguments: [
        "", "evil.example.com", "evil.example.com:443", "203.0.113", "203.0.113.256", "203.0.113.05", "203.0.113.5:0", "203.0.113.5:65536",
        "203.0.113.5:+443", "203.0.113.5:0443", "203.0.113.5:", "203.0.113.0/15", "203.0.113.0/33", "203.0.113.0/", "2001:db8::/31",
        "[2001:db8::1]443", "[2001:db8::1]:", "[2001:db8::1", "2001:db8::1%en0", "127.0.0.1", "127.8.9.10:80", "169.254.1.1",
        "0.0.0.0", "::1", "[::1]:443", "::", "fe80::1", "febf::1", "::ffff:127.0.0.1", "203.0.113.5 ", String(repeating: "1", count: 65),
    ])
    func rejectsNamesBadFormsAndLocalAddresses(entry: String) {
        #expect(RemoteHost(entry) == nil)
    }

    @Test func rangesMatchByPrefixAndPortWhenGiven() throws {
        let range = try #require(RemoteHost("203.0.112.0/23:443"))
        #expect(range.matches([203, 0, 112, 1], port: 443))
        #expect(range.matches([203, 0, 113, 254], port: 443))
        #expect(!range.matches([203, 0, 114, 1], port: 443))
        #expect(!range.matches([203, 0, 113, 1], port: 80))

        let ipv6 = try #require(RemoteHost("2001:db8::/32"))
        let inside = try #require(RemoteHost.address(of: "2001:db8:ffff::1"))
        let outside = try #require(RemoteHost.address(of: "2001:db9::1"))
        #expect(ipv6.matches(inside, port: 1))
        #expect(!ipv6.matches(outside, port: 1))
        #expect(!ipv6.matches([32, 1, 13, 184], port: 1))
    }

    @Test func singleAddressesHaveFullPrefixes() throws {
        #expect(try #require(RemoteHost("203.0.113.5:443")).isSingleAddress)
        #expect(try #require(RemoteHost("[2001:db8::1]:443")).isSingleAddress)
        #expect(try !#require(RemoteHost("203.0.113.0/24")).isSingleAddress)
    }
}
