import Testing
@testable import BluehatCore

struct SoftwareVersionTests {
    func version(_ text: String, _ product: SoftwareProduct = .node) throws -> SoftwareVersion {
        try #require(SoftwareVersion(text, for: product))
    }

    @Test func comparesComponentsAsNumbers() throws {
        #expect(try version("20.9.0") < version("20.11.0"))
        #expect(try version("2.45.2") < version("10.0.0"))
        #expect(try version("20.11.1") > version("20.11.0"))
    }

    @Test func missingComponentsCountAsZero() throws {
        #expect(try version("20.11") == version("20.11.0"))
        #expect(try version("3") == version("3.0.0.0"))
        #expect(try version("20.11") < version("20.11.0.1"))
    }

    @Test func acceptsLeadingV() throws {
        #expect(try version("v20.11.0") == version("20.11.0"))
        #expect(try version("v20.11.0").description == "20.11.0")
    }

    @Test func ordersOpenSSLLetterReleases() throws {
        #expect(try version("1.1.1", .openssl) < version("1.1.1a", .openssl))
        #expect(try version("1.1.1w", .openssl) < version("1.1.2", .openssl))
        #expect(try version("1.0.2z", .openssl) < version("1.0.2za", .openssl))
        #expect(try version("1.1.1w", .openssl).description == "1.1.1w")
    }

    @Test(arguments: ["", "v", "20.", ".20", "20..1", "20.11.0-rc.1", "3.13.0rc1", "1.1.1w", "HEAD-abc123", "lts", "1.2.3.4.5.6.7", "1234567890.0", "20.11.0 ", "２０.1"])
    func rejectsAnythingButDottedNumbers(text: String) {
        #expect(SoftwareVersion(text, for: .node) == nil)
    }
}
