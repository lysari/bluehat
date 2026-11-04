import Testing
@testable import BluehatCore

struct ProcessMemoryTests {
    @Test func readsThisProcessesFootprint() throws {
        let footprint = try #require(ProcessMemory.footprintBytes())
        #expect(footprint > 1 << 20)
    }
}
