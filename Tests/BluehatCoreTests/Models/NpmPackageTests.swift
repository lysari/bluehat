import Foundation
import Testing
@testable import BluehatCore

struct NpmPackageTests {
    @Test(arguments: ["chalk", "@babel/core", "lodash.merge", "string_decoder", "-x", "~tilde", "a", "@s/a", String(repeating: "a", count: NpmPackage.maxNameLength)])
    func acceptsNpmNames(name: String) {
        #expect(NpmPackage.isName(name))
    }

    @Test(arguments: [
        "", "Chalk", "JSONStream", ".hidden", "_private", "@scope", "@scope/", "@/x", "a/b", "@a/b/c", "a b", "a\nb", "chalk!", "chälk", "../etc",
        String(repeating: "a", count: NpmPackage.maxNameLength + 1),
    ])
    func rejectsOtherNames(name: String) {
        #expect(!NpmPackage.isName(name))
    }

    @Test(arguments: ["1.2.3", "0.0.0", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7", "1.0.0-x-y-z.--", "1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", "0.0.0-use.local"])
    func acceptsSemverVersions(version: String) {
        #expect(NpmPackage.isVersion(version))
    }

    @Test(arguments: [
        "", "1", "1.2", "v1.2.3", "01.2.3", "1.2.3-", "1.2.3+", "1.2.3-a..b", "^1.2.3", "1.2.x", "latest", "npm:chalk@1.2.3", "file:../lib", "git+https://x.example/r.git", "1.2.3 ",
        "1.2.3-" + String(repeating: "a", count: NpmPackage.maxVersionLength),
    ])
    func rejectsOtherVersions(version: String) {
        #expect(!NpmPackage.isVersion(version))
    }

    @Test func everyVersionMatchesAnyVersionAndAListOnlyItsOwn() {
        #expect(PackageVersions.every.contains("9.9.9"))
        #expect(PackageVersions.only(["5.6.1", "5.6.2"]).contains("5.6.2"))
        #expect(!PackageVersions.only(["5.6.1"]).contains("5.6.10"))
        #expect(!PackageVersions.only(["5.6.1"]).contains("5.6.1-beta"))
    }

    @Test func versionsRoundTripAsStarOrList() throws {
        let packages = [
            MaliciousPackage(name: "a", versions: .every, advisory: "MAL-2025-1"),
            MaliciousPackage(name: "b", versions: .only(["1.0.0"]), advisory: "MAL-2025-2"),
        ]
        let encoded = try JSONEncoder().encode(packages)
        #expect(String(decoding: encoded, as: UTF8.self).contains(#""versions":"*""#))
        #expect(try JSONDecoder().decode([MaliciousPackage].self, from: encoded) == packages)
    }

    @Test func installedPackageRequiresValidNameAndVersion() {
        #expect(InstalledPackage(name: "chalk", version: "5.6.1", path: "/p") != nil)
        #expect(InstalledPackage(name: "Chalk", version: "5.6.1", path: "/p") == nil)
        #expect(InstalledPackage(name: "chalk", version: "github:chalk/chalk", path: "/p") == nil)
    }
}
