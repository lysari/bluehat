import Foundation
import Testing
@testable import BluehatCore

struct SystemExtensionTests {
    static let systemExtensionsctlOutput = """
        3 extension(s)
        --- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        *\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.102.4/101.102.4)\tTailscale Network Extension\t[activated enabled]
        *\t*\tAB12CD34EF\tcom.example.proxy.filter (2.0/20)\tFree VPN Filter\t[activated enabled]
        --- com.apple.system_extension.endpoint_security
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        \t\tZZ99YY88XX\tnet.example.monitor.agent (1.0/1)\tSystem Monitor\t[terminated waiting to uninstall on reboot]
        """

    static let kmutilOutput = """
            3  228 0                  0          0          com.apple.kpi.bsd (27.0.0) 25FECA3D-AD9D-3958-B633-A14EC36D3BE7 <>
           10    6 0xfffffe0007144000 0x7098     0x7098     com.apple.kec.Libm (1) 4E3603E4-7BF1-3ED1-B3B6-F6FA24130C74 <6>
          201    0 0xfffffe000a1b2000 0x9000     0x9000     io.macfuse.filesystems.macfuse (5.0.7) 11111111-2222-3333-4444-555555555555 <9 8 7 6 5 3>
          202    0 0xfffffe000a1c3000 0x4000     0x4000     com.example.rootkit (1.0) 66666666-7777-8888-9999-000000000000 <6 3>
        """

    static func rule(teams: [String]?, bundles: [String]?) -> Rule {
        Rule(id: "extension.unknown-vendor", title: "Unknown vendor", severity: .medium, category: .persistence, check: .systemExtension, patterns: nil, paths: nil, ports: nil, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: teams, bundles: bundles, minimumVersion: nil, summary: nil, remedy: nil, references: nil)
    }

    @Test func parsesSystemExtensionsWithTeamAndState() {
        let extensions = Scanner.systemExtensions(fromSystemExtensionsctlOutput: Self.systemExtensionsctlOutput)

        #expect(extensions.map(\.bundle) == ["io.tailscale.ipn.macsys.network-extension", "com.example.proxy.filter", "net.example.monitor.agent"])
        #expect(extensions.map(\.team) == ["W5364U7YZB", "AB12CD34EF", "ZZ99YY88XX"])
        #expect(extensions.first?.detail == "Tailscale Network Extension (io.tailscale.ipn.macsys.network-extension) · team W5364U7YZB · activated enabled")
        #expect(extensions.last?.detail == "System Monitor (net.example.monitor.agent) · team ZZ99YY88XX · terminated waiting to uninstall on reboot")
    }

    @Test func parsesThirdPartyKernelExtensionsOnly() {
        let extensions = Scanner.kernelExtensions(fromKmutilOutput: Self.kmutilOutput)

        #expect(extensions.map(\.bundle) == ["io.macfuse.filesystems.macfuse", "com.example.rootkit"])
        #expect(extensions.allSatisfy { $0.team == nil })
        #expect(extensions.last?.detail == "Kernel extension (com.example.rootkit) · loaded")
    }

    @Test func missingOrFailedToolGivesNoExtensions() {
        #expect(Scanner.systemExtensions(fromSystemExtensionsctlOutput: "").isEmpty)
        #expect(Scanner.kernelExtensions(fromKmutilOutput: "").isEmpty)
        #expect(Scanner.systemExtensions(fromSystemExtensionsctlOutput: "0 extension(s)\n").isEmpty)
    }

    @Test func flagsOnlyExtensionsOutsideTheAllowList() {
        let extensions = Scanner.systemExtensions(fromSystemExtensionsctlOutput: Self.systemExtensionsctlOutput) + Scanner.kernelExtensions(fromKmutilOutput: Self.kmutilOutput)

        let findings = Scanner.systemExtensionFindings([Self.rule(teams: ["W5364U7YZB"], bundles: ["io.macfuse"])], extensions: extensions)

        #expect(findings.map(\.detail) == [
            "Free VPN Filter (com.example.proxy.filter) · team AB12CD34EF · activated enabled",
            "System Monitor (net.example.monitor.agent) · team ZZ99YY88XX · terminated waiting to uninstall on reboot",
            "Kernel extension (com.example.rootkit) · loaded",
        ])
        #expect(findings.allSatisfy { $0.path == nil })
    }

    @Test func teamsAllowSystemExtensionsAndBundlesAllowOnlyKernelExtensions() {
        let spoofed = [(bundle: "io.macfuse.helper", team: Optional("AB12CD34EF"), detail: "Helper (io.macfuse.helper) · team AB12CD34EF · activated enabled")]
        #expect(Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: ["io.macfuse"])], extensions: spoofed).count == 1)
        let lookalike = [(bundle: "io.macfusex.driver", team: String?.none, detail: "Kernel extension (io.macfusex.driver) · loaded")]
        #expect(Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: ["io.macfuse"])], extensions: lookalike).count == 1)
        let exact = [(bundle: "IO.MacFuse", team: String?.none, detail: "Kernel extension (IO.MacFuse) · loaded")]
        #expect(Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: ["io.macfuse"])], extensions: exact).isEmpty)
    }

    @Test func withoutVendorsEveryThirdPartyExtensionIsReported() {
        let extensions = Scanner.systemExtensions(fromSystemExtensionsctlOutput: Self.systemExtensionsctlOutput) + Scanner.kernelExtensions(fromKmutilOutput: Self.kmutilOutput)
        #expect(Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: nil)], extensions: extensions).count == 5)
    }

    @Test func ignoringOneExtensionKeepsTheOthers() {
        let extensions = Scanner.systemExtensions(fromSystemExtensionsctlOutput: Self.systemExtensionsctlOutput)
        let findings = Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: nil)], extensions: extensions)
        let again = Scanner.systemExtensionFindings([Self.rule(teams: nil, bundles: nil)], extensions: extensions)
        #expect(findings.map(\.fingerprint) == again.map(\.fingerprint))
        #expect(Set(findings.map(\.fingerprint)).count == findings.count)
    }
}
