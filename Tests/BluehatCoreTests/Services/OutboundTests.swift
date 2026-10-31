import Foundation
import Testing
@testable import BluehatCore

struct OutboundTests {
    static let tcpOutput = """
        Active Internet connections (including servers)
        Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
        tcp4       0      0  192.168.1.20.52480                            203.0.113.5.443                               ESTABLISHED        11164         2215  131072  131600             curl:63399  00102 00000008 000000000279c858 00000080 04000900      2      0 000000
        tcp4       0      0  192.168.1.20.52481                            203.0.113.5.443                               TIME_WAIT           5178         2696  131072  131860             curl:63399  02131 00000008 0000000002796572 00000080 04000900      0      0 000000
        tcp4       0      0  192.168.1.20.52323                            198.51.100.7.8080                             SYN_SENT               0            0  131072  131860 Brave Browser He:46556  00102 00000008 0000000002796573 00000080 04000900      0      0 000000
        tcp6       0      0  2001:db8:1::20.52490                          2001:db8:2::9.4444                            ESTABLISHED          514         8263  407680  146808         osascript:7001   00102 00000008 000000000267174c 00000080 04000900      2      0 000000
        tcp6       0      0  fe80::47f:4bb5:b0bd:9ebb%en0.59244            fe80::9c:f985:941:ce81%en0.61689              ESTABLISHED       267798       104148  131072 4194304         rapportd:1015   00102 00000004 000000000267c6f1 20080083 01000800      3      0 000004
        tcp6       0      0  ::1.1408                                      ::1.58061                                     ESTABLISHED        43022          185  407275  146808             node:14476  00102 00000104 000000000267174d 00000081 01000800      2      0 000000
        tcp4       0      0  127.0.0.1.51964                               127.0.0.1.52469                               ESTABLISHED          238          209  408256  146988              agy:11160  02131 0000000c 000000000279c6a2 00000080 01000800      0      0 000000
        tcp4       0      0  169.254.10.1.50000                            169.254.10.2.443                              ESTABLISHED          238          209  408256  146988              agy:11160  00102 0000000c 000000000279c6a3 00000080 01000800      0      0 000000
        tcp46      0      0  *.15611                                       *.*                                           LISTEN                 0            0  131072  131072          Postman:31595  00100 00000106 00000000012520a2 00000001 00000800      1      0 000000
        tcp4       0      0  127.0.0.1.8021                                *.*                                           LISTEN                 0            0  131072  131072          launchd:1      00180 00000006 00000000025c45cb 00000000 00000800      1      0 000000
        """

    static let udpOutput = """
        Active Internet connections (including servers)
        Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
        udp4       0      0  192.168.1.20.63144                            203.0.113.9.443                                                  12066         8322 1048576   29040 Google Chrome He:94045  00102 00000000 000000000279c9b1 00000000 04200900      1      0 000002
        udp6       0      0  *.3722                                        *.*                                                                  0          348  786896    9216         rapportd:1015   00100 00010200 000000000267c6f2 00000001 00000800      1      0 000002
        """

    static func rule(hosts: [String]? = nil, ports: [Int]? = nil) -> Rule {
        Rule(id: "outbound.test", title: "C2", severity: .high, category: .malware, check: .outbound, patterns: nil, paths: nil, ports: ports, hashes: nil, setting: nil, product: nil, advisory: nil, ranges: nil, packages: nil, files: nil, teams: nil, bundles: nil, minimumVersion: nil, hosts: hosts, summary: nil, remedy: nil, references: nil)
    }

    static var connections: [Connection] {
        Scanner.connections(fromNetstatOutput: tcpOutput) + Scanner.connections(fromNetstatOutput: udpOutput)
    }

    @Test func parsesRemoteEndpointsAndSkipsListenersLoopbackAndLinkLocal() {
        let connections = Self.connections

        #expect(connections.map(\.endpoint) == ["203.0.113.5:443", "203.0.113.5:443", "198.51.100.7:8080", "[2001:db8:2::9]:4444", "203.0.113.9:443"])
        #expect(connections.map(\.transport) == ["TCP", "TCP", "TCP", "TCP", "UDP"])
        #expect(connections.map(\.state) == ["ESTABLISHED", "TIME_WAIT", "SYN_SENT", "ESTABLISHED", nil])
        #expect(connections.map(\.process) == ["curl", "curl", "Brave Browser He", "osascript", "Google Chrome He"])
        #expect(connections.map(\.address.count) == [4, 4, 4, 16, 4])
    }

    @Test func missingOrFailedToolGivesNoConnections() {
        #expect(Scanner.connections(fromNetstatOutput: "").isEmpty)
        #expect(Scanner.connections(fromNetstatOutput: "netstat: sysctl: net.inet.tcp.pcblist_n: Operation not permitted\n").isEmpty)
    }

    @Test func reportsMatchingHostsWithStateAndProcess() {
        let findings = Scanner.outboundFindings([Self.rule(hosts: ["203.0.113.0/24:443", "[2001:db8:2::9]:4444"])], connections: Self.connections)

        #expect(findings.map(\.detail) == [
            "203.0.113.5:443 · TCP ESTABLISHED · curl",
            "[2001:db8:2::9]:4444 · TCP ESTABLISHED · osascript",
            "203.0.113.9:443 · UDP · Google Chrome He",
        ])
        #expect(findings.allSatisfy { $0.path == nil })
    }

    @Test func hostPortMustMatchWhenGiven() {
        let rule = Self.rule(hosts: ["198.51.100.7:443", "203.0.113.5"])
        #expect(Scanner.outboundFindings([rule], connections: Self.connections).map(\.detail) == ["203.0.113.5:443 · TCP ESTABLISHED · curl"])
    }

    @Test func remotePortsAloneMatchAnyAddress() {
        let findings = Scanner.outboundFindings([Self.rule(ports: [4444, 8080])], connections: Self.connections)
        #expect(findings.map(\.detail) == ["[2001:db8:2::9]:4444 · TCP ESTABLISHED · osascript", "198.51.100.7:8080 · TCP SYN_SENT · Brave Browser He"])
    }

    @Test func listedLoopbackAndLinkLocalConnectionsAreNeverReported() {
        #expect(Scanner.outboundFindings([Self.rule(ports: [58061, 52469, 61689])], connections: Self.connections).isEmpty)
    }

    @Test func ignoredFindingSurvivesANewLocalPortAndProcessID() {
        let rule = Self.rule(hosts: ["203.0.113.5"])
        let first = Scanner.connections(fromNetstatOutput: Self.tcpOutput)
        let reconnected = Scanner.connections(fromNetstatOutput: Self.tcpOutput.replacing("192.168.1.20.52480", with: "192.168.1.20.60001").replacing("curl:63399", with: "curl:70123"))

        let before = Scanner.outboundFindings([rule], connections: first)
        let after = Scanner.outboundFindings([rule], connections: reconnected)

        #expect(before.count == 1)
        #expect(before.map(\.fingerprint) == after.map(\.fingerprint))
    }
}
