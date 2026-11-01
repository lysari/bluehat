import BluehatCore

extension ThreatCategory {
    var title: String {
        switch self {
        case .malware: "Malware"
        case .rce: "RCE"
        case .worm: "Worm"
        case .backdoor: "Backdoor"
        case .persistence: "Persistence"
        case .miner: "Miner"
        case .hardening: "Hardening"
        }
    }

    var whyItMatters: String {
        switch self {
        case .malware: "Files or settings left by known malicious software. Malware can steal passwords, browser data and crypto wallets, or download more malware."
        case .rce: "Something on your Mac downloads and runs code from the internet without asking. An attacker can use it to run any command as you."
        case .worm: "Signs of software that spreads itself across networks. A worm can infect other computers on your network from this Mac."
        case .backdoor: "A hidden way into your Mac. An attacker can connect to it from anywhere and control your Mac remotely."
        case .persistence: "Something set up to start on its own every time you log in or restart. Malware uses this to survive restarts."
        case .miner: "Software that uses your Mac's processor to mine cryptocurrency for someone else. It slows your Mac and drains the battery."
        case .hardening: "A macOS protection is weaker than it should be. Nothing bad has to be running, but your Mac is easier to attack."
        }
    }
}
