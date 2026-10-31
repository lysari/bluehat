import Foundation

public enum InstallManager: String, Sendable {
    case homebrew, nvm, volta, fnm, asdf, mise, pyenv, rbenv, pythonOrg, nodeInstaller
}

public struct Installation: Sendable, Equatable {
    static let nodeDownloadPage = URL(string: "https://nodejs.org/en/download")!
    static let pythonDownloadPage = URL(string: "https://www.python.org/downloads/macos/")!
    static let nvmSetup = """
        export NVM_DIR="$HOME/.nvm"
        for nvm_script in "$NVM_DIR/nvm.sh" /opt/homebrew/opt/nvm/nvm.sh /usr/local/opt/nvm/nvm.sh; do
          if [ -s "$nvm_script" ]; then . "$nvm_script"; break; fi
        done
        """

    public let product: SoftwareProduct
    public let version: SoftwareVersion
    public let path: String
    public let manager: InstallManager

    public var isTrashable: Bool {
        switch manager {
        case .nvm, .volta, .fnm, .asdf, .mise, .pyenv, .rbenv: true
        case .homebrew, .pythonOrg, .nodeInstaller: false
        }
    }

    public var downloadPage: URL? {
        switch manager {
        case .nodeInstaller: Self.nodeDownloadPage
        case .pythonOrg: Self.pythonDownloadPage
        case .homebrew, .nvm, .volta, .fnm, .asdf, .mise, .pyenv, .rbenv: nil
        }
    }

    var parentFolderName: String {
        URL(fileURLWithPath: path).deletingLastPathComponent().lastPathComponent
    }

    var formula: String? {
        guard manager == .homebrew, parentFolderName.wholeMatch(of: /[a-z]{1,16}(@[0-9]{1,4}(\.[0-9]{1,4}){0,2})?/) != nil else { return nil }
        return parentFolderName
    }

    var pluginName: String? {
        guard manager == .asdf || manager == .mise, parentFolderName.wholeMatch(of: /[a-z]{1,16}/) != nil else { return nil }
        return parentFolderName
    }

    var brewExecutable: String? {
        Scanner.homebrewCellars.first { path.hasPrefix($0 + "/") }.map {
            URL(fileURLWithPath: $0).deletingLastPathComponent().appending(path: "bin/brew").path
        }
    }

    public func updateTarget(findings: [Finding]) -> SoftwareVersion? {
        let rules = findings.filter { $0.path == path && $0.rule.check == .softwareVersion && $0.rule.product == product }.map(\.rule)
        let ranges = rules.compactMap { Scanner.affectingRange(of: $0, for: version) }
        guard !ranges.isEmpty, ranges.count == rules.count else { return nil }
        let fixes = ranges.map { $0.fixed.flatMap { SoftwareVersion($0, for: product) } }
        guard
            fixes.allSatisfy({ $0 != nil }),
            let target = fixes.compactMap({ $0 }).max(),
            rules.allSatisfy({ Scanner.affectingRange(of: $0, for: target) == nil })
        else { return nil }
        return target
    }

    public func updateCommand(to target: SoftwareVersion) -> TerminalCommand? {
        let version = target.description
        guard target > self.version, version.wholeMatch(of: /[0-9]{1,9}(\.[0-9]{1,9}){0,5}[a-z]{0,2}/) != nil else { return nil }
        switch manager {
        case .homebrew:
            guard let brew = brewExecutable, let formula else { return nil }
            return TerminalCommand(setup: nil, command: "\(brew) upgrade", values: [formula])
        case .nvm:
            return TerminalCommand(setup: Self.nvmSetup, command: "nvm install", values: [version])
        case .fnm:
            return TerminalCommand(setup: nil, command: "fnm install", values: [version])
        case .volta:
            return TerminalCommand(setup: nil, command: "volta install", values: ["node@\(version)"])
        case .asdf:
            return pluginName.map { TerminalCommand(setup: nil, command: "asdf install", values: [$0, version]) }
        case .mise:
            return pluginName.map { TerminalCommand(setup: nil, command: "mise install", values: ["\($0)@\(version)"]) }
        case .pyenv:
            return TerminalCommand(setup: nil, command: "pyenv install", values: [version])
        case .rbenv:
            return TerminalCommand(setup: nil, command: "rbenv install", values: [version])
        case .pythonOrg, .nodeInstaller:
            return nil
        }
    }

    public func removeCommand(among installs: [Installation]) -> TerminalCommand? {
        guard let brew = brewExecutable, let formula else { return nil }
        let rack = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let hasNewerKeg = installs.contains { URL(fileURLWithPath: $0.path).deletingLastPathComponent().path == rack && $0.version > version }
        return TerminalCommand(setup: nil, command: "\(brew) \(hasNewerKeg ? "cleanup" : "uninstall")", values: [formula])
    }
}
