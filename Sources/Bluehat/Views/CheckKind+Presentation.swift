import BluehatCore
import SwiftUI

extension CheckKind {
    var title: String {
        switch self {
        case .path: "Malware files"
        case .launchItem: "Launch items"
        case .shellProfile: "Shell startup"
        case .process: "Processes"
        case .listeningPort: "Open ports"
        case .fileHash: "Downloads"
        case .crontab: "Scheduled jobs"
        case .setting: "Protections"
        case .launchItemSignature: "Launch signing"
        case .appSignature: "App signing"
        case .sshKey: "SSH keys"
        case .profile: "Profiles"
        case .browserExtension: "Extensions"
        case .softwareVersion: "Software versions"
        case .npmPackage: "npm packages"
        case .projectFile: "Project files"
        }
    }

    var symbol: String {
        switch self {
        case .path: "ladybug"
        case .launchItem: "power"
        case .shellProfile: "terminal"
        case .process: "cpu"
        case .listeningPort: "network"
        case .fileHash: "arrow.down.circle"
        case .crontab: "clock"
        case .setting: "lock.shield"
        case .launchItemSignature: "signature"
        case .appSignature: "app.badge.checkmark"
        case .sshKey: "key.horizontal"
        case .profile: "gearshape.2"
        case .browserExtension: "puzzlepiece.extension"
        case .softwareVersion: "shippingbox"
        case .npmPackage: "cube.transparent"
        case .projectFile: "doc.text.magnifyingglass"
        }
    }

    var fixHint: String {
        switch self {
        case .path: "Show the file in Finder. If you don't recognize it, quit the app it belongs to, move the file to the Trash, and restart your Mac."
        case .launchItem: "Show the launch item in Finder. If you didn't install it, remove it with launchctl bootout, move the file to the Trash, and restart."
        case .shellProfile: "Open the shell startup file in a text editor and delete the line if you didn't add it, then open a new Terminal window."
        case .process: "Open Activity Monitor, find the process, and quit it. Then look for the launch item or file that started it."
        case .listeningPort: "Find the app with lsof -nP -iTCP -sTCP:LISTEN and quit it, or turn the service off in System Settings › General › Sharing."
        case .fileHash: "Show the file in Finder and move it to the Trash. Don't open it."
        case .crontab: "Run crontab -e in Terminal and delete the line if you didn't add it."
        case .setting: "Turn the protection back on in System Settings."
        case .launchItemSignature: "Show the launch item in Finder. If you don't know the program it starts, unload it with launchctl bootout, then move the plist and the program to the Trash."
        case .appSignature: "If you didn't build or knowingly allow this app, delete it and download it again from its developer or the App Store. A changed signature can also come from an app updating itself; reinstalling fixes that too."
        case .sshKey: "Open ~/.ssh/authorized_keys in a text editor and delete every line you don't recognize. If you don't use SSH at all, turn off Remote Login in System Settings › General › Sharing."
        case .profile: "Open System Settings › General › Device Management, select the profile, and remove it unless your school or company installed it."
        case .browserExtension: "Open the browser's extensions page (for Chrome, chrome://extensions), find the extension by its ID with Developer mode on, and remove it. Then change passwords for sites you used while it was installed."
        case .softwareVersion: "Upgrade to the fixed version named above with the tool that installed this copy (for example brew upgrade, nvm install or pyenv install), switch your projects to it, then remove the old copy (brew cleanup, nvm uninstall or pyenv uninstall). With no fixed release listed, move to a supported release line."
        case .npmPackage: "Remove the package or pin a version that isn't listed, delete node_modules, and reinstall from a clean lockfile with npm ci --ignore-scripts. These attacks steal secrets, so from another device rotate your npm, GitHub and cloud tokens and SSH keys, and check your GitHub account for repositories, workflows or keys you didn't add."
        case .projectFile: "Don't run the project: no npm install, npm run dev or other scripts. Open the file in a plain text editor, go to the reported line and scroll far to the right, since payloads hide after long runs of spaces. Compare it with the original repository. If the project came from a stranger or a job interview, delete it. If you already ran it, from another device rotate your npm, GitHub and cloud tokens and SSH keys, and check Bluehat's other findings for what it left behind."
        }
    }
}
