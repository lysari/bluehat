import BluehatCore
import SwiftUI

struct CheckDetails {
    static let diskWalkTitle = "Disk walk"
    static let diskWalkSymbol = "square.3.layers.3d"
    static let staysOnMac = "No. This check stays on your Mac."
    static let offlineSignature = "No. Bluehat asks macOS to validate the signature without the network, so this check doesn't notice a certificate Apple has revoked."
    static let diskWalk = CheckDetails(
        looksFor: "npm packages and project config files anywhere on your startup disk, with the same rules as npm packages and Project files. It runs last, only in a Deep Scan.",
        looksIn: "Your startup disk, except folders and patterns you exclude in Settings › General. Other volumes and cloud-only files are skipped. It stops early at the Deep Scan memory limit in Settings › Limits and says so.",
        findingMeans: "A match that the normal scan's folders didn't cover, which needs the same care. It also counts under npm packages or Project files.",
        fileContents: "Only package files: package.json, lockfiles and config files a rule can use. Everything else is seen by name alone.",
        internet: "No. Cloud-only files aren't downloaded."
    )

    let looksFor: String
    let looksIn: String
    let findingMeans: String
    let fileContents: String
    let internet: String
}

extension CheckKind {
    var details: CheckDetails {
        switch self {
        case .path:
            CheckDetails(
                looksFor: "Files and folders that known Mac malware leaves behind, recognized by their exact location.",
                looksIn: "Only the exact paths the signed rules list, so the list changes when the rules update. No folder is searched.",
                findingMeans: "Something exists at a path that known malware uses. Unless you know the file, treat your Mac as possibly infected and follow the finding's steps.",
                fileContents: "No. It only asks whether each path exists.",
                internet: CheckDetails.staysOnMac
            )
        case .launchItem:
            CheckDetails(
                looksFor: "Launch items that start a program the way malware does, such as fetching a remote script. The signed rules set the patterns.",
                looksIn: "~/Library/LaunchAgents, /Library/LaunchAgents and /Library/LaunchDaemons.",
                findingMeans: "Something set itself to start automatically in a suspicious way. If you didn't install it, it may be malware.",
                fileContents: "Yes. It reads each launch item's .plist to see what it starts, not the program itself.",
                internet: CheckDetails.staysOnMac
            )
        case .shellProfile:
            CheckDetails(
                looksFor: "Startup lines that match the signed rules, such as ones that download and run code whenever you open Terminal.",
                looksIn: "~/.zshrc, ~/.zprofile, ~/.zshenv, ~/.zlogin, ~/.bashrc, ~/.bash_profile and ~/.profile.",
                findingMeans: "A line that looks like malware runs each time a shell starts. If you didn't add it, take it seriously.",
                fileContents: "Yes. It reads these files, and a matching line appears in the finding.",
                internet: CheckDetails.staysOnMac
            )
        case .process:
            CheckDetails(
                looksFor: "Running programs whose command lines match the signed rules, such as reverse shells, miners and stealers.",
                looksIn: "The list of running processes from the system tool ps.",
                findingMeans: "Something that looks harmful may be running right now. Unless you started it, deal with this one first.",
                fileContents: "No. It reads command lines only, and a matching one appears in the finding.",
                internet: CheckDetails.staysOnMac
            )
        case .listeningPort:
            CheckDetails(
                looksFor: "Programs waiting for connections on ports the signed rules list, such as ports that backdoors use by default.",
                looksIn: "Listening TCP ports from the system tool lsof, which mainly shows your own programs without administrator rights.",
                findingMeans: "A program may accept connections from your network. That's fine if you know it. If not, find it and quit it.",
                fileContents: "No. It reads port numbers and program names only.",
                internet: CheckDetails.staysOnMac
            )
        case .fileHash:
            CheckDetails(
                looksFor: "Exact copies of known malware files. Each file's SHA-256 fingerprint is compared with the signed rules and the malware feed.",
                looksIn: "~/Downloads, ~/Desktop, /Users/Shared and\n/private/tmp, newest files first, up to the numbers in Settings › Limits.",
                findingMeans: "This file is an exact copy of a known sample, or of the harmless test file if the finding says so. Don't open it.",
                fileContents: "Yes. It reads each file to compute its fingerprint and keeps only the fingerprint.",
                internet: "No. The fingerprint lists are already on your Mac."
            )
        case .crontab:
            CheckDetails(
                looksFor: "Scheduled jobs that match the signed rules, such as ones that download or decode code and run it on a timer.",
                looksIn: "Your own crontab, from crontab -l.",
                findingMeans: "A job that looks like malware keeps running on a timer. If you didn't add it, remove it.",
                fileContents: "Only your crontab's lines. A matching line appears in the finding.",
                internet: CheckDetails.staysOnMac
            )
        case .setting:
            CheckDetails(
                looksFor: "Whether System Integrity Protection, Gatekeeper or the Application Firewall is turned off.",
                looksIn: "The status reported by the macOS tools csrutil, spctl and socketfilterfw.",
                findingMeans: "A protection built into macOS is off, so your Mac is easier to attack. Turn it back on unless you need it off.",
                fileContents: "No. It reads only whether each one is on or off.",
                internet: CheckDetails.staysOnMac
            )
        case .launchItemSignature:
            CheckDetails(
                looksFor: "Programs started by launch items that are unsigned, ad-hoc signed, have a broken signature or changed after signing.",
                looksIn: "The program each launch item names, in:\n~/Library/LaunchAgents, /Library/LaunchAgents and /Library/LaunchDaemons.",
                findingMeans: "A program that starts by itself has no trustworthy developer identity, or was changed. If you don't know it, treat it as suspect.",
                fileContents: "Yes. It reads each launch item's .plist, and macOS reads the program to validate its signature. Nothing is run.",
                internet: CheckDetails.offlineSignature
            )
        case .appSignature:
            CheckDetails(
                looksFor: "Apps that are unsigned, ad-hoc signed, have a broken signature or changed after signing.",
                looksIn: "/Applications, ~/Applications and ~/Downloads, including one folder down. Bluehat skips itself.",
                findingMeans: "The app has no trustworthy developer identity, or its files changed. Cracked and tampered apps look like this, and so can an app that updated itself.",
                fileContents: "Yes. macOS reads the app's files to validate them. The app isn't run.",
                internet: CheckDetails.offlineSignature
            )
        case .sshKey:
            CheckDetails(
                looksFor: "SSH keys that can log in to your Mac as you. The signed rules decide whether every key is listed or only certain ones.",
                looksIn: "~/.ssh/authorized_keys and\n~/.ssh/authorized_keys2.",
                findingMeans: "Whoever holds the private half of this key can log in as you when Remote Login is on. Ignore keys you know, so only new ones return.",
                fileContents: "Yes, those two files. They hold public keys. Your private keys aren't read.",
                internet: CheckDetails.staysOnMac
            )
        case .profile:
            CheckDetails(
                looksFor: "Configuration profiles. The signed rules decide which to report, such as ones that control your proxy, DNS, certificates or browser.",
                looksIn: "The list from the system tool profiles, which shows only your own profiles without administrator rights. Ones macOS marks as internal are skipped.",
                findingMeans: "A profile can change settings and reroute your traffic. That's normal from a school or company. If not, remove it.",
                fileContents: "No. It reads each profile's name, identifier and payload types.",
                internet: CheckDetails.staysOnMac
            )
        case .browserExtension:
            CheckDetails(
                looksFor: "Extensions the signed rules flag, such as ones from published attacks, from outside official stores or with wide permissions.",
                looksIn: "Chrome, Brave, Edge, Arc, Chromium, Vivaldi and Firefox profiles in ~/Library/Application Support. Safari extensions come with apps, so App signing covers them.",
                findingMeans: "An extension may be able to read your browsing or sign-ins. Some findings only note wide permissions. Remove what you don't recognize.",
                fileContents: "Only extension details: manifest.json, messages.json and Firefox's extensions.json. Not your history, passwords or cookies.",
                internet: "No. Extension update addresses are read but never contacted."
            )
        case .softwareVersion:
            CheckDetails(
                looksFor: "Copies of Node.js, Python, Ruby, PHP, OpenSSL and Git at a version the signed rules list as having a known vulnerability.",
                looksIn: "Homebrew, nvm, Volta, fnm, asdf, mise, pyenv and rbenv version folders, python.org frameworks and the nodejs.org installer.",
                findingMeans: "This copy has a known security hole, which doesn't mean anyone used it. Update it, then remove the old copy.",
                fileContents: "Almost none. Versions come from folder names and, for python.org and nodejs.org copies, one header file. Nothing is run.",
                internet: CheckDetails.staysOnMac
            )
        case .npmPackage:
            CheckDetails(
                looksFor: "npm package versions listed as malicious in the signed rules and the malware feed.",
                looksIn: "Lockfiles of projects in your project folders (Settings › Projects), and global packages in Homebrew and Node.js installs.",
                findingMeans: "A malicious version is installed or locked in. If it ever ran, your npm, GitHub and cloud tokens and SSH keys may be stolen. Follow the steps in order.",
                fileContents: "Yes: lockfiles, and package.json of global packages. It never runs npm, node or any script.",
                internet: "No. The package lists are already on your Mac."
            )
        case .projectFile:
            CheckDetails(
                looksFor: "Code hidden in JavaScript config files and npm install scripts. The signed rules choose the file names and patterns.",
                looksIn: "Projects with a package.json in your project folders (Settings › Projects), only files directly in each project's folder.",
                findingMeans: "This project may run hidden code when you install or build it, as fake job interview projects do. Don't run it until you've checked.",
                fileContents: "Yes, the start of each matching file, up to the size in Settings › Limits. Matched code isn't shown and nothing is run.",
                internet: CheckDetails.staysOnMac
            )
        case .systemExtension:
            CheckDetails(
                looksFor: "System and kernel extensions from vendors that aren't on the signed rules' list. Apple's kernel extensions are skipped.",
                looksIn: "The lists from the macOS tools systemextensionsctl and kmutil.",
                findingMeans: "Software with more power than an app is installed. An unlisted vendor doesn't make it bad: many VPNs and drivers aren't listed.",
                fileContents: "No. It reads names, bundle IDs and team IDs only.",
                internet: CheckDetails.staysOnMac
            )
        case .xprotect:
            CheckDetails(
                looksFor: "Whether XProtect, the malware scanner built into macOS, is older than the version the signed rules expect.",
                looksIn: "XProtect.bundle in /Library/Apple/System/Library/CoreServices and /private/var/protected/xprotect. The higher version counts.",
                findingMeans: "macOS hasn't updated its malware definitions, so it may miss current threats. Check that security updates are on.",
                fileContents: "Only those two Info.plist files, for the version number.",
                internet: CheckDetails.staysOnMac
            )
        case .outbound:
            CheckDetails(
                looksFor: "Connections to addresses or ports listed in the signed rules and the malware feed, such as known malware servers.",
                looksIn: "Open TCP and UDP connections from the system tool netstat. Connections within this Mac and link-local ones are skipped.",
                findingMeans: "A program is connected to a listed address. Addresses can be reused, so check the process before you act.",
                fileContents: "No. It sees addresses, ports and process names, never what a connection carries.",
                internet: "No. It only lists existing connections, never connects to a listed address and looks up no names."
            )
        case .notarization:
            CheckDetails(
                looksFor: "Apps signed with a Developer ID that Apple never notarized, so Apple never scanned that build for malware.",
                looksIn: "The same apps as App signing:\n/Applications, ~/Applications and ~/Downloads, including one folder down.",
                findingMeans: "Many older apps look like this and are fine. Look for a newer version, and remove the app if you don't know where it came from.",
                fileContents: "Only each app's signature and notarization ticket. The app isn't run.",
                internet: "Sometimes. If macOS can't settle a new or changed app offline, Gatekeeper may ask Apple, for 5 apps per scan by default (Settings › Limits). Never when offline."
            )
        case .nodeInstall:
            CheckDetails(
                looksFor: "Code added to npm's own files, which then runs with every npm command. The signed rules choose the files and patterns.",
                looksIn: "The global node_modules of each Node.js install: Homebrew, nvm, Volta, fnm, asdf, mise and /usr/local. Only the files the rules name.",
                findingMeans: "npm on this Mac was changed to run hidden code, so it ran each time you used npm or npx. Treat its secrets as stolen.",
                fileContents: "Yes, the start of each named file, up to the size in Settings › Limits. Matched code isn't shown and nothing is run.",
                internet: CheckDetails.staysOnMac
            )
        }
    }

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
        case .systemExtension: "System extensions"
        case .xprotect: "XProtect"
        case .outbound: "Connections"
        case .notarization: "Notarization"
        case .nodeInstall: "Node.js installs"
        }
    }

    var inlineTitle: String {
        guard let first = title.first, title.dropFirst().first?.isLowercase == true else { return title }
        return first.lowercased() + title.dropFirst()
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
        case .systemExtension: "memorychip"
        case .xprotect: "checkmark.shield"
        case .outbound: "antenna.radiowaves.left.and.right"
        case .notarization: "checkmark.seal"
        case .nodeInstall: "curlybraces.square"
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
        case .npmPackage: "Remove the package or pin a version that isn't listed, delete node_modules, and reinstall from a clean lockfile with npm ci --ignore-scripts. These attacks steal secrets, and some leave a monitor that wipes your home folder when a stolen GitHub token is revoked, from any device. Before revoking anything, if ~/Library/LaunchAgents/com.user.gh-token-monitor.plist exists, run launchctl bootout gui/$(id -u) on it, then delete it, ~/.local/bin/gh-token-monitor.sh and ~/.config/gh-token-monitor. Then from another device rotate your npm, GitHub and cloud tokens and SSH keys, and check your GitHub account for repositories, workflows or keys you didn't add."
        case .projectFile: "Don't run the project: no npm install, npm run dev or other scripts. Open the file in a plain text editor, go to the reported line and scroll far to the right, since payloads hide after long runs of spaces. Compare it with the original repository. If the project came from a stranger or a job interview, delete it. If you already ran it, first remove what Bluehat's other findings show it left behind, because some malware wipes your home folder when a stolen GitHub token is revoked. Then from another device rotate your npm, GitHub and cloud tokens and SSH keys."
        case .systemExtension: "If you know the app it came from, ignore this finding. Otherwise open System Settings › General › Login Items & Extensions, turn the extension off, and delete the app that installed it. For a kernel extension, run the vendor's uninstaller and restart."
        case .xprotect: "Open System Settings › General › Software Update, click the info button next to Automatic Updates, and turn on Install Security Responses and system files. Stay online and restart; macOS updates XProtect on its own. Scan again a day later."
        case .outbound: "Open Activity Monitor, search for the process named above, and quit it (Force Quit if it comes back). Then scan again and remove the launch item, app or file that started it. If it was malware, change your passwords from another device, starting with email, Apple Account and banking. If you know the app and trust it, ignore this finding."
        case .notarization: "Check the developer's website for a newer version of the app, which is usually notarized, and install it from there. If the app is old and you trust its developer, ignore this finding. If you don't know where it came from, quit it and move it to the Trash."
        case .nodeInstall: "Don't run npm or npx with this Node.js version. Reinstall it with the tool that installed it (for example nvm uninstall and nvm install, or brew reinstall node), which replaces npm's files, then scan again. Act on Bluehat's other findings first, then from another device rotate your npm, GitHub and cloud tokens and SSH keys."
        }
    }
}
