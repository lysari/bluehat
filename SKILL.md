---
name: bluehat
description: Use when the user wants to check their Mac for RCE, malware, worms, backdoors, miners or weak security settings, to build and open the Bluehat menu bar scanner, or to add or change its detection rules in the lysari/bluehat-rules repository
---

# Bluehat

Bluehat is a macOS menu bar app. Clicking its shield icon opens a panel with a **Scan This Mac** button. A scan makes no request for rules: it loads the signed rule list from the Mac (a copy built into the app, or an update the user accepted, in Application Support/Bluehat), verifies its Ed25519 signature against the owner's public keys built into the app, and runs every rule with the check types built into the app. It loads the malware fingerprint feed (`feed.signed.json`, SHA-256 hashes of current macOS malware from MalwareBazaar and ThreatFox) the same way and checks Downloads, Desktop and shared folders against it. Only **Check for Updates** in Settings › Rules contacts `https://raw.githubusercontent.com/lysari/bluehat-rules/main/`; a download is shown as an update only after it passes verification, and nothing is saved until the user accepts it. The same feed can list known-malicious npm package versions (hijacked or worm-published releases), which Bluehat looks for in the lockfiles of your project folders (Settings › Projects) and in the global `node_modules` of each Node.js install, reading files only. Rules can also flag code injected into the config files (`tailwind.config.js`, `next.config.js` and similar) and install scripts of those projects, as fake job interview repositories do. The feed also lists the IP addresses and ports of command-and-control servers of current macOS malware and of attack frameworks such as Cobalt Strike and Sliver from ThreatFox, which Bluehat compares with the Mac's open connections from `netstat` (it never connects to them or looks up names). Apps signed with a Developer ID are checked for notarization: offline from the ticket stapled to the app or already known to macOS, and only for the rest (at most 5 new or changed apps per scan, never while offline) through `spctl --assess`, which makes macOS look up the app's code hash on Apple's servers. The feed is signed by a separate CI key that the app accepts only for fingerprints, never for rules; if the feed is unavailable or expired, the scan runs with the rules alone. Rules and fingerprints are data only: they cannot add commands, so a compromised repository cannot make the app run code.

`README.md` is the public overview (features, privacy, install, build, architecture); update it when checks, commands or network behaviour change.

## Flow

1. Install and open the app: `devbox run install` (or `devbox run start` to run it from `.build`). The first launch shows a welcome window to turn on scheduled scans and launch at login.
2. Click the shield in the menu bar (after a scan it shows the number of issues beside it), then **Scan Now**. The ring fills per check area as the scan runs. The panel stays open above other windows until you click the shield again.
3. Click a finding for what was found, why it matters, how to fix it, and source links. **Ignore** hides that exact finding; undo it in Settings › Ignored. A software version finding also offers **Update** (opens Terminal with the upgrade command, which runs only after you press Return) and **Remove** (moves an nvm, Volta, fnm, asdf, mise, pyenv or rbenv copy to the Trash after you confirm its path, or opens Terminal with `brew` for a Homebrew copy). Bluehat never changes anything unless you ask, and never deletes permanently.
4. Settings (Cmd+, from the `⋯` menu): launch at login, scan schedule and new-issue notifications, project folders to check for npm projects (pre-filled with ~/Developer, ~/Projects, ~/Code and similar folders that exist), scan history (last 30 scans with what changed), ignored findings, and Rules: the local and repository update dates of the rules and the malware feed, Check for Updates, the added, changed and removed rules (counts for the feed), Open Full File, Accept Update and Decline, plus the rules keys, the fingerprint, npm package and C2 address counts, and the feed key. About: the current version, the update key and Check for Updates, which shows either "Up to date" or the new version, its date and its notes, with **Update and Relaunch**.
5. App updates happen only when the user clicks. **Check for Updates** sends one request to `api.github.com`; **Update and Relaunch** downloads the signature file and the DMG from `github.com` and GitHub's download servers, with a progress bar and Cancel. No timer, launch path or scan reaches this code. Bluehat installs only if an Ed25519 signature from the update key built into the app covers this version and the exact DMG, and the app inside has the expected bundle identifier, a newer version and a valid code signature. The new app is swapped in atomically, and the old one is put back if the new one doesn't start. A build with no update key, a release with no signature file, or a copy running outside `/Applications` or `~/Applications` (translocated, in `.build`, or in a folder it can't write) shows why and links to the Releases page instead. Updates and scans never run at the same time.

## Add or change a rule

1. Edit `rules/rules.json` (format in `rules/README.md`) and raise `version`. Give each rule a `summary` and `remedy` for the detail view.
2. Run `devbox run test` to check every rule still validates.
3. Run `devbox run sign-rules` (macOS asks you to approve access to the signing key in the Keychain). It refuses to sign invalid rules, stamps the signed `issued` time, and writes `rules/rules.signed.json`.
4. In `rules/` (a git submodule of `lysari/bluehat-rules`), commit both files and `git push`. Installed apps offer them when the user clicks Check for Updates in Settings › Rules, and nothing changes until the user accepts. Then commit the updated `rules` pointer in the app repo, so its tests run against the same rules and the next build ships them.
5. Re-sign and push the hand-written rules at least once a year, even without changes. Signed rules expire 365 days after signing; the app warns in the last 30 days and refuses expired rules.
6. Malware fingerprints need no manual step: the rules repository's scheduled job pulls MalwareBazaar, OSV and ThreatFox daily and signs `feed.signed.json` with the CI feed key (valid 7 days). The app never pulls it: the user checks and accepts it in Settings › Rules, and when the local copy expires the app scans with the rules alone and says so in the panel. The app also accepts a feed signed with a personal key, for an emergency (`bluehat-sign` signs only rules today).
7. The rules repo's CI (`Verify rules`) must pass. Key backup and rotation steps are in `rules/README.md`.

## Commands

| Command | What it does |
|---|---|
| `devbox run build` | Debug build |
| `devbox run test` | Run the test suite |
| `devbox run bundle` | Build `.build/Bluehat.app` (release, menu bar only), signed with the first "Apple Development" identity in the Keychain so macOS keeps folder permissions across rebuilds; ad-hoc signed when there is none |
| `devbox run start` | Bundle and open the app from `.build` |
| `devbox run install` | Bundle, copy to `/Applications/Bluehat.app`, and open it |
| `devbox run release` | Build a universal (Apple silicon and Intel) app, signed like `bundle`, into `.build/dist/Bluehat-<version>.dmg`, print its SHA-256, and write the update signature `Bluehat-<version>.dmg.sig` when the build has an update key |
| `devbox run publish` | Check the repository, run `release`, and publish the DMG and its update signature as GitHub Release `v<version>` with generated notes and a verified SHA-256; it refuses without the signature; `devbox run publish -- --dry-run` uploads nothing |
| `devbox run icon` | Regenerate `assets/AppIcon.icns` from `scripts/make-icon.swift` |
| `devbox run keygen` | Create the signing key in the login Keychain, or print the existing public key |
| `devbox run sign-rules` | Validate and sign `rules/rules.json` with the Keychain key, stamping `issued` and `expires` |
| `devbox run -- swift run bluehat-sign backup-keygen <file>` | Create an offline backup signing key for rules |
| `devbox run update-keygen` | Create the app update signing key in the login Keychain, or print the existing public key |

## Make a release

Before the first release with in-app updates, create the update key once: run `devbox run update-keygen`, replace `[String]()` in `AppUpdater.trustedKeys` (`Sources/BluehatCore/Services/AppUpdater.swift`) with `["<public key>"]`, run `devbox run test`, then commit and push.

1. Update the `rules` submodule (`git -C rules pull`) so the app ships current signed files; the feed expires 7 days after it was built. Raise `version` (and `build`) at the top of `scripts/bundle.sh`, the only place the version is set (the DMG name and the About tab read it from there), then commit and push it.
2. Run `devbox run publish -- --dry-run`. It runs every check and the build, prints the release notes and the exact `gh` command, and uploads nothing. macOS asks you to approve access to the update key in the Keychain, because the build signs the DMG.
3. Run `devbox run publish`. It refuses unless the tree is clean and equals the pushed `main`, `v<version>` is not yet tagged or released, and the update signature exists. It then builds the DMG, signs it with `bluehat-sign sign-update`, and publishes both files as a GitHub Release of `lysari/bluehat` at that commit with notes from `scripts/release-notes.md` (commits since the previous `v*` tag, or the file in `RELEASE_NOTES`) and the SHA-256. Finally it checks both uploaded files against the local ones.

The app is not Developer ID signed or notarized, so recipients see "Apple could not verify" the first time. They drag Bluehat into Applications, double-click it, click Done, then open System Settings › Privacy & Security and click **Open Anyway** next to the Bluehat message, and confirm. They need macOS 26 or later. Rules update from Settings › Rules after the user reviews them. App updates install from Settings › About; versions 1.0 to 1.2 have no updater, so they need the new DMG once. An app replaced this way carries no quarantine flag, so macOS shouldn't ask for Open Anyway again, and privacy permissions should carry over as long as each release is signed by the same Apple Development identity. Neither has been confirmed on a real in-app update yet, so check both on the first one.

## Requirements

- macOS 26 or later, with Xcode at `/Applications/Xcode.app` (devbox.json points `DEVELOPER_DIR` and `SDKROOT` at it; the Command Line Tools lack the SwiftUI macro plugin).
- The update signing key lives only in the login Keychain under service `bluehat-update-signing`. It is separate from the rules keys because it authorises running code, so never add a rules key to `AppUpdater.trustedKeys`. If it is lost, run `devbox run update-keygen` on a fresh Keychain and add the new public key to `AppUpdater.trustedKeys`. Copies already installed can't verify releases signed with the new key, so they need the new DMG once.
- The private signing key lives only in the login Keychain under service `bluehat-rules-signing`. If it is lost, run `devbox run keygen` on a fresh Keychain, put the new public key in `RuleFeed.trustedKeys` and in `TRUSTED_KEYS` in `rules/.github/workflows/verify.yml`, rebuild, and re-sign the rules.
