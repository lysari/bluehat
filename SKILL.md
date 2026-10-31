---
name: bluehat
description: Use when the user wants to check their Mac for RCE, malware, worms, backdoors, miners or weak security settings, to build and open the Bluehat menu bar scanner, or to add or change its detection rules in the lysari/bluehat-rules repository
---

# Bluehat

Bluehat is a macOS menu bar app. Clicking its shield icon opens a panel with a **Scan This Mac** button. A scan downloads the rule list from `https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json`, verifies its Ed25519 signature against the owner's public keys built into the app, and runs every rule with the check types built into the app. It also downloads the malware fingerprint feed (`feed.signed.json`, SHA-256 hashes of current macOS malware from MalwareBazaar) and checks Downloads, Desktop and shared folders against it. The feed is signed by a separate CI key that the app accepts only for fingerprints, never for rules; if the feed is unavailable, the scan runs with the rules alone. Rules and fingerprints are data only: they cannot add commands, so a compromised repository cannot make the app run code.

## Flow

1. Install and open the app: `devbox run install` (or `devbox run start` to run it from `.build`). The first launch shows a welcome window to turn on scheduled scans and launch at login.
2. Click the shield in the menu bar, then **Scan Now**. The ring fills per check area as the scan runs.
3. Click a finding for what was found, why it matters, how to fix it, and source links. **Ignore** hides that exact finding; undo it in Settings › Ignored. Bluehat reports only and never deletes anything.
4. Settings (Cmd+, from the `⋯` menu): launch at login, scan schedule and new-issue notifications, scan history (last 30 scans with what changed), ignored findings, and in About the rules keys, the fingerprint count with its last update and expiry, and the feed key.

## Add or change a rule

1. Edit `rules/rules.json` (format in `rules/README.md`) and raise `version`. Give each rule a `summary` and `remedy` for the detail view.
2. Run `devbox run test` to check every rule still validates.
3. Run `devbox run sign-rules` (macOS asks you to approve access to the signing key in the Keychain). It refuses to sign invalid rules, stamps the signed `issued` time, and writes `rules/rules.signed.json`.
4. In `rules/` (a git submodule of `lysari/bluehat-rules`), commit both files and `git push`. The app picks them up on the next scan. Then commit the updated `rules` pointer in the app repo, so its tests run against the same rules.
5. Re-sign and push the hand-written rules at least once a year, even without changes. Signed rules expire 365 days after signing; the app warns in the last 30 days and refuses expired rules.
6. Malware fingerprints need no manual step: the rules repository's scheduled job pulls MalwareBazaar daily and signs `feed.signed.json` with the CI feed key (valid 7 days). If the job stops, the app keeps using its cached feed until it expires, then scans with the rules alone and says so in the panel. The app also accepts a feed signed with a personal key, for an emergency (`bluehat-sign` signs only rules today).
7. The rules repo's CI (`Verify rules`) must pass. Key backup and rotation steps are in `rules/README.md`.

## Commands

| Command | What it does |
|---|---|
| `devbox run build` | Debug build |
| `devbox run test` | Run the test suite |
| `devbox run bundle` | Build `.build/Bluehat.app` (release, menu bar only), signed with the first "Apple Development" identity in the Keychain so macOS keeps folder permissions across rebuilds; ad-hoc signed when there is none |
| `devbox run start` | Bundle and open the app from `.build` |
| `devbox run install` | Bundle, copy to `/Applications/Bluehat.app`, and open it |
| `devbox run icon` | Regenerate `assets/AppIcon.icns` from `scripts/make-icon.swift` |
| `devbox run keygen` | Create the signing key in the login Keychain, or print the existing public key |
| `devbox run sign-rules` | Validate and sign `rules/rules.json` with the Keychain key, stamping `issued` and `expires` |
| `devbox run -- swift run bluehat-sign backup-keygen <file>` | Create an offline backup signing key |

## Requirements

- macOS 26 or later, with Xcode at `/Applications/Xcode.app` (devbox.json points `DEVELOPER_DIR` and `SDKROOT` at it; the Command Line Tools lack the SwiftUI macro plugin).
- The private signing key lives only in the login Keychain under service `bluehat-rules-signing`. If it is lost, run `devbox run keygen` on a fresh Keychain, put the new public key in `RuleFeed.trustedKeys` and in `TRUSTED_KEYS` in `rules/.github/workflows/verify.yml`, rebuild, and re-sign the rules.
