---
name: bluehat
description: Use when the user wants to check their Mac for RCE, malware, worms, backdoors, miners or weak security settings, to build and open the Bluehat menu bar scanner, or to add or change its detection rules in the lysari/bluehat-rules repository
---

# Bluehat

Bluehat is a macOS menu bar app. Clicking its shield icon opens a panel with a **Scan This Mac** button. A scan downloads the rule list from `https://raw.githubusercontent.com/lysari/bluehat-rules/main/rules.signed.json`, verifies its Ed25519 signature against the public key built into the app, and runs every rule with the check types built into the app. Rules are data only: they cannot add commands, so a compromised repository cannot make the app run code.

## Flow

1. Install and open the app: `devbox run install` (or `devbox run start` to run it from `.build`). The first launch shows a welcome window to turn on scheduled scans and launch at login.
2. Click the shield in the menu bar, then **Scan Now**. The ring fills per check area as the scan runs.
3. Click a finding for what was found, why it matters, how to fix it, and source links. **Ignore** hides that exact finding; undo it in Settings › Ignored. Bluehat reports only and never deletes anything.
4. Settings (Cmd+, from the `⋯` menu): launch at login, scan schedule and new-issue notifications, scan history (last 30 scans with what changed), ignored findings, and the signing key fingerprint.

## Add or change a rule

1. Edit `rules/rules.json` (format in `rules/README.md`) and raise `version`. Give each rule a `summary` and `remedy` for the detail view.
2. Run `devbox run test` to check every rule still validates.
3. Run `devbox run sign-rules`. It refuses to sign invalid rules, stamps the signed `issued` time, and writes `rules/rules.signed.json`.
4. In `rules/` (a git submodule of `lysari/bluehat-rules`), commit both files and `git push`. The app picks them up on the next scan. Then commit the updated `rules` pointer in the app repo, so its tests run against the same rules.
5. Re-sign and push at least every 14 days, even without changes. Signed rules expire 30 days after signing; the app warns at 14 days and refuses expired rules.
6. The rules repo's CI (`Verify rules`) must pass. Key backup and rotation steps are in `rules/README.md`.

## Commands

| Command | What it does |
|---|---|
| `devbox run build` | Debug build |
| `devbox run test` | Run the test suite |
| `devbox run bundle` | Build `.build/Bluehat.app` (release, ad-hoc signed, menu bar only) |
| `devbox run start` | Bundle and open the app from `.build` |
| `devbox run install` | Bundle, copy to `/Applications/Bluehat.app`, and open it |
| `devbox run icon` | Regenerate `assets/AppIcon.icns` from `scripts/make-icon.swift` |
| `devbox run keygen` | Create the signing key in the login Keychain, or print the existing public key |
| `devbox run sign-rules` | Validate and sign `rules/rules.json` with the Keychain key, stamping `issued` and `expires` |
| `devbox run -- swift run bluehat-sign backup-keygen <file>` | Create an offline backup signing key |

## Requirements

- macOS 26 or later, with Xcode at `/Applications/Xcode.app` (devbox.json points `DEVELOPER_DIR` and `SDKROOT` at it; the Command Line Tools lack the SwiftUI macro plugin).
- The private signing key lives only in the login Keychain under service `bluehat-rules-signing`. If it is lost, run `devbox run keygen` on a fresh Keychain, put the new public key in `RuleFeed.publicKey`, rebuild, and re-sign the rules.
