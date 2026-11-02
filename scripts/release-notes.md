Bluehat is a menu bar threat scanner for macOS. It checks for known malware, persistence, unsigned apps, risky browser extensions, vulnerable developer tools (node, php, python, openssl, git, ruby), malicious npm packages and code injected into JavaScript project config files. Rules are Ed25519-signed, ship inside the app, and update only when you check and accept in Settings › Rules.

## Changes

@CHANGES@

## Requirements

- macOS 26 or later
- Apple silicon or Intel (universal app)

## Install

1. Download `Bluehat-@VERSION@.dmg`, open it and drag **Bluehat** onto **Applications**.
2. Open Bluehat. macOS says it can't verify the developer, because this build isn't notarized.
3. Go to **System Settings › Privacy & Security** and click **Open Anyway**, then confirm.
4. Look for the shield in the menu bar.

To update the app, click **Check for Updates** in Settings › About. Bluehat installs an update only if it's signed by the update key built into the app; versions without that key need the new DMG from Releases. Rules update from Settings › Rules, after you review the changes.

## Verify your download

```
shasum -a 256 Bluehat-@VERSION@.dmg
```

should print:

```
@SHA256@
```
