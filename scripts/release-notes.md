Bluehat is a menu bar threat scanner for macOS. It checks for known malware, persistence, unsigned apps, risky browser extensions, vulnerable developer tools (node, php, python, openssl, git, ruby), malicious npm packages and code injected into JavaScript project config files. Rules are Ed25519-signed and update automatically from [lysari/bluehat-rules](https://github.com/lysari/bluehat-rules).

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

App updates are manual for now: download the new DMG from Releases. Rules update by themselves.

## Verify your download

```
shasum -a 256 Bluehat-@VERSION@.dmg
```

should print:

```
@SHA256@
```
