#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != Darwin ]; then
    echo "release.sh: needs macOS" >&2
    exit 1
fi
for tool in swift lipo codesign security plutil hdiutil shasum ditto; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "release.sh: $tool not found" >&2
        exit 1
    fi
done

sh scripts/bundle.sh universal
app=.build/Bluehat.app

archs=$(lipo -archs "$app/Contents/MacOS/Bluehat")
if ! lipo "$app/Contents/MacOS/Bluehat" -verify_arch arm64 x86_64; then
    echo "release.sh: expected arm64 and x86_64, got: $archs" >&2
    exit 1
fi
codesign --verify --deep --strict "$app"
authority=$(codesign -dvv "$app" 2>&1 | sed -n 's/^Authority=//p' | head -n 1)

version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")
dist=.build/dist
dmg=$dist/Bluehat-$version.dmg
staging=.build/dmg-staging
trap 'rm -rf "$staging"' EXIT

rm -rf "$staging"
mkdir -p "$staging" "$dist"
ditto "$app" "$staging/Bluehat.app"
ln -s /Applications "$staging/Applications"
cat > "$staging/How to open Bluehat.txt" <<'TXT'
How to open Bluehat

Bluehat needs macOS 26 or later.

1. Drag Bluehat into the Applications folder.
2. Double-click Bluehat in Applications. macOS says it can't verify the
   developer. Click Done.
3. Open System Settings > Privacy & Security, scroll down, and click
   Open Anyway next to the Bluehat message.
4. Confirm with Open Anyway and your password or Touch ID.

You only do this the first time.

Bluehat is a menu bar app: it has no Dock icon or window. Look for the
shield in the menu bar at the top of the screen and click it to scan.

The detection rules update automatically. App updates are manual:
download the new DMG and drag Bluehat into Applications again.
TXT

hdiutil create -volname Bluehat -srcfolder "$staging" -format UDZO -ov "$dmg"
if [ -n "$authority" ]; then
    codesign --force --sign "$authority" "$dmg"
    codesign --verify --strict "$dmg"
fi
hdiutil verify "$dmg"

echo "App: $app ($archs)"
echo "Signed by: ${authority:-ad-hoc (DMG left unsigned)}"
echo "DMG: $dmg"
echo "SHA-256: $(shasum -a 256 "$dmg" | cut -d ' ' -f 1)"
