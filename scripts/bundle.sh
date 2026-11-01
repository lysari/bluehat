#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

version=1.2
build=2

case "${1:-}" in
    "") arch_flags="" ;;
    universal) arch_flags="--arch arm64 --arch x86_64" ;;
    *) echo "usage: bundle.sh [universal]" >&2; exit 64 ;;
esac
swift build -c release --product Bluehat $arch_flags
bin=$(swift build -c release $arch_flags --show-bin-path)

app=.build/Bluehat.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin/Bluehat" "$app/Contents/MacOS/Bluehat"
cp assets/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Bluehat</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.lysari.bluehat</string>
    <key>CFBundleName</key>
    <string>Bluehat</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$version</string>
    <key>CFBundleVersion</key>
    <string>$build</string>
    <key>LSMinimumSystemVersion</key>
    <string>26.0</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST
identity=$(security find-identity -v -p codesigning | awk '/"Apple Development: /{print $2; exit}')
codesign --force --options runtime --sign "${identity:--}" "$app"
echo "$app"
