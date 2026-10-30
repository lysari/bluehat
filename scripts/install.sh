#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

sh scripts/bundle.sh
pkill -x Bluehat || true
rm -rf /Applications/Bluehat.app
ditto .build/Bluehat.app /Applications/Bluehat.app
open /Applications/Bluehat.app
echo "Installed /Applications/Bluehat.app"
