#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

repo=lysari/bluehat
branch=main

case "$#:${1:-}" in
    0:) dry_run= ;;
    1:--dry-run) dry_run=1 ;;
    *) echo "usage: publish.sh [--dry-run]" >&2; exit 64 ;;
esac

fail() {
    echo "publish.sh: $*" >&2
    exit 1
}

if [ "$(uname -s)" != Darwin ]; then
    fail "needs macOS"
fi
for tool in git gh shasum hdiutil plutil awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool not found"
    fi
done
if ! gh auth status >/dev/null 2>&1; then
    fail "gh is not logged in; run: gh auth login"
fi

if [ -n "${RELEASE_NOTES:-}" ] && [ ! -f "$RELEASE_NOTES" ]; then
    fail "RELEASE_NOTES file $RELEASE_NOTES not found"
fi
if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    fail "the working tree has changes; commit and push them, or stash them, first"
fi
if [ "$(git symbolic-ref --quiet --short HEAD)" != "$branch" ]; then
    fail "not on $branch; run: git switch $branch"
fi
git fetch --quiet --tags origin "$branch"
head=$(git rev-parse HEAD)
remote=$(git rev-parse "origin/$branch")
if [ "$head" != "$remote" ]; then
    fail "HEAD ($head) is not origin/$branch ($remote); push your commits or pull first"
fi

sh scripts/release.sh

if [ "$(git rev-parse HEAD)" != "$head" ] || [ -n "$(git status --porcelain)" ]; then
    fail "the repository changed during the build; run again"
fi

version=$(plutil -extract CFBundleShortVersionString raw -o - .build/Bluehat.app/Contents/Info.plist)
tag=v$version
asset=Bluehat-$version.dmg
dmg=.build/dist/$asset
if [ ! -f "$dmg" ]; then
    fail "$dmg not found after the build"
fi
if git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
    fail "tag $tag already exists locally; raise version in scripts/bundle.sh, commit and push"
fi
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
    fail "tag $tag already exists on origin; raise version in scripts/bundle.sh, commit and push"
fi
if gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
    fail "GitHub release $tag already exists; raise version in scripts/bundle.sh, commit and push"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

previous=$(git describe --tags --abbrev=0 --match 'v*' HEAD 2>/dev/null || true)
changes=$work/changes.md
if [ -n "${RELEASE_NOTES:-}" ]; then
    cat "$RELEASE_NOTES" > "$changes"
elif [ -n "$previous" ]; then
    git log --no-merges --format='- %s' "$previous..HEAD" > "$changes"
else
    echo "First release." > "$changes"
fi

sha256=$(shasum -a 256 "$dmg" | cut -d ' ' -f 1)
notes=$work/notes.md
awk -v version="$version" -v sha256="$sha256" -v changes="$changes" '
    $0 == "@CHANGES@" { while ((getline line < changes) > 0) print line; next }
    { gsub(/@VERSION@/, version); gsub(/@SHA256@/, sha256); print }
' scripts/release-notes.md > "$notes"

if [ -n "$dry_run" ]; then
    echo "Release notes:"
    echo
    cat "$notes"
    echo
    echo "Dry run, nothing uploaded. Without --dry-run this runs:"
    echo "gh release create $tag $dmg -R $repo --target $head --title \"Bluehat $version\" --notes-file <the notes above>"
    exit 0
fi

gh release create "$tag" "$dmg" -R "$repo" --target "$head" --title "Bluehat $version" --notes-file "$notes"

download=$work/download
mkdir "$download"
gh release download "$tag" -R "$repo" -p "$asset" -D "$download"
published=$(shasum -a 256 "$download/$asset" | cut -d ' ' -f 1)
if [ "$published" != "$sha256" ]; then
    cat >&2 <<ERROR

!!! CHECKSUM MISMATCH: the published $asset does not match its release notes !!!

  notes:     $sha256
  published: $published

Do not share this release yet. The release is left in place. Upload the
DMG the notes describe again, then download it into an empty folder and compare:
  gh release upload $tag $dmg -R $repo --clobber
  gh release download $tag -R $repo -p '$asset' -D <empty dir>
  shasum -a 256 <empty dir>/$asset
If it still differs, delete the release on https://github.com/$repo/releases/tag/$tag
and the tag (git push origin :refs/tags/$tag), then run devbox run publish again.
ERROR
    exit 1
fi

echo "Published: $(gh release view "$tag" -R "$repo" --json url --jq .url)"
echo "SHA-256: $sha256"
