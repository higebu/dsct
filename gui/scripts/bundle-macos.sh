#!/usr/bin/env bash
# Build dsct-gui in release mode and package it as dsct.app and dsct.dmg.
#
# Usage: gui/scripts/bundle-macos.sh [--target <rust-target>]
# Output: gui/target/<profile dir>/bundle/{dsct.app,dsct.dmg}
#
# The app is ad-hoc signed, not notarized: macOS asks for confirmation the
# first time it is opened from a download (see gui/README.md).
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "bundle-macos.sh: run this on macOS" >&2
    exit 1
fi

gui_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$gui_dir"

target_args=()
release_dir="target/release"
if [[ "${1:-}" == "--target" && -n "${2:-}" ]]; then
    target_args=(--target "$2")
    release_dir="target/$2/release"
fi

cargo build --release --locked "${target_args[@]}"

version="$(cargo metadata --no-deps --format-version 1 --locked |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"

bundle_dir="$release_dir/bundle"
app="$bundle_dir/dsct.app"
rm -rf "$bundle_dir"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$release_dir/dsct-gui" "$app/Contents/MacOS/dsct-gui"
sed "s/@VERSION@/$version/g" macos/Info.plist > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"

# Ad-hoc signature so Apple Silicon Macs run the bundle as a whole.
codesign --force --sign - --timestamp=none "$app"
codesign --verify --strict "$app"

hdiutil create -volname dsct -srcfolder "$app" -ov -format UDZO "$bundle_dir/dsct.dmg" >/dev/null
echo "Built $app"
echo "Built $bundle_dir/dsct.dmg"
