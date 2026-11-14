#!/bin/sh
# Copyright 2026 Mark Alan Boykin
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# SPDX-License-Identifier: MPL-2.0
#
# Assemble and sign the macOS custodian cohort. Run in the SIGNING account
# (H1-F1: never the account that will run the custodian), from a checkout:
#
#   build-macos.sh IDENTITY TEAM-ID PROVISIONING-PROFILE OUT-DIR [PREBUILT-BINARY]
#
# With PREBUILT-BINARY nothing is compiled: the signing account needs no Rust
# toolchain and signs exactly the binary a reviewed build produced (its SHA-256
# is printed; compare it with the build's receipt). Without it the release
# binary is built from the checkout.
#
# IDENTITY is the Developer ID Application certificate's name or SHA-1.
# PROVISIONING-PROFILE is a macOS Developer ID profile for the App ID
# TEAM-ID.com.merely.djinn.custodian that authorizes the keychain-access-groups
# entitlement (created in the Apple developer portal). OUT-DIR must not exist.
# Produces OUT-DIR/djinn-custodian.app (the custodian, with its entitlement and
# profile) and OUT-DIR/djinn-custodian-consent (the same program signed as the
# consent channel, no entitlements), both hardened-runtime and timestamped,
# and OUT-DIR/revision.txt naming the source it was built from.
set -eu

{ [ $# -eq 4 ] || [ $# -eq 5 ]; } || { echo 'usage: build-macos.sh IDENTITY TEAM-ID PROVISIONING-PROFILE OUT-DIR [PREBUILT-BINARY]' >&2; exit 2; }
identity=$1 team=$2 profile=$3 out=$4 prebuilt=${5:-}
case "$team" in *[!A-Za-z0-9]*|'') echo 'Refusing unexpected characters in the team.' >&2; exit 2;; esac
[ -f "$profile" ] || { echo "$profile is not a file." >&2; exit 2; }
[ ! -e "$out" ] || { echo "$out already exists." >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
group="$team.com.merely.djinn.custodian"

# The profile must carry the group and this team, or the signed binary is
# killed at launch: fail here, not on the install.
decoded=$(security cms -D -i "$profile")
printf '%s' "$decoded" | grep -q "$group" || { echo "The profile does not authorize $group." >&2; exit 2; }
printf '%s' "$decoded" | grep -q "$team" || { echo "The profile does not name team $team." >&2; exit 2; }

if [ -n "$prebuilt" ]; then
    [ -x "$prebuilt" ] || { echo "$prebuilt is not an executable." >&2; exit 2; }
    binary=$prebuilt
else
    (cd "$repo" && cargo build --release -p djinn-custodian --bin djinn-custodian)
    target=$(cd "$repo" && cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')
    binary="$target/release/djinn-custodian"
    [ -x "$binary" ] || { echo "No release binary at $binary." >&2; exit 2; }
fi

mkdir -p "$out/djinn-custodian.app/Contents/MacOS"
cp "$binary" "$out/djinn-custodian.app/Contents/MacOS/djinn-custodian"
cp "$profile" "$out/djinn-custodian.app/Contents/embedded.provisionprofile"
cat > "$out/djinn-custodian.app/Contents/Info.plist" <<EOT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.merely.djinn.custodian</string>
  <key>CFBundleExecutable</key><string>djinn-custodian</string>
  <key>CFBundleName</key><string>Djinn custodian</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.0.1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSBackgroundOnly</key><true/>
</dict></plist>
EOT
cat > "$out/custodian.entitlements" <<EOT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>$group</string>
  <key>com.apple.developer.team-identifier</key><string>$team</string>
  <key>keychain-access-groups</key><array><string>$group</string></array>
</dict></plist>
EOT
# Hardened runtime, no get-task-allow (it is in no entitlement above), a secure timestamp.
codesign --force --sign "$identity" --options runtime --timestamp --identifier com.merely.djinn.custodian \
    --entitlements "$out/custodian.entitlements" "$out/djinn-custodian.app"
cp "$binary" "$out/djinn-custodian-consent"
codesign --force --sign "$identity" --options runtime --timestamp --identifier com.merely.djinn.custodian.consent "$out/djinn-custodian-consent"
rm "$out/custodian.entitlements"
codesign --verify --strict --deep --verbose=2 "$out/djinn-custodian.app"
codesign --verify --strict --verbose=2 "$out/djinn-custodian-consent"
{
    if [ -n "$prebuilt" ]; then
        echo 'prebuilt binary (source revisions are in the build receipt)'
    else
        printf 'dramatis %s\n' "$(cd "$repo" && git rev-parse HEAD)"
        (cd "$repo" && git status --porcelain --untracked-files=no | grep -q .) && echo 'dramatis tree: dirty' || echo 'dramatis tree: clean'
    fi
    shasum -a 256 "$binary" "$out/djinn-custodian.app/Contents/MacOS/djinn-custodian" "$out/djinn-custodian-consent"
} > "$out/revision.txt"
cat "$out/revision.txt"
