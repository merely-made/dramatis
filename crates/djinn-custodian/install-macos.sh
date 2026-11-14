#!/bin/sh
# Copyright 2026 Mark Alan Boykin
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# SPDX-License-Identifier: MPL-2.0
#
# Install a signed djinn-custodian and its consent helper as launchd agents
# for one owner (custody isolation plan §5.2). Run as an administrator,
# never in the account whose vault the custodian will hold, and sign in an
# account that account cannot use (H1-F1):
#
#   sudo install-macos.sh USER SIGNED-APP SIGNED-CONSENT-HELPER TEAM-ID DJINN-TEAM-ID
#
# SIGNED-APP is djinn-custodian.app, built and signed by build-macos.sh: the
# bundle carries the hardened runtime, identifier com.merely.djinn.custodian,
# no get-task-allow, and the keychain-access-groups entitlement with its
# embedded provisioning profile, which is what opens the data-protection
# Keychain envelope for the wallet's sealing root. SIGNED-CONSENT-HELPER is the
# same program signed as com.merely.djinn.custodian.consent: the custodian
# admits it as the consent channel by that signature, and it puts each
# petition to the owner through LocalAuthentication. Djinn must be signed as
# com.merely.djinn by DJINN-TEAM-ID.
#
# This installs and writes configuration only. It moves no data and starts no
# vault: run `adopt` or `init` yourself afterwards, in USER's own session (the
# commands are printed), because the Keychain item belongs to that login.
set -eu

[ "$(id -u)" = 0 ] || { echo 'Run with sudo from an administrator account.' >&2; exit 2; }
[ $# -eq 5 ] || { echo 'usage: install-macos.sh USER SIGNED-APP SIGNED-CONSENT-HELPER TEAM-ID DJINN-TEAM-ID' >&2; exit 2; }
user=$1 app=$2 helper=$3 team=$4 djinn_team=$5
case "$user$team$djinn_team" in *[!A-Za-z0-9_.-]*|'') echo 'Refusing unexpected characters.' >&2; exit 2;; esac
uid=$(id -u "$user")
home=$(dscl . -read "/Users/$user" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
here=$(cd "$(dirname "$0")" && pwd)
root="/Library/Application Support/Merely/djinn-custodian"
group="$team.com.merely.djinn.custodian"
executable="$app/Contents/MacOS/djinn-custodian"

[ -d "$app" ] && [ -x "$executable" ] || { echo "$app is not a signed bundle with a djinn-custodian executable." >&2; exit 2; }
[ -f "$app/Contents/embedded.provisionprofile" ] || { echo 'The bundle carries no embedded provisioning profile.' >&2; exit 2; }
[ -f "$helper" ] && [ -x "$helper" ] || { echo "$helper is not an executable." >&2; exit 2; }

hardened() {
    codesign -d --verbose=4 "$1" 2>&1 | grep -q 'flags=.*runtime' || { echo "$1 lacks the hardened runtime." >&2; exit 2; }
    if codesign -d --entitlements - "$1" 2>/dev/null | grep -q get-task-allow; then
        echo "$1 carries get-task-allow." >&2; exit 2
    fi
}
requirement="anchor apple generic and identifier \"com.merely.djinn.custodian\" and certificate leaf[subject.OU] = \"$team\""
codesign --verify --strict --deep --verbose=2 -R="$requirement" "$app"
hardened "$app"
codesign -d --entitlements - "$app" 2>/dev/null | grep -q "$group" || { echo "The bundle's entitlements do not name the Keychain group $group." >&2; exit 2; }
helper_requirement="anchor apple generic and identifier \"com.merely.djinn.custodian.consent\" and certificate leaf[subject.OU] = \"$team\""
codesign --verify --strict --verbose=2 -R="$helper_requirement" "$helper"
hardened "$helper"

install -d -o root -g wheel -m 0755 "/Library/Application Support/Merely" "$root" "$root/clients"
# A copy replaces the previous bundle whole; root owns it and nobody else may write it.
rm -rf "$root/djinn-custodian.app"
ditto "$app" "$root/djinn-custodian.app"
chown -R root:wheel "$root/djinn-custodian.app"
chmod -R go-w "$root/djinn-custodian.app"
install -o root -g wheel -m 0755 "$helper" "$root/djinn-custodian-consent"

state="$home/Library/Application Support/Merely/djinn-custodian"
install -d -o "$user" -g staff -m 0700 "$home/Library/Application Support/Merely" "$state" "$state/vault" "$state/data"
# Djinn's grants (custody isolation plan, H2 inventory): the Linux values.
# Djinn is matched by its code signature and each release or act waits for
# the owner once per unlock, a guest delegation once per signature. The
# consent helper is matched by its own signature, is the channel and holds
# a status grant only.
grants=$(sed -e 's/@CONSENT@/per-generation/g' -e 's/@SIGN_CONSENT@/per-operation/g' "$here/packaging/djinn-grants.json.in")
cat > "$root/$user.json" <<EOT
{
  "vault": {"directory": "$state/vault", "data_root": "$state/data"},
  "owner": {"unix_uid": $uid},
  "consent": "channel",
  "envelope": {"access_group": "$group"},
  "principals": [
    {"name": "consent", "match": {"signed": {"team": "$team", "identifier": "com.merely.djinn.custodian.consent"}}, "consent_channel": true, "grants": [{"operation": "status"}]},
    {"name": "djinn", "match": {"signed": {"team": "$djinn_team", "identifier": "com.merely.djinn"}}, "grants": $grants}
  ]
}
EOT
cat > "$root/clients/$uid.json" <<EOT
{"endpoint": "$state/custody.sock",
 "server": {"signed": [{"team": "$team", "identifier": "com.merely.djinn.custodian"}]},
 "agent": "$state/agent.sock"}
EOT
chown root:wheel "$root/$user.json" "$root/clients/$uid.json"
chmod 0644 "$root/$user.json" "$root/clients/$uid.json"
for name in com.merely.djinn.custodian com.merely.djinn.custodian.consent; do
    sed -e "s|@USER@|$user|g" -e "s|@HOME@|$home|g" "$here/packaging/macos/$name.plist.in" > "/Library/LaunchAgents/$name.plist"
    chown root:wheel "/Library/LaunchAgents/$name.plist"
    chmod 0644 "/Library/LaunchAgents/$name.plist"
    plutil -lint "/Library/LaunchAgents/$name.plist"
done
bin="$root/djinn-custodian.app/Contents/MacOS/djinn-custodian"
echo "Installed under $root. As $user, in that account's own login session, run one of:"
echo "  '$bin' init  --config '$root/$user.json'                       # a new vault"
echo "  '$bin' adopt --config '$root/$user.json' --from VAULT-DIR --data-from DJINN-DATA-ROOT"
echo "then log out and in (or: launchctl bootstrap gui/$uid /Library/LaunchAgents/com.merely.djinn.custodian.plist, and the same for .consent)."
echo "Point SSH_AUTH_SOCK at $state/agent.sock."
