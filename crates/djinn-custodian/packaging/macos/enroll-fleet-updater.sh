#!/bin/bash
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

set -Eeo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'Run once as the target administrator.'
[ "$#" = 2 ] || fail 'usage: enroll-fleet-updater.sh STAGED_DIRECTORY CHECKSUM_LIST_SHA256'
bundle=$1
checksum=$2
[[ $bundle = /* && $checksum =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid bundle path or checksum digest.'

user=_djinnupdates
receiver=/usr/local/libexec/luggage-ssh-update
adapter=/usr/local/libexec/djinn-custodian-upgrade
policy=/private/etc/luggage/djinn.json
custody_config=/private/etc/djinn-custodian/upgrade.json
keys=/private/etc/ssh/djinn-updates.authorized_keys
ssh_config=/private/etc/ssh/sshd_config.d/190-djinn-fleet-updates.conf
sudo_config=/private/etc/sudoers.d/djinn-fleet-updates
feed=/private/var/lib/luggage/djinn/feed
forced="/usr/bin/sudo -n $receiver $policy"
paths=("$receiver" "$adapter" "$policy" "$custody_config" "$keys" "$ssh_config" "$sudo_config" "$feed")
for path in "${paths[@]}"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "Review the existing installation at $path."
done
if dscl . -read "/Users/$user" >/dev/null 2>&1; then fail "Account $user already exists."; fi
sshd -t
dseditgroup -o read com.apple.access_ssh >/dev/null

private=$(mktemp -d /private/var/tmp/djinn-enroll.XXXXXXXX)
installed=()
directories=()
account_created=0
member_added=0
cleanup() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        if [ "$member_added" = 1 ]; then dseditgroup -o edit -d "$user" -t user com.apple.access_ssh || true; fi
        if [ "$account_created" = 1 ]; then dscl . -delete "/Users/$user" || true; fi
        for path in "${installed[@]}"; do rm -f -- "$path"; done
        for ((i=${#directories[@]}-1; i>=0; i--)); do rmdir -- "${directories[i]}" || true; done
    fi
    rm -rf -- "$private"
    exit "$status"
}
trap cleanup EXIT
trap 'printf "Enrollment stopped at line %s while running %s.\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM

files=(djinn-custodian-upgrade djinn-luggage.json luggage-ssh-update upgrade.json operator.pub)
for path in SHA256SUMS "${files[@]}"; do install -m 0600 "$bundle/$path" "$private/$path"; done
cd "$private"
printf '%s  SHA256SUMS\n' "$checksum" | shasum -a 256 -c
shasum -a 256 -c SHA256SUMS
for path in "${files[@]}"; do
    grep -Eq "^[a-f0-9]{64}  ${path//./[.]}$" SHA256SUMS || fail "Missing pinned file $path."
done
ssh-keygen -lf operator.pub >/dev/null
read -r key_type key_data comment < operator.pub
[[ $key_type = ssh-ed25519 && $key_data =~ ^[A-Za-z0-9+/=]+$ ]] || fail 'Expected one Ed25519 public key.'
owner=$(python3 -I -c 'import json; print(json.load(open("upgrade.json"))["owner"])')
[[ $owner =~ ^[a-z_][a-z0-9_-]*$ ]] || fail 'Invalid custodian owner.'
sshd -T -C "user=$owner,host=localhost,addr=127.0.0.1" > owner-ssh.before

create_dir() {
    if [ ! -d "$1" ]; then
        install -d -o root -g wheel -m 0755 "$1"
        directories+=("$1")
    fi
    if [ -L "$1" ] || [ "$(stat -f '%u' "$1")" != 0 ] || (( (8#$(stat -f '%OLp' "$1") & 022) != 0 )); then
        fail "Directory is not controlled by the administrator: $1."
    fi
}
put() {
    installed+=("$3")
    install -o root -g wheel -m "$1" "$2" "$3"
}
for path in /usr/local /usr/local/libexec /private/etc/luggage /private/etc/djinn-custodian \
    /private/var/lib/luggage /private/var/lib/luggage/djinn "$feed"; do
    create_dir "$path"
done
put 0755 luggage-ssh-update "$receiver"
put 0755 djinn-custodian-upgrade "$adapter"
put 0644 djinn-luggage.json "$policy"
put 0644 upgrade.json "$custody_config"
"$adapter" running-version

dscl . -list /Users UniqueID | awk '{print $2}' > used-uids
uid=
for n in {450..499}; do
    if ! grep -Fxq "$n" used-uids; then uid=$n; break; fi
done
[ -n "$uid" ] || fail 'No free macOS service UID.'
record="/Users/$user"
dscl . -create "$record"
account_created=1
set_attribute() {
    printf 'Setting update service %s.\n' "$1"
    dscl . -create "$record" "$1" "$2"
}
set_attribute UniqueID "$uid"
set_attribute PrimaryGroupID 20
if ! dscl . -read "$record" GeneratedUID >/dev/null 2>&1; then
    set_attribute GeneratedUID "$(uuidgen)"
fi
set_attribute RealName 'Djinn Fleet Update Service'
set_attribute IsHidden 1
set_attribute NFSHomeDirectory /var/empty
set_attribute UserShell /bin/sh
# macOS creates authentication metadata with the record and applies its
# password policy even to a disabled marker. Give the service a random
# credential; the SSH policy below accepts only the restricted public key.
python3 -I - "$record" <<'PY'
import secrets
import subprocess
import sys

result = subprocess.run(
    ["/usr/bin/dscl", ".", "-passwd", sys.argv[1], secrets.token_urlsafe(48)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
if result.returncode:
    raise SystemExit("Could not initialize the service account credential.")
PY

printf 'restrict %s %s\n' "$key_type" "$key_data" > authorized
put 0644 authorized "$keys"
printf '%s ALL=(root) NOPASSWD: %s %s\n' "$user" "$receiver" "$policy" > update-sudo
visudo -cf update-sudo >/dev/null
put 0440 update-sudo "$sudo_config"
visudo -c
sudo -l -U "$user"

cat > update-ssh <<EOF
Match User $user
    AuthenticationMethods publickey
    PubkeyAcceptedAlgorithms ssh-ed25519
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile $keys
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    PermitTTY no
    PermitUserRC no
    DisableForwarding yes
    ForceCommand $forced
Match all
EOF
put 0644 update-ssh "$ssh_config"
sshd -t
sshd -T -C "user=$owner,host=localhost,addr=127.0.0.1" | cmp - owner-ssh.before
sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" > effective-ssh
grep -Fxi "forcecommand $forced" effective-ssh
grep -Fxi "authorizedkeysfile $keys" effective-ssh
grep -Fxi 'authenticationmethods publickey' effective-ssh
grep -Fxi 'disableforwarding yes' effective-ssh
member_added=1
dseditgroup -o edit -a "$user" -t user com.apple.access_ssh
dseditgroup -o checkmember -m "$user" com.apple.access_ssh
printf 'Enrolled %s with the Djinn update command.\n' "$user"
