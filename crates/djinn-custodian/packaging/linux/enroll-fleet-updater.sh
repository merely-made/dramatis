#!/bin/bash
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'Run once as the target administrator.'
[ "$#" = 2 ] || fail 'usage: enroll-fleet-updater.sh STAGED_DIRECTORY CHECKSUM_LIST_SHA256'
bundle=$1
checksum_sha=$2
[[ $bundle = /* && $checksum_sha =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid bundle path or checksum digest.'

user=djinn-updates
receiver=/usr/local/libexec/luggage-ssh-update
adapter=/usr/local/libexec/djinn-custodian-upgrade
policy=/etc/luggage/djinn.json
custody_config=/etc/djinn-custodian/upgrade.json
keys=/etc/ssh/djinn-updates.authorized_keys
keys_pattern='/etc/ssh/djinn-updates\.authorized_keys'
ssh_config=/etc/ssh/sshd_config.d/70-djinn-fleet-updates.conf
sudo_policy=/etc/sudoers.d/djinn-fleet-updates
feed=/var/lib/luggage/djinn/feed
home=/var/lib/djinn-updates
forced="/usr/bin/sudo -n $receiver $policy"

paths=("$receiver" "$adapter" "$policy" "$custody_config" "$keys" "$ssh_config"
       "$sudo_policy" "$feed" "$home")
for path in "${paths[@]}"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "Review the existing installation at $path."
done
getent passwd "$user" >/dev/null && fail "Account $user already exists."
getent group "$user" >/dev/null && fail "Group $user already exists."
systemctl is-active --quiet sshd

private=$(mktemp -d /run/djinn-enroll.XXXXXXXX)
installed=()
directories=()
account_created=false
reload_attempted=false
label_added=false
cleanup() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        for p in "${installed[@]}"; do rm -f -- "$p"; done
        if $reload_attempted; then systemctl reload sshd || true; fi
        if $label_added; then semanage fcontext -d "$keys_pattern" || true; fi
        if $account_created; then userdel "$user" || true; fi
        for ((i=${#directories[@]}-1; i>=0; i--)); do
            rmdir -- "${directories[i]}" || true
        done
    fi
    rm -rf -- "$private"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

files=(djinn-custodian-upgrade djinn-luggage.json luggage-ssh-update upgrade.json operator.pub)
for p in SHA256SUMS "${files[@]}"; do install -m 0600 -- "$bundle/$p" "$private/$p"; done
cd "$private"
printf '%s  SHA256SUMS\n' "$checksum_sha" | sha256sum --check --status
sha256sum --check --strict --status SHA256SUMS
for p in "${files[@]}"; do
    grep -Eq "^[a-f0-9]{64}  ${p//./[.]}$" SHA256SUMS || fail "Missing pinned file $p."
done
ssh-keygen -lf operator.pub >/dev/null
read -r key_type key_data comment < operator.pub
[[ $key_type = ssh-ed25519 && $key_data =~ ^[A-Za-z0-9+/=]+$ ]] || fail 'Expected one Ed25519 public key.'
owner=$(python3 -c 'import json; print(json.load(open("upgrade.json"))["owner"])')
[[ $owner =~ ^[a-z_][a-z0-9_-]*$ ]] || fail 'Invalid custodian owner.'
baseline=$(python3 -c 'import json; print(json.load(open("upgrade.json"))["baseline_sha256"])')
[[ $baseline =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid baseline digest.'
printf '%s  /usr/local/libexec/djinn-custodian\n' "$baseline" | sha256sum --check --status
sshd -T -C "user=$owner,host=localhost,addr=127.0.0.1" > existing-ssh

create_dir() {
    if [ ! -d "$1" ]; then
        install -d -o root -g root -m 0755 -- "$1"
        directories+=("$1")
    fi
    if [ -L "$1" ] || [ "$(stat -c %u -- "$1")" != 0 ] ||
        (( (8#$(stat -c %a -- "$1") & 022) != 0 )); then
        fail "Directory is not controlled by the administrator: $1."
    fi
}
put() {
    installed+=("$3")
    install -o root -g root -m "$1" -- "$2" "$3"
}

for path in /etc/luggage /var/lib/luggage /var/lib/luggage/djinn "$feed" "$home"; do
    create_dir "$path"
done
put 0755 luggage-ssh-update "$receiver"
put 0755 djinn-custodian-upgrade "$adapter"
put 0644 djinn-luggage.json "$policy"
put 0644 upgrade.json "$custody_config"

useradd --system --no-create-home --user-group --home-dir "$home" --shell /bin/sh "$user"
account_created=true
printf 'restrict %s %s\n' "$key_type" "$key_data" > authorized
put 0644 authorized "$keys"
printf '%s ALL=(root) NOPASSWD: %s %s\n' "$user" "$receiver" "$policy" > sudo-config
visudo -cf sudo-config >/dev/null
put 0440 sudo-config "$sudo_policy"
visudo -c >/dev/null

cat > ssh-config <<EOF
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
put 0644 ssh-config "$ssh_config"
if command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
    semanage fcontext -a -t ssh_home_t "$keys_pattern"
    label_added=true
fi
if command -v restorecon >/dev/null; then restorecon "${installed[@]}"; fi
sshd -t
sshd -T -C "user=$owner,host=localhost,addr=127.0.0.1" | cmp - existing-ssh
sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" > update-ssh
grep -Fxi "forcecommand $forced" update-ssh
grep -Fxi "authorizedkeysfile $keys" update-ssh
grep -Fxi 'disableforwarding yes' update-ssh
"$adapter" running-version
reload_attempted=true
systemctl reload sshd
printf 'Enrolled %s with the Djinn update command.\n' "$user"
