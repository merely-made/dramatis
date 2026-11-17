#!/bin/bash
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'Run as the target administrator.'
[ "$#" = 3 ] || fail 'usage: replace-fleet-receiver.sh NEW_RECEIVER OLD_SHA256 NEW_SHA256'
source=$1
old_sha=$2
new_sha=$3
[[ $source = /* && $old_sha =~ ^[0-9a-f]{64}$ && $new_sha =~ ^[0-9a-f]{64}$ ]] ||
    fail 'Expected an absolute receiver path and two SHA-256 digests.'

receiver=/usr/local/libexec/luggage-ssh-update
prior=/usr/local/libexec/.luggage-ssh-update.previous
lock=/etc/luggage/djinn.lock
for file in "$receiver" "$lock"; do
    [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c %u -- "$file")" = 0 ] ||
        fail "Expected an administrator-owned file at $file."
done
exec 9<>"$lock"
flock -x 9

check_digest() { printf '%s  %s\n' "$1" "$2" | sha256sum --check --status; }
if check_digest "$new_sha" "$receiver"; then
    printf 'The requested Luggage receiver is already installed.\n'
    exit 0
fi
check_digest "$old_sha" "$receiver" || fail 'The installed receiver differs from the expected version.'

stage=$(mktemp -d /usr/local/libexec/.luggage-receiver.XXXXXXXX)
trap 'rm -f -- "$stage/receiver"; rmdir -- "$stage"' EXIT
install -o root -g root -m 0755 -- "$source" "$stage/receiver"
check_digest "$new_sha" "$stage/receiver" || fail 'The replacement receiver checksum differs.'
if command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
    chcon --reference="$receiver" "$stage/receiver"
fi
if [ -e "$prior" ] || [ -L "$prior" ]; then
    [ -f "$prior" ] && [ ! -L "$prior" ] && check_digest "$old_sha" "$prior" ||
        fail 'Review the existing receiver backup before replacing it.'
else
    ln -- "$receiver" "$prior"
fi
mv -T -- "$stage/receiver" "$receiver"
check_digest "$new_sha" "$receiver"
printf 'Replaced the Luggage receiver and retained the previous executable.\n'
