#!/bin/bash
# Refresh an existing standalone recovery copy after a verified App install.
# Runs only as the login user; never executes the copied recovery script.
set -euo pipefail
[ "$#" = 2 ] || exit 64
[ "$(id -u)" != 0 ] || { echo 'skip Desktop recovery refresh as root' >&2; exit 0; }
source_script=$1
destination=$2
directory=$(dirname "$destination")
marker='# AlwaysConnect emergency network reset (DESIGN.md §24.6).'
is_recovery_script() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(sed -n '2p' "$1")" = "$marker" ]
}
is_recovery_script "$source_script" || { echo 'invalid bundled recovery resource' >&2; exit 1; }
# Do not add Desktop files, replace personal notes, follow links, or rewrite
# another user's copy. These are the same ownership markers as uninstall.
[ -d "$directory" ] && [ ! -L "$directory" ] || exit 0
is_recovery_script "$destination" || exit 0
[ "$(stat -f %u "$destination")" = "$(id -u)" ] || exit 0
cmp -s "$source_script" "$destination" && exit 0
temporary=$(mktemp "$directory/.alwaysconnect-recovery.XXXXXXXX")
trap 'rm -f "$temporary"' EXIT
install -m 700 "$source_script" "$temporary"
# Recheck before replacing; rename replaces this file, not a symlink target.
is_recovery_script "$destination" || exit 0
[ "$(stat -f %u "$destination")" = "$(id -u)" ] || exit 0
mv -f "$temporary" "$destination"
