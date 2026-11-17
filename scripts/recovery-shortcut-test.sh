#!/bin/bash
# Real file copies in a temporary directory; never the user's Desktop.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
REFRESH="$ROOT/scripts/refresh-recovery-shortcut.sh"
[ -f "$REFRESH" ] || { echo 'FAIL no installer path to refresh an existing recovery copy'; exit 1; }
SOURCE="$ROOT/scripts/reset-network.sh"
mkdir -p "$WORK/Desktop"
TARGET="$WORK/Desktop/AlwaysConnect 恢复网络.command"
refresh() { /bin/bash "$REFRESH" "$SOURCE" "$TARGET"; }

# An update does not create a new Desktop file without an existing copy.
refresh
[ ! -e "$TARGET" ]
printf '#!/bin/bash\n# AlwaysConnect emergency network reset (DESIGN.md §24.6).\n# old version\n' > "$TARGET"
chmod 644 "$TARGET"
refresh
cmp -s "$SOURCE" "$TARGET"
[ "$(stat -f %Lp "$TARGET")" = 700 ]
[ "$(stat -f %u "$TARGET")" = "$(id -u)" ]
before=$(stat -f %m "$TARGET")
refresh
[ "$(stat -f %m "$TARGET")" = "$before" ]

# Same-name personal files and symlink targets must never be overwritten.
printf 'personal recovery notes\n' > "$TARGET"
refresh
grep -qx 'personal recovery notes' "$TARGET"
cp "$SOURCE" "$WORK/external"
rm "$TARGET"
ln -s "$WORK/external" "$TARGET"
refresh
[ -L "$TARGET" ]
cmp -s "$SOURCE" "$WORK/external"
rm "$TARGET"
mkdir "$TARGET"
refresh
[ -d "$TARGET" ]
rmdir "$TARGET"
printf '#!/bin/bash\n# AlwaysConnect emergency network reset (DESIGN.md §24.6).\n# old version\n' > "$TARGET"
cp "$TARGET" "$WORK/original"
mv "$WORK/Desktop" "$WORK/actual-desktop"
ln -s "$WORK/actual-desktop" "$WORK/Desktop"
refresh
cmp -s "$WORK/original" "$TARGET"
rm "$WORK/Desktop"
mv "$WORK/actual-desktop" "$WORK/Desktop"

# A root installer must not refresh files in a user's Desktop. Substitute
# only the identity readback; the test itself remains an ordinary user.
mkdir "$WORK/bin"
printf '#!/bin/bash\nprintf "0\\n"\n' > "$WORK/bin/id"
chmod +x "$WORK/bin/id"
PATH="$WORK/bin:$PATH" /bin/bash "$REFRESH" "$SOURCE" "$TARGET" 2>/dev/null
cmp -s "$WORK/original" "$TARGET"
rm "$WORK/bin/id"

# A copy owned by somebody else is also kept. Only this metadata read is
# substituted; file matching and the refresh implementation remain real.
cat > "$WORK/bin/stat" <<'STUB'
#!/bin/bash
if [ "$1" = -f ] && [ "$2" = %u ]; then echo 0; else /usr/bin/stat "$@"; fi
STUB
chmod +x "$WORK/bin/stat"
PATH="$WORK/bin:$PATH" /bin/bash "$REFRESH" "$SOURCE" "$TARGET"
cmp -s "$WORK/original" "$TARGET"
rm "$WORK/bin/stat"

# Copy/rename errors keep the usable old script and remove staging files.
for command in install mv; do
    printf '#!/bin/bash\nexit 1\n' > "$WORK/bin/$command"
    chmod +x "$WORK/bin/$command"
    if PATH="$WORK/bin:$PATH" /bin/bash "$REFRESH" "$SOURCE" "$TARGET"; then
        echo "FAIL $command failure reported as a successful refresh"; exit 1
    fi
    cmp -s "$WORK/original" "$TARGET"
    [ "$(find "$WORK/Desktop" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 1 ]
    rm "$WORK/bin/$command"
done

# A missing or unrelated bundled resource cannot replace the recovery copy.
if /bin/bash "$REFRESH" "$WORK/missing" "$TARGET" 2>/dev/null; then echo 'FAIL missing recovery source accepted'; exit 1; fi
printf 'unrelated source\n' > "$WORK/unrelated"
if /bin/bash "$REFRESH" "$WORK/unrelated" "$TARGET" 2>/dev/null; then echo 'FAIL foreign recovery source accepted'; exit 1; fi
cmp -s "$WORK/original" "$TARGET"
[ "$(find "$WORK/Desktop" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 1 ]
echo 'PASS existing recovery copy refreshed; absent, foreign and linked paths preserved (temporary files only)'
