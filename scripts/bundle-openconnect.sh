#!/bin/bash
# Makes a self-contained openconnect for the App (DESIGN.md §27.3): the
# binary plus every non-system library it loads, rewritten to load from
# next to each other, signed, with their licences.
#
#   scripts/bundle-openconnect.sh <out-dir> [sign-identity]
#
# <out-dir>/bin/openconnect, <out-dir>/lib/*.dylib, <out-dir>/licenses/,
# <out-dir>/VERSIONS. The source is the build machine's Homebrew
# openconnect (`brew install openconnect`); the users' Macs need nothing.
set -euo pipefail
OUT=${1:?out dir}
IDENTITY=${2:--}
SRC=$(command -v openconnect || true)
for c in /opt/homebrew/bin/openconnect /usr/local/bin/openconnect; do [ -z "$SRC" ] && [ -x "$c" ] && SRC=$c; done
[ -n "$SRC" ] || { echo "no openconnect on the build machine: brew install openconnect" >&2; exit 2; }
SRC=$(cd "$(dirname "$SRC")" && cd "$(dirname "$(readlink "$SRC" || basename "$SRC")")" && pwd)/$(basename "$(readlink "$SRC" || echo openconnect)")

rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/lib" "$OUT/licenses"
cp "$SRC" "$OUT/bin/openconnect"
chmod 755 "$OUT/bin/openconnect"

is_system() { case "$1" in /usr/lib/*|/System/*) return 0;; *) return 1;; esac; }
deps() { otool -L "$1" | tail -n +2 | awk '{print $1}'; }
resolve() { # dependency path as written -> real file
    local dep=$1 from=$2
    case "$dep" in
        @loader_path/*) echo "$(dirname "$from")/${dep#@loader_path/}";;
        @rpath/*) for d in /opt/homebrew/lib /usr/local/lib "$(dirname "$from")"; do
                      [ -e "$d/${dep#@rpath/}" ] && { echo "$d/${dep#@rpath/}"; return; }
                  done; echo "$dep";;
        *) echo "$dep";;
    esac
}

# Breadth-first over the library graph, copying each library once.
queue=("$SRC")
seen=" "
while [ ${#queue[@]} -gt 0 ]; do
    file=${queue[0]}; queue=("${queue[@]:1}")
    for dep in $(deps "$file"); do
        is_system "$dep" && continue
        real=$(resolve "$dep" "$file")
        name=$(basename "$dep")
        case "$seen" in *" $name "*) continue;; esac
        seen="$seen$name "
        [ -e "$real" ] || { echo "missing library $dep (from $file)" >&2; exit 1; }
        cp -L "$real" "$OUT/lib/$name"
        chmod 644 "$OUT/lib/$name"
        queue+=("$real")
    done
done

# Rewrite every non-system reference to the copies next door.
fix() { # file prefix
    local f=$1 prefix=$2
    for dep in $(deps "$f"); do
        is_system "$dep" && continue
        install_name_tool -change "$dep" "$prefix/$(basename "$dep")" "$f" 2>/dev/null
    done
}
fix "$OUT/bin/openconnect" "@loader_path/../lib"
for lib in "$OUT"/lib/*.dylib; do
    install_name_tool -id "@loader_path/$(basename "$lib")" "$lib" 2>/dev/null
    fix "$lib" "@loader_path"
done
# Nothing may still point at the build machine.
if otool -L "$OUT/bin/openconnect" "$OUT"/lib/*.dylib | grep -E "/opt/homebrew|/usr/local|@rpath" >/dev/null; then
    otool -L "$OUT/bin/openconnect" "$OUT"/lib/*.dylib | grep -E "/opt/homebrew|/usr/local|@rpath" >&2
    echo "unresolved build-machine paths left" >&2; exit 1
fi
for f in "$OUT"/lib/*.dylib "$OUT/bin/openconnect"; do
    codesign --force --sign "$IDENTITY" --timestamp=none "$f" >/dev/null 2>&1
done

# Licences, versions and corresponding sources of everything shipped
# (DESIGN.md §三十四). LGPL: the user may swap these libraries (they are
# separate files loaded through @loader_path, see README-LGPL.txt); the
# exact source archives are listed in SOURCES with their SHA-256 and
# fetched by scripts/fetch-third-party-sources.sh.
{
    echo "openconnect bundle built $(date -u +%Y-%m-%d) from Homebrew on the build machine"
    "$OUT/bin/openconnect" --version 2>&1 | head -2
} > "$OUT/VERSIONS"
{
    echo "# formula version source-url sha256 (Homebrew formula: https://formulae.brew.sh/formula/<formula>)"
} > "$OUT/SOURCES"
FORMULAS="openconnect gnutls nettle gmp p11-kit libtasn1 libidn2 libunistring gettext stoken libtomcrypt libtommath"
for formula in $FORMULAS; do
    dir=$(brew --prefix "$formula" 2>/dev/null || true)
    [ -n "$dir" ] && [ -d "$dir" ] || continue
    ver=$(basename "$(readlink -f "$dir")")
    echo "$formula $ver" >> "$OUT/VERSIONS"
    brew info --json=v2 "$formula" 2>/dev/null | python3 -I -c '
import json, sys
f = json.load(sys.stdin)["formulae"][0]
s = f["urls"]["stable"]
url, sum_ = s["url"], s.get("checksum") or "-"
installed, current = sys.argv[1].split("_")[0], f["versions"]["stable"]
if installed != current:
    # The formula moved on since this library was installed: its URL is
    # for the newer version. Point at the installed one; no checksum.
    url, sum_ = url.replace(current, installed), "-"
    print("warning: %s %s installed, formula now %s (brew upgrade on the build machine)"
          % (f["name"], installed, current), file=sys.stderr)
print(f["name"], sys.argv[1], url, sum_)
for p in f.get("patches") or []:
    print("#  patch", f["name"], p.get("url") or "inline", p.get("sha256") or "-")
' "$ver" >> "$OUT/SOURCES" || echo "$formula $ver unknown -" >> "$OUT/SOURCES"
    for lic in COPYING COPYING.LESSER COPYING.LIB LICENSE LICENSE.md COPYING.LESSERv3 COPYINGv2 COPYINGv3 COPYING.LGPL; do
        [ -f "$dir/$lic" ] && { mkdir -p "$OUT/licenses/$formula"; cp "$dir/$lic" "$OUT/licenses/$formula/"; }
    done
done
# Homebrew installs only some of the licence files; the full LGPL/GPL
# texts every one of these libraries refers to come from the repository.
cp "$(cd "$(dirname "$0")/.." && pwd)"/third_party/licenses/*.txt "$OUT/licenses/"
cat > "$OUT/README-LGPL.txt" <<'EOF'
This folder holds OpenConnect and the libraries it loads. They are free
software under the GNU LGPL (and, for some, GPL/BSD/public-domain terms):
see licenses/ for each one's licence and SOURCES for the exact source
archive of every version shipped (fetch and verify them with
scripts/fetch-third-party-sources.sh from the AlwaysConnect source tree).

They are separate files, not linked into AlwaysConnect itself: the App
runs bin/openconnect as its own program, and bin/openconnect loads the
libraries in lib/ through @loader_path. To use your own build, replace
any of these files with a compatible one (same library name), then sign
the folder ad hoc so macOS will load it:
    codesign --force --sign - lib/*.dylib bin/openconnect
Quit AlwaysConnect first (this disconnects the VPN). Then deliberately
install your modified components from Terminal, adjusting APP if needed:
    APP=/Applications/AlwaysConnect.app
    sudo /bin/bash "$APP/Contents/Resources/dev-helper.sh" install "$APP/Contents/Library/LaunchDaemons/AlwaysConnectHelper"
The script copies the component folder next to that Helper into
/Library/PrivilegedHelperTools/AlwaysConnect-openconnect.

App management buttons accept only a complete, unmodified App signed
with its original certificate. Replacing a component breaks the bundle
seal; ad-hoc signing does not restore that certificate. Automatic root
execution rejects modified bundles to prevent user-writable files from
becoming administrator code. The explicit Terminal command above is a
user-authorized replacement path; it does not weaken automatic verification.
EOF
echo "bundled $(ls "$OUT/lib" | wc -l | tr -d ' ') libraries into $OUT ($(du -sh "$OUT" | cut -f1))"
