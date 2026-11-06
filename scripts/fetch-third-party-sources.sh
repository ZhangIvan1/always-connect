#!/bin/bash
# Downloads the corresponding source of every LGPL/GPL component the App
# ships (OpenConnect and the libraries it loads), exactly the versions
# listed in the App's openconnect/SOURCES, and checks each SHA-256
# (DESIGN.md §三十四, THIRD_PARTY_NOTICES.md). Whoever hands the App to
# someone else keeps these archives next to it, or gives them on request.
#
#   scripts/fetch-third-party-sources.sh <out-dir> [SOURCES file]
#
# SOURCES defaults to .local-build/AlwaysConnect.app's, then the
# installed /Applications/AlwaysConnect.app's.
set -euo pipefail
OUT=${1:?usage: fetch-third-party-sources.sh <out-dir> [SOURCES]}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIST=${2:-}
for c in "$ROOT/.local-build/AlwaysConnect.app/Contents/Resources/openconnect/SOURCES" \
         /Applications/AlwaysConnect.app/Contents/Resources/openconnect/SOURCES; do
    [ -z "$LIST" ] && [ -f "$c" ] && LIST=$c
done
[ -n "$LIST" ] && [ -f "$LIST" ] || { echo "no SOURCES file (build the App first or pass one)" >&2; exit 2; }

get() { curl -fsSL --retry 2 --connect-timeout 20 --max-time "${FETCH_MAX_TIME:-900}" -o "$2.part" "$1" && mv "$2.part" "$2"; }
mkdir -p "$OUT"
cp "$LIST" "$OUT/SOURCES"
bad=0
while read -r formula version url sum; do
    case "$formula" in ''|'#'*) continue;; esac
    [ "$url" = unknown ] && { echo "?? $formula $version: source unknown, see https://formulae.brew.sh/formula/$formula" >&2; bad=1; continue; }
    file="$OUT/$(basename "${url%%\?*}")"
    if [ ! -f "$file" ]; then
        # GNU's mirror redirector sometimes hands out a dead mirror: fall
        # back to the main GNU server.
        get "$url" "$file" || { case "$url" in *ftpmirror.gnu.org/*)
            get "https://ftp.gnu.org/gnu/${url#*ftpmirror.gnu.org/}" "$file";; *) false;; esac; } ||
            { echo "!! $formula $version: download failed ($url)" >&2; bad=1; continue; }
    fi
    if [ "$sum" != "-" ] && [ "$(shasum -a 256 "$file" | cut -d' ' -f1)" != "$sum" ]; then
        echo "!! $formula $version: checksum mismatch for $file" >&2; bad=1
    else
        echo "ok $formula $version $(basename "$file")"
    fi
done < "$LIST"
# Homebrew patches applied on top, if any (listed as "#  patch" lines).
grep '^#  patch' "$LIST" | while read -r _ _ formula url sum; do
    [ "$url" = inline ] && { echo "note: $formula has an inline Homebrew patch, see its formula" ; continue; }
    get "$url" "$OUT/$formula-$(basename "${url%%\?*}")" && echo "ok patch $formula $(basename "$url")"
done || true
exit $bad
