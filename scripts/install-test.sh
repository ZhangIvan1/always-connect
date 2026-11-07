#!/bin/bash
# install.sh (DESIGN.md §三十五) against a local server standing in for
# GitHub: release choice, checksum, refusals, replacing an older copy,
# the App's stage-then-install path, quarantine cleared, the old copy
# kept on failure. Installs only into a scratch directory, never
# /Applications, and never quits a real AlwaysConnect (install.sh only
# looks for copies running from the path it installs to).
# Verification level: CI harness.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
SERVER=""
# shellcheck source=scripts/lib-test-identity.sh
. "$ROOT/scripts/lib-test-identity.sh"
# The scratch defaults suite's emptied plist file stays behind otherwise.
SUITE_PLIST="$HOME/Library/Preferences/com.alwaysconnect.update-install-test.plist"
trap '[ -n "$SERVER" ] && kill $SERVER 2>/dev/null; test_identity_cleanup; defaults delete com.alwaysconnect.update-install-test >/dev/null 2>&1 || true; rm -f "$SUITE_PLIST"; rm -rf "$WORK"' EXIT
FAILS=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }

# Releases are signed with a real certificate (lib-test-identity.sh);
# install.sh is told to expect it, as it expects the real release one.
test_identity_setup "$WORK"
export ALWAYSCONNECT_RELEASE_SIGNER=$TEST_SIGN_SHA1

# A minimal signed App bundle with the right identifier.
cc -x c -o "$WORK/bin" - <<<'int main(void){return 0;}'
make_app() { # dir version min-os [bundle-id] [signing identity, - = ad-hoc]
    local app="$1/AlwaysConnect.app"
    mkdir -p "$app/Contents/MacOS"
    cp "$WORK/bin" "$app/Contents/MacOS/AlwaysConnect"
    cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>${4:-com.alwaysconnect.app}</string>
<key>CFBundleExecutable</key><string>AlwaysConnect</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$2</string>
<key>LSMinimumSystemVersion</key><string>$3</string>
</dict></plist>
EOF
    codesign --force --sign "${5:-$TEST_SIGN_NAME}" "$app" 2>/dev/null
}
WWW="$WORK/www"
mkdir -p "$WWW"
publish() { # version min-os [bundle-id] [bad-sum] [signing identity]
    local d="$WORK/build-$1"
    make_app "$d" "$1" "$2" "${3:-}" "${5:-}"
    for arch in arm64 x86_64; do
        local zip="AlwaysConnect-$1-macos-$arch.zip"
        (cd "$d" && ditto -c -k --keepParent AlwaysConnect.app "$WWW/$zip")
        if [ -n "${4:-}" ]; then
            echo "0000000000000000000000000000000000000000000000000000000000000000  $zip" >"$WWW/$zip.sha256"
        else
            (cd "$WWW" && shasum -a 256 "$zip" >"$zip.sha256")
        fi
    done
}
publish 0.1.0 13.0
publish 0.2.0 13.0
publish 0.3.0-beta.1 13.0
publish 0.4.0 99.0
publish 0.5.0 13.0 com.example.other
publish 0.6.0 13.0 "" bad
publish 0.8.0 13.0 "" "" -

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
BASE="http://127.0.0.1:$PORT"
asset() { # name [url-base]; the size GitHub lists, when the file is here
    local size; size=$(stat -f %z "$WWW/$1" 2>/dev/null || echo 0)
    printf '{"name":"%s","size":%s,"browser_download_url":"%s/%s"}' "$1" "$size" "${2:-$BASE}" "$1"
}
rel() { # tag draft prerelease version [url-base]
    local z="AlwaysConnect-$4-macos-arm64.zip" x="AlwaysConnect-$4-macos-x86_64.zip"
    printf '{"tag_name":"%s","html_url":"https://github.com/o/r/releases/tag/%s","draft":%s,"prerelease":%s,"assets":[%s,%s,%s,%s]}' "$1" "$1" "$2" "$3" \
        "$(asset "$z" "${5:-}")" "$(asset "$z.sha256" "${5:-}")" "$(asset "$x" "${5:-}")" "$(asset "$x.sha256" "${5:-}")"
}
# Newest first, as GitHub lists them; a draft on top is never taken.
echo "[$(rel v9.0.0 true false 0.2.0),$(rel v0.3.0-beta.1 false true 0.3.0-beta.1),$(rel v0.2.0 false false 0.2.0),$(rel v0.1.0 false false 0.1.0),$(rel v0.4.0 false false 0.4.0),$(rel v0.5.0 false false 0.5.0),$(rel v0.6.0 false false 0.6.0),$(rel v0.7.0 false false 0.2.0 https://example.com),$(rel v0.8.0 false false 0.8.0)]" >"$WWW/releases.json"
echo '[{"tag_name":"v1.0.0","draft":false,"prerelease":false,"assets":[]}]' >"$WWW/noassets.json"
echo '{"message":"Not Found","status":"404"}' >"$WWW/notfound.json"
echo '[]' >"$WWW/empty.json"
echo "[$(rel v0.2.0 false false 0.2.0)]" >"$WWW/app-ok.json"
echo "[$(rel v0.6.0 false false 0.6.0)]" >"$WWW/app-bad.json"

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WWW" >"$WORK/server.log" 2>&1 &
SERVER=$!
disown "$SERVER"
for _ in $(seq 1 40); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.25; done

export ALWAYSCONNECT_DOWNLOAD_PREFIX="$BASE/"
# Never open the scratch Apps (the App's own path passes no --no-open).
export ALWAYSCONNECT_INSTALL_NO_OPEN=1
DEST="$WORK/Applications/AlwaysConnect.app"
version_of() { /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$1/Contents/Info.plist" 2>/dev/null || echo none; }
run() { # list-file args... (output in $OUT, status in $ST)
    local list=$1; shift
    set +e
    OUT=$(ALWAYSCONNECT_RELEASES_API="$BASE/$list" /bin/bash "$ROOT/install.sh" --app "$DEST" --no-open "$@" 2>&1 </dev/null)
    ST=$?
    set -e
}

# 1 fresh install: the newest non-draft (a pre-release counts), no quarantine flag
run releases.json
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.3.0-beta.1 ] && codesign --verify --strict "$DEST" 2>/dev/null \
    && ! xattr -r "$DEST" 2>/dev/null | grep -q com.apple.quarantine; then
    pass fresh-install-newest
else fail "fresh-install-newest ($ST) $OUT"; fi

# Downgrades, including stable -> prerelease, need a deliberate override.
run releases.json --version v0.1.0
if [ "$ST" != 0 ] && echo "$OUT" | grep -q "拒绝降级" && [ "$(version_of "$DEST")" = 0.3.0-beta.1 ]; then
    pass downgrade-refused
else fail "downgrade-refused ($ST) $OUT"; fi
make_app "$WORK/stable" 0.3.0 13.0
ditto "$WORK/stable/AlwaysConnect.app" "$DEST"
run releases.json --version v0.3.0-beta.1
if [ "$ST" != 0 ] && echo "$OUT" | grep -q "拒绝降级"; then pass prerelease-downgrade-refused
else fail "prerelease-downgrade-refused ($ST) $OUT"; fi
# A legitimate old binary advertised under a newer tag must be refused.
echo "[$(rel v99.0.0 false false 0.2.0)]" >"$WWW/mismatch.json"
run mismatch.json
if [ "$ST" != 0 ] && echo "$OUT" | grep -q "版本与发布版本不符"; then pass tag-version-mismatch
else fail "tag-version-mismatch ($ST) $OUT"; fi
run releases.json --from "$WORK/stable/AlwaysConnect.app" --expected-version 99.0.0
if [ "$ST" != 0 ] && echo "$OUT" | grep -q "版本与发布版本不符"; then pass from-version-mismatch
else fail "from-version-mismatch ($ST) $OUT"; fi

# 2 a chosen version over the installed one; nothing left beside it
run releases.json --version v0.1.0 --allow-downgrade
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.1.0 ] && [ "$(ls -A "$WORK/Applications")" = AlwaysConnect.app ]; then
    pass allow-downgrade
else fail "allow-downgrade ($ST) $OUT"; fi

# 3 refusals leave the installed copy alone
check_refused() { # name expected-text
    if [ "$ST" != 0 ] && echo "$OUT" | grep -q "$2" && [ "$(version_of "$DEST")" = 0.1.0 ]; then
        pass "$1"
    else fail "$1 ($ST) $OUT"; fi
}
run releases.json --version v0.6.0; check_refused bad-checksum "校验不一致"
run releases.json --version v0.4.0; check_refused too-new-macos "需要 macOS 99.0"
run releases.json --version v0.5.0; check_refused foreign-bundle "不是 AlwaysConnect"
run releases.json --version v0.7.0; check_refused foreign-download "不在 GitHub 上"
run releases.json --version v8.8.8; check_refused unknown-version "找不到版本"
# 3a who signed it (§36.3): an ad-hoc build in a Release is refused; so is
# one with the right certificate when the installed copy has another
run releases.json --version v0.8.0; check_refused adhoc-release "不是用 AlwaysConnect 的发布证书签名"
mkdir -p "$WORK/fresh"
set +e
OUT=$(ALWAYSCONNECT_RELEASE_SIGNER=0123456789abcdef0123456789abcdef01234567 \
    ALWAYSCONNECT_RELEASES_API="$BASE/releases.json" /bin/bash "$ROOT/install.sh" \
    --app "$WORK/fresh/AlwaysConnect.app" --no-open --version v0.2.0 2>&1 </dev/null); ST=$?
set -e
if [ "$ST" != 0 ] && echo "$OUT" | grep -q "发布证书" && [ ! -e "$WORK/fresh/AlwaysConnect.app" ]; then
    pass first-install-wrong-signer
else fail "first-install-wrong-signer ($ST) $OUT"; fi
# the installed copy's certificate wins over the built-in one
set +e
OUT=$(ALWAYSCONNECT_RELEASE_SIGNER=0123456789abcdef0123456789abcdef01234567 \
    ALWAYSCONNECT_RELEASES_API="$BASE/releases.json" /bin/bash "$ROOT/install.sh" \
    --app "$DEST" --no-open --version v0.1.0 2>&1 </dev/null); ST=$?
set -e
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.1.0 ]; then pass update-keeps-installed-signer
else fail "update-keeps-installed-signer ($ST) $OUT"; fi
# https only: a plain-http list is refused by curl itself
set +e
OUT=$(ALWAYSCONNECT_DOWNLOAD_PREFIX=https://github.com/ ALWAYSCONNECT_RELEASES_API="$BASE/releases.json" \
    /bin/bash "$ROOT/install.sh" --app "$DEST" --no-open 2>&1 </dev/null); ST=$?
set -e
check_refused https-only "连不上 GitHub"
run notfound.json; check_refused private-repo "没有返回发布列表"
run empty.json; check_refused no-release "还没有可以下载"
run noassets.json; check_refused no-asset "没有适合本机"
ALWAYSCONNECT_DOWNLOAD_PREFIX="$BASE/" run missing.json; check_refused list-missing "连不上 GitHub"

# 4 the App's path: stage, then install from the stage after its pid is gone
STAGE="$WORK/stage"
run releases.json --version v0.2.0 --stage "$STAGE"
STAGED=$(echo "$OUT" | LC_ALL=C sed -n 's/^STAGED //p')
if [ "$ST" = 0 ] && [ "$STAGED" = "$STAGE/AlwaysConnect.app" ] && [ -f "$STAGE/.alwaysconnect-stage" ] \
    && [ "$(version_of "$DEST")" = 0.1.0 ]; then
    pass stage-only
else fail "stage-only ($ST) $OUT"; fi
# the App's progress line: the file being written and the listed size
DL=$(echo "$OUT" | LC_ALL=C sed -n 's/^DOWNLOAD //p')
if [ "${DL##* }" = "$(stat -f %z "$WWW/AlwaysConnect-0.2.0-macos-arm64.zip")" ] && [ "${DL##* }" -gt 0 ] \
    && case "${DL% *}" in */app.zip) true ;; *) false ;; esac && echo "$OUT" | grep -q "正在校验"; then
    pass stage-progress-line
else fail "stage-progress-line: $DL"; fi
xattr -w com.apple.quarantine "0081;00000000;Safari;" "$STAGED"
sleep 2 & PID=$!
START=$(date +%s)
run releases.json --from "$STAGED" --expected-version 0.2.0 --wait-pid "$PID" --yes
ELAPSED=$(( $(date +%s) - START ))
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.2.0 ] && [ "$ELAPSED" -ge 1 ] && [ ! -e "$STAGE" ] \
    && ! xattr -r "$DEST" 2>/dev/null | grep -q com.apple.quarantine; then
    pass from-stage-after-pid
else fail "from-stage-after-pid ($ST, ${ELAPSED}s) $OUT"; fi

# 5 a broken staged App: refused, installed copy untouched
mkdir -p "$WORK/broken/AlwaysConnect.app/Contents/MacOS"
run releases.json --from "$WORK/broken/AlwaysConnect.app" --expected-version 0.2.0 --yes
if [ "$ST" != 0 ] && [ "$(version_of "$DEST")" = 0.2.0 ]; then pass broken-from; else fail "broken-from ($ST) $OUT"; fi

# 6 the one-liner shape: the script read from stdin, nothing else on it
set +e
OUT=$(ALWAYSCONNECT_RELEASES_API="$BASE/releases.json" /bin/bash -s -- --app "$DEST" --no-open --version v0.1.0 --allow-downgrade <"$ROOT/install.sh" 2>&1)
ST=$?
set -e
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.1.0 ]; then pass piped-script; else fail "piped-script ($ST) $OUT"; fi

# 7 a copy running from the target and no one to ask: refused, not quit.
# (Only without a terminal; with one, install.sh would ask on it. --yes is
# not tried: its quit request goes to the App by bundle identifier, which
# could reach a real AlwaysConnect on this Mac.)
if (exec 3</dev/tty) 2>/dev/null; then
    echo "SKIP running-copy-no-terminal (this shell has a terminal)"
else
    cc -x c -o "$WORK/sleeper" - <<<'#include <unistd.h>
int main(void){sleep(20);return 0;}'
    cp "$WORK/sleeper" "$DEST/Contents/MacOS/AlwaysConnect"
    "$DEST/Contents/MacOS/AlwaysConnect" & RUNNING_PID=$!
    sleep 0.5
    run releases.json --version v0.2.0
    if [ "$ST" != 0 ] && echo "$OUT" | grep -q "没有可交互的终端" && kill -0 "$RUNNING_PID" 2>/dev/null \
        && [ "$(version_of "$DEST")" = 0.1.0 ]; then
        pass running-copy-no-terminal
    else fail "running-copy-no-terminal ($ST) $OUT"; fi
    kill "$RUNNING_PID" 2>/dev/null || true
    wait "$RUNNING_PID" 2>/dev/null || true
fi

# 8 the App's "更新" button: UpdateChecker + the Rust decision + install.sh
(cd "$ROOT/core" && cargo build --release --quiet)
swiftc -O -parse-as-library "$ROOT/Sources/App/UpdateChecker.swift" "$ROOT/Sources/App/AppQuit.swift" "$ROOT/core/scripts/UpdateInstallTest.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/apptest" 2>&1 | grep -v "built for newer" || true
run releases.json --version v0.1.0 --allow-downgrade
set +e
OUT=$("$WORK/apptest" "$BASE/" "$ROOT/install.sh" "$DEST" "$WORK/update.log" fail 2>&1); ST=$?
set -e
echo "$OUT" | grep -E "^(PASS|FAIL)" || true
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.1.0 ] && [ -z "$(ls -A "$HOME/Library/Caches/com.alwaysconnect.app" 2>/dev/null | grep '^update-' || true)" ]; then
    pass app-update-refused-cleanly
else fail "app-update-refused-cleanly ($ST) $OUT"; fi
set +e
OUT=$("$WORK/apptest" "$BASE/" "$ROOT/install.sh" "$DEST" "$WORK/update.log" ok 2>&1); ST=$?
set -e
echo "$OUT" | grep -E "^(PASS|FAIL)" || true
# The detached half finishes after the test process (the "App") is gone.
for _ in $(seq 1 60); do [ "$(version_of "$DEST")" = 0.2.0 ] && break; sleep 0.5; done
sleep 1
if [ "$ST" = 0 ] && [ "$(version_of "$DEST")" = 0.2.0 ] && grep -q "已安装 AlwaysConnect 0.2.0" "$WORK/update.log" \
    && [ -z "$(ls -A "$HOME/Library/Caches/com.alwaysconnect.app" 2>/dev/null | grep '^update-' || true)" ]; then
    pass app-update-installed-after-quit
else fail "app-update-installed-after-quit ($ST) $OUT $(cat "$WORK/update.log" 2>/dev/null)"; fi

# 9 the scratch directory is gone every time
if ls -d "${TMPDIR:-/tmp}"/alwaysconnect-install.* >/dev/null 2>&1; then
    fail "scratch directories left: $(ls -d "${TMPDIR:-/tmp}"/alwaysconnect-install.*)"
else pass no-scratch-left; fi

[ "$FAILS" = 0 ] && echo "install-test: all passed" || { echo "install-test: $FAILS failed"; exit 1; }
