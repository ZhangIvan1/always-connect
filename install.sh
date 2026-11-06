#!/bin/bash
# Install or update AlwaysConnect from GitHub Releases (DESIGN.md §三十五):
#
#   curl -fsSL https://raw.githubusercontent.com/weiazm/AlwaysConnect/main/install.sh | bash
#
# Why a script: the builds carry no Apple developer signature and are
# not notarized, so a zip downloaded by a browser is quarantined and
# Gatekeeper refuses to open it. curl sets no quarantine flag; this
# script downloads the newest Release (pre-releases included, drafts
# never, as the App's update check), checks its .sha256, quits a running
# copy the normal way (quit = VPN off, DESIGN.md §21.5; never killed: a
# killed App holds the network for up to two minutes, §25.2), replaces
# it, clears any quarantine flag and opens it. Any failure after the old
# copy was moved aside puts it back.
#
# Who signed it (DESIGN.md §36.3): the new App must be signed with the
# same certificate as the copy it replaces, or, on a first install,
# with the release certificate below. A Release published from a stolen
# GitHub account but signed with any other key is refused. A fork sets
# its own RELEASE_SIGNER (or ALWAYSCONNECT_RELEASE_SIGNER).
#
# Options (pass them through the pipe with `| bash -s -- --version v0.2.0`):
#   --version TAG   that Release instead of the newest
#   --app PATH      install to PATH (default /Applications/AlwaysConnect.app)
#   --yes           do not ask before quitting a running copy
#   --no-open       do not open the App afterwards
# Used by the App's own "更新" button (Sources/App/UpdateChecker.swift):
#   --stage DIR     download and check only; print "STAGED <app>" and stop
#   --from APP      install this already checked App instead of downloading
#   --wait-pid PID  wait for that process (the App quitting itself) to end
#                   instead of asking the App to quit
#
# Needs only what every Mac has (bash, curl, ditto, shasum, codesign,
# osascript). Writes nothing but the App itself and a scratch directory
# it removes. ALWAYSCONNECT_RELEASES_API is the App's own releases list
# (Info.plist, so a fork updates from the fork) or the harness's;
# ALWAYSCONNECT_DOWNLOAD_PREFIX and ALWAYSCONNECT_INSTALL_NO_OPEN exist
# for scripts/install-test.sh only. Downloads are https only, redirects
# included (the harness's loopback http server excepted).
# The whole script is one block, so bash has read all of it before
# running any of it: with `curl … | bash` the script arrives on stdin,
# and a command that reads stdin must not swallow the rest.
{
set -euo pipefail

API=${ALWAYSCONNECT_RELEASES_API:-https://api.github.com/repos/weiazm/AlwaysConnect/releases?per_page=20}
DOWNLOAD_PREFIX=${ALWAYSCONNECT_DOWNLOAD_PREFIX:-https://github.com/}
BUNDLE_ID=com.alwaysconnect.app
# SHA-1 of the leaf certificate every release is signed with: the
# self-signed "AlwaysConnect Local Dev" identity (DESIGN.md §35.5).
RELEASE_SIGNER=${ALWAYSCONNECT_RELEASE_SIGNER:-a357e463d6135ef45eff7b00d3d59feb3c99c33e}
case "$DOWNLOAD_PREFIX" in
    http://127.0.0.1:*/) PROTO="=http,https" ;;   # scripts/install-test.sh
    *) PROTO="=https" ;;
esac
DEST=/Applications/AlwaysConnect.app
TAG="" YES=0 OPEN=${ALWAYSCONNECT_INSTALL_NO_OPEN:+0} STAGE="" FROM="" WAIT_PID=""
OPEN=${OPEN:-1}

say() { printf '%s\n' "$*"; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) TAG=${2:?}; shift 2 ;;
        --app) DEST=${2:?}; shift 2 ;;
        --yes) YES=1; shift ;;
        --no-open) OPEN=0; shift ;;
        --stage) STAGE=${2:?}; shift 2 ;;
        --from) FROM=${2:?}; shift 2 ;;
        --wait-pid) WAIT_PID=${2:?}; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0" 2>/dev/null || true; exit 0 ;;  # before the trap below
        *) die "不认识的参数 $1" ;;
    esac
done
case "$DEST" in
    /*.app) ;;
    *) die "--app 要写完整路径，以 .app 结尾：$DEST" ;;
esac
[ "$(uname -s)" = Darwin ] || die "AlwaysConnect 只支持 macOS"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/alwaysconnect-install.XXXXXX")
SUDO=""
OLD=""          # where the previous copy waits until the new one is in
RUNNING=0       # a copy was running and has been quit by us
DONE=0
cleanup() {
    local status=$?
    # bash 3.2 reports an unbound-variable abort as status 0 here: only a
    # run that reached the end counts as a success.
    [ "$DONE" = 1 ] || [ "$status" != 0 ] || status=1
    # Interrupted or failed after the old copy was moved aside: put it
    # back rather than leave no App at all.
    if [ -n "$OLD" ] && [ -e "$OLD" ] && [ ! -e "$DEST" ]; then
        $SUDO mv "$OLD" "$DEST" 2>/dev/null && say "已恢复原来的版本"
    fi
    # We quit it and did not finish: open the old one again.
    if [ "$status" != 0 ] && [ "$RUNNING" = 1 ] && [ "$OPEN" = 1 ] && [ -e "$DEST" ]; then
        open "$DEST" 2>/dev/null || true
    fi
    $SUDO rm -rf "$WORK" 2>/dev/null || rm -rf "$WORK" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null || true; }

# "13.0" <= "15.1"? Dotted numbers, missing parts count as 0.
version_le() {
    local IFS=.
    local -a a=($1) b=($2)
    local i x y
    for i in 0 1 2; do
        x=${a[i]:-0}; y=${b[i]:-0}
        x=${x//[^0-9]/}; y=${y//[^0-9]/}
        x=${x:-0}; y=${y:-0}
        [ "$((10#$x))" -lt "$((10#$y))" ] && return 0
        [ "$((10#$x))" -gt "$((10#$y))" ] && return 1
    done
    return 0
}

arch() {
    # Under Rosetta uname says x86_64 on Apple silicon; the hardware decides.
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then echo arm64; else uname -m; fi
}

fetch() { # url file
    curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" --connect-timeout 15 --max-time 900 --retry 2 \
        -H "User-Agent: AlwaysConnect-install" "$1" -o "$2"
}

# Pick the Release and its two assets from GitHub's list (newest first).
# JavaScript for Automation reads the JSON: present on every Mac, unlike
# python3 or jq.
pick_release() { # list.json tag arch -> "tag<TAB>zip-url<TAB>sha-url" or "ERR <why>"
    cat >"$WORK/pick.js" <<'JS'
ObjC.import('Foundation');
function run(argv) {
    var text = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, $()).js;
    var list;
    try { list = JSON.parse(text); } catch (e) { return 'ERR notjson'; }
    if (!Array.isArray(list)) return 'ERR notlist';
    var want = argv[1], arch = argv[2], seen = false;
    for (var i = 0; i < list.length; i++) {
        var r = list[i];
        if (!r || r.draft || typeof r.tag_name !== 'string') continue;
        if (want && r.tag_name !== want) continue;
        seen = true;
        var assets = r.assets || [], zip = null, sha = null;
        for (var j = 0; j < assets.length; j++) {
            if (/^AlwaysConnect-.*-macos-/.test(assets[j].name) && assets[j].name.endsWith('-macos-' + arch + '.zip')) zip = assets[j];
        }
        if (zip) {
            for (var k = 0; k < assets.length; k++) {
                if (assets[k].name === zip.name + '.sha256') sha = assets[k];
            }
        }
        if (zip && sha) return r.tag_name + '\t' + zip.browser_download_url + '\t' + sha.browser_download_url;
        if (want) return 'ERR noasset';
    }
    return seen ? 'ERR noasset' : (want ? 'ERR notag' : 'ERR none');
}
JS
    osascript -l JavaScript "$WORK/pick.js" "$1" "$2" "$3" 2>/dev/null || echo "ERR notjson"
}

download_and_check() { # -> sets NEW to the checked App in $WORK
    local a list picked tag zip_url sha_url expected actual
    a=$(arch)
    say "正在查找 AlwaysConnect 的最新发布…"
    fetch "$API" "$WORK/releases.json" || die "连不上 GitHub，请检查网络后再试"
    picked=$(pick_release "$WORK/releases.json" "$TAG" "$a")
    case "$picked" in
        "ERR notlist"|"ERR notjson") die "GitHub 没有返回发布列表（仓库不可访问或访问次数受限），过一会儿再试" ;;
        "ERR none") die "还没有可以下载的发布版本" ;;
        "ERR notag") die "找不到版本 $TAG" ;;
        "ERR noasset") die "这个发布里没有适合本机（${a}）的安装包" ;;
        ERR*) die "读不懂发布列表" ;;
    esac
    IFS=$'\t' read -r tag zip_url sha_url <<<"$picked"
    for url in "$zip_url" "$sha_url"; do
        case "$url" in
            "$DOWNLOAD_PREFIX"*) ;;
            *) die "下载地址不在 GitHub 上，已拒绝：$url" ;;
        esac
    done
    say "正在下载 ${tag}…"
    fetch "$zip_url" "$WORK/app.zip" || die "下载失败，请检查网络后再试"
    fetch "$sha_url" "$WORK/app.zip.sha256" || die "下载校验文件失败"
    expected=$(awk '{print tolower($1); exit}' "$WORK/app.zip.sha256")
    actual=$(shasum -a 256 "$WORK/app.zip" | awk '{print $1}')
    [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "安装包校验不一致（下载不完整或被改过），已停止"
    mkdir -p "$WORK/x"
    ditto -x -k "$WORK/app.zip" "$WORK/x" || die "解压失败"
    NEW="$WORK/x/AlwaysConnect.app"
    check_app "$NEW"
}

# SHA-1 of an App's leaf signing certificate, lowercase; empty when it
# has none (ad-hoc or unsigned).
leaf_sha1() { # app
    local dir
    dir=$(mktemp -d "$WORK/cert.XXXXXX")
    codesign -d --extract-certificates="$dir/c" "$1" >/dev/null 2>&1 || true
    if [ -s "$dir/c0" ]; then shasum -a 1 "$dir/c0" | awk '{print tolower($1)}'; fi
    rm -rf "$dir"
}

# The certificate the new App must carry: the installed copy's, when it
# has one (an update keeps its signer; a fork's users stay on the fork),
# else the release certificate.
expected_signer() {
    local installed=""
    [ -d "$DEST/Contents/MacOS" ] && installed=$(leaf_sha1 "$DEST")
    echo "${installed:-$RELEASE_SIGNER}"
}

check_app() { # app
    local app=$1 id min os signer
    [ -d "$app/Contents/MacOS" ] || die "安装包里没有 AlwaysConnect.app"
    id=$(plist "$app" CFBundleIdentifier)
    [ "$id" = "$BUNDLE_ID" ] || die "安装包里的不是 AlwaysConnect（${id}）"
    codesign --verify --strict "$app" 2>/dev/null || die "安装包的签名校验不通过，已停止"
    signer=$(expected_signer)
    codesign --verify --strict \
        -R="identifier \"$BUNDLE_ID\" and certificate leaf = H\"$signer\"" "$app" 2>/dev/null \
        || die "安装包不是用 AlwaysConnect 的发布证书签名的（可能被替换过），已停止"
    min=$(plist "$app" LSMinimumSystemVersion)
    os=$(sw_vers -productVersion)
    if [ -n "$min" ] && ! version_le "$min" "$os"; then
        die "这个版本需要 macOS $min 或更新，本机是 $os"
    fi
}

# Processes of the copy at DEST (the menu-bar App and its settings
# window share the executable).
running_pids() { pgrep -f "^$DEST/Contents/MacOS/AlwaysConnect( |$)" 2>/dev/null || true; }

quit_running() {
    if [ -n "$WAIT_PID" ]; then
        # The App started us and is quitting itself.
        for _ in $(seq 1 120); do kill -0 "$WAIT_PID" 2>/dev/null || break; sleep 0.5; done
        kill -0 "$WAIT_PID" 2>/dev/null && die "AlwaysConnect 一分钟内没有退出，未更新"
        RUNNING=1
    fi
    [ -n "$(running_pids)" ] || return 0
    if [ "$YES" != 1 ]; then
        say "AlwaysConnect 正在运行。更新会先退出它：VPN 会断开，新版打开后自动重新连接（可能要在手机上再确认一次登录）。"
        if ! { exec 3</dev/tty; } 2>/dev/null; then
            die "没有可交互的终端：请先在菜单栏面板里点「退出」，或加 --yes 再运行"
        fi
        local answer=""
        printf '继续吗？[y/N] '
        read -r answer <&3 || true
        exec 3<&-
        case "$answer" in y|Y|yes|YES) ;; *) die "已取消，什么都没改" ;; esac
    fi
    say "正在退出 AlwaysConnect…"
    # The normal quit (VPN off, network back to direct). The settings
    # window is a second process of the same App and may take the first
    # quit request, so ask again until none is left. Never kill it.
    for _ in $(seq 1 30); do
        [ -n "$(running_pids)" ] || break
        osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
        sleep 2
    done
    [ -z "$(running_pids)" ] || die "AlwaysConnect 一分钟内没有退出。请在菜单栏面板里点「退出」后再运行一次"
    RUNNING=1
}

replace() { # new-app
    local new=$1 parent
    parent=$(dirname "$DEST")
    mkdir -p "$parent" 2>/dev/null || true
    if [ ! -w "$parent" ] || { [ -e "$DEST" ] && [ ! -w "$DEST" ]; }; then
        say "需要管理员权限才能写入 ${parent}，请输入电脑开机密码："
        SUDO=sudo
        sudo -v || die "没有拿到管理员权限，未更新"
    fi
    if [ -e "$DEST" ]; then
        OLD="$WORK/previous.app"
        $SUDO mv "$DEST" "$OLD" || die "无法移走旧版本"
    fi
    if ! $SUDO ditto "$new" "$DEST"; then
        $SUDO rm -rf "$DEST" || true
        die "复制新版本失败，已恢复原来的版本"
    fi
    # Downloads by curl carry no quarantine flag; clear one anyway (a zip
    # opened in Finder first, a copy made by a browser).
    $SUDO xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true
    if ! codesign --verify --strict "$DEST" 2>/dev/null; then
        $SUDO rm -rf "$DEST" || true
        die "新版本复制后校验不通过，已恢复原来的版本"
    fi
    [ -n "$OLD" ] && $SUDO rm -rf "$OLD"
    OLD=""
}

if [ -n "$FROM" ]; then
    check_app "$FROM"
    NEW=$FROM
else
    download_and_check
fi

if [ -n "$STAGE" ]; then
    mkdir -p "$STAGE"
    rm -rf "$STAGE/AlwaysConnect.app"
    ditto "$NEW" "$STAGE/AlwaysConnect.app"
    touch "$STAGE/.alwaysconnect-stage"
    say "STAGED $STAGE/AlwaysConnect.app"
    DONE=1
    exit 0
fi

quit_running
replace "$NEW"
VERSION=$(plist "$DEST" CFBundleShortVersionString)
say "已安装 AlwaysConnect $VERSION 到 $DEST"
if [ -n "$FROM" ] && [ -f "$(dirname "$FROM")/.alwaysconnect-stage" ]; then
    rm -rf "$(dirname "$FROM")"   # the App's own staging directory
fi
if [ "$OPEN" = 1 ]; then
    open "$DEST" || say "请在「应用程序」里打开 AlwaysConnect"
fi
DONE=1
exit 0
}
