#!/bin/bash
# CLI behavior contract test for the Helper classifier (DESIGN.md §16.3.1).
# Asserts only the tun-independent behaviors: form-stage auth rejection
# and cookie rejection. The correct-password case is deliberately NOT
# asserted here: after a successful auth it needs a tun device, which
# sandboxes and some CI runners deny (the server then answers 401
# "Cookie is not acceptable" for a tun failure, not an auth failure —
# see the DESIGN note; asserting exit codes there would bake in a lie).
# Usage: cli-behavior-test.sh  (gateway must already be running, see
# ocserv-test.sh; this script does not start or stop it)
set -u
export -n http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
URL="${AC_TEST_URL:-https://127.0.0.1:4443}"
CA="${AC_TEST_CA:-/tmp/ocserv-test/ca-cert.pem}"
USER="${AC_TEST_USER:-testuser}"
FAIL=0

check() { # name, expected_exit, stderr_grep, command...
  local name="$1" want_exit="$2" want_grep="$3"; shift 3
  local err
  err="$(mktemp)"
  set +e
  "$@" >/dev/null 2>"$err"
  local got_exit=$?
  set -e
  if [ "$got_exit" != "$want_exit" ]; then
    echo "FAIL $name: exit=$got_exit, want=$want_exit"; FAIL=1
  elif ! grep -q "$want_grep" "$err"; then
    echo "FAIL $name: stderr lacks [$want_grep]"; FAIL=1
  else
    echo "ok $name (exit=$got_exit)"
  fi
  rm -f "$err"
}

check "wrong-password" 1 "Login failed." \
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  timeout 30 openconnect --server="$URL" --user="$USER" \
    --cafile="$CA" --passwd-on-stdin --script=/bin/true \
    <<< "definitely-wrong-password"

check "bogus-cookie" 1 "VPN service unavailable" \
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  timeout 30 openconnect --server="$URL" \
    --cafile="$CA" --cookie-on-stdin --script=/bin/true \
    <<< "boguscookievalue"

exit "$FAIL"
