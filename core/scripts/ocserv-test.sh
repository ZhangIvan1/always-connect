#!/bin/bash
# Local ocserv test gateway for the Rust openconnect auth driver.
# Auth-only: the sandbox bans tun devices, so this server is used to
# prove TLS + password auth + cookie issuance, never a tunnel connect.
# Usage: ocserv-test.sh start|stop|status
# After start, run the tests with proxies cleared:
#   env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
#     AC_TEST_URL=https://127.0.0.1:4443 AC_TEST_CA=/tmp/ocserv-test/ca-cert.pem \
#     AC_TEST_USER=testuser AC_TEST_PASS=testpass \
#     cargo test --features openconnect openconnect
set -e
DIR=/tmp/ocserv-test
PORT=4443
PIDFILE=$DIR/ocserv.pid

start() {
  mkdir -p "$DIR"
  cd "$DIR"
  if [ ! -f ca-cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem \
      -days 365 -nodes -subj "/CN=AlwaysConnect Test CA" 2>/dev/null
    openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr \
      -nodes -subj "/CN=localhost" 2>/dev/null
    printf "subjectAltName=IP:127.0.0.1,DNS:localhost" > server.ext
    openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
      -CAcreateserial -out server-cert.pem -days 365 -extfile server.ext 2>/dev/null
  fi
  if [ ! -f ocpasswd ]; then
    if command -v ocpasswd >/dev/null 2>&1; then
      printf 'testpass\ntestpass\n' | ocpasswd -c "$DIR/ocpasswd" testuser
    else
      # ocpasswd missing (e.g. ocserv package lost to a VM replacement):
      # ocserv plain auth verifies with crypt(3), so a SHA-512 crypt
      # entry is equivalent.
      python3 -c "import crypt; print('testuser:' + crypt.crypt('testpass', crypt.mksalt(crypt.METHOD_SHA512)))" > "$DIR/ocpasswd"
      chmod 600 "$DIR/ocpasswd"
    fi
  fi
  cat > "$DIR/ocserv.conf" <<EOF
auth = "plain[passwd=$DIR/ocpasswd]"
tcp-port = $PORT
udp-port = 0
server-cert = $DIR/server-cert.pem
server-key = $DIR/server-key.pem
ca-cert = $DIR/ca-cert.pem
socket-file = $DIR/ocserv.sock
device = ${OCSERV_DEVICE:-vpns}
ipv4-network = 10.77.0.0/24
EOF
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "ocserv already running (pid $(cat "$PIDFILE"))"
  else
    nohup ocserv -c "$DIR/ocserv.conf" --pid-file "$PIDFILE" >/tmp/ocserv-test/ocserv.log 2>&1 &
    for _ in $(seq 1 20); do
      # Portable readiness probe (ss exists on Linux only; python3 is
      # on both Linux and macOS runners).
      if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null; then
        echo "ocserv up on 127.0.0.1:$PORT (pid $(cat "$PIDFILE" 2>/dev/null))"
        exit 0
      fi
      sleep 0.5
    done
    echo "ocserv did not come up; see $DIR/ocserv.log"
    tail -20 "$DIR/ocserv.log" 2>/dev/null || true
    exit 1
  fi
}

stop() {
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "ocserv stopped"
  else
    echo "ocserv not running"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "running (pid $(cat "$PIDFILE"))"
    else
      echo "not running"
    fi
    ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
