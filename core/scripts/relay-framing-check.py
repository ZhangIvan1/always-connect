#!/usr/bin/env python3
"""End-to-end checks of the App's certificate relay (DESIGN.md §二十三).

Loopback only, test certificates only. Run by scripts/relay-test.sh with
a RelayHarness relay already listening on <relay-port> and forwarding to
<fixture-port>, where this script plays the gateway.

  relay-framing-check.py frames <relay-port> <fixture-port> <dir>
      A fragmented CONNECT goes through, the fixture answers 200, then
      CSTP packets written split and coalesced on both sides must reach
      the other side one TLS record per packet (the PoC's §22.13 bug).
      The fixture also demands the "company" client certificate, so a
      pass proves the relay presented it.
  relay-framing-check.py dtls <relay-port> <fixture-port> <dir>
      The DTLS channel (§26.10): the CONNECT reaching the gateway no
      longer offers PSK-NEGOTIATE (other suites and the master secret
      intact); the gateway's X-DTLS-Port comes back pointing at a local
      UDP port of the relay; datagrams sent there reach the gateway's
      UDP port unchanged and its answers come back, small and full-size.
  relay-framing-check.py access <relay-port> <fixture-port> <dir> <cert-name|none>
      With a fixture gateway answering every request, a client without
      the Helper's relay certificate must get nothing back; the relay
      certificate itself (the positive control) must get the answer.
  relay-framing-check.py presents <relay-port> <fixture-port> <dir> <name>
      One relayed connection; the fixture reads which client
      certificate the relay presented and expects <name> (its CN):
      an expired automatic choice is swapped for the renewal (§45).

<dir> holds ca.pem, gateway.pem/.key (fixture identity) and
relay-client.pem/.key (what the Helper hands openconnect).
"""
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True


def packet(body):
    return b"STF\x01" + len(body).to_bytes(2, "big") + b"\x00\x00" + body


FRAMES = [packet(b"a" * 40), packet(b"b" * 1300), packet(b"c" * 600)]
TOTAL = sum(map(len, FRAMES))


def client_context(d, name):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The relay's listener is a throwaway self-signed identity that
    # openconnect pins; this test client does not need to check it.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if name != "none":
        ctx.load_cert_chain(d / (name + ".pem"), d / (name + ".key"))
    return ctx


def frames(relay_port, fixture_port, d):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "gateway.pem", d / "gateway.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(d / "ca.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", fixture_port))
    listener.listen()
    listener.settimeout(10)
    observed, errors = [], []

    def serve():
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as conn:
                conn.settimeout(10)
                if not conn.getpeercert():
                    raise AssertionError("no client certificate")
                request = b""
                while b"\r\n\r\n" not in request:
                    request += conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
                while sum(map(len, observed)) < TOTAL:
                    part = conn.recv(65536)
                    if not part:
                        raise EOFError("relay closed")
                    observed.append(part)
                combined = b"".join(FRAMES)
                conn.sendall(combined[:5])
                time.sleep(0.05)
                conn.sendall(combined[5:])
                time.sleep(0.3)
        except Exception as error:  # reported below
            errors.append(repr(error))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with client_context(d, "relay-client").wrap_socket(
            socket.create_connection(("127.0.0.1", relay_port), timeout=10),
            server_hostname="localhost") as conn:
        conn.sendall(b"CON")
        conn.sendall(b"NECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: localhost\r\n\r\n")
        header = b""
        while b"\r\n\r\n" not in header:
            header += conn.recv(4096)
        combined = b"".join(FRAMES)
        conn.sendall(combined[:3])
        time.sleep(0.05)
        conn.sendall(combined[3:])
        received = []
        while sum(map(len, received)) < TOTAL:
            part = conn.recv(65536)
            if not part:
                break
            received.append(part)
    thread.join(timeout=5)
    listener.close()
    ok = True
    for name, good in (("fixture saw the company client certificate", not errors),
                       ("openconnect -> gateway: one TLS record per CSTP packet", observed == FRAMES),
                       ("gateway -> openconnect: one TLS record per CSTP packet", received == FRAMES)):
        print(("PASS " if good else "FAIL ") + name)
        ok = ok and good
    if errors:
        print("fixture error: " + "; ".join(errors))
    return ok


def dtls(relay_port, fixture_port, d):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "gateway.pem", d / "gateway.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(d / "ca.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", fixture_port))
    listener.listen()
    listener.settimeout(10)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", fixture_port))
    udp.settimeout(10)
    seen, request_box, errors = [], [], []
    done = threading.Event()

    def serve_tls():
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as conn:
                conn.settimeout(10)
                request = b""
                while b"\r\n\r\n" not in request:
                    request += conn.recv(4096)
                request_box.append(request)
                conn.sendall(b"HTTP/1.1 200 OK\r\nX-CSTP-MTU: 1300\r\nX-DTLS-Port: "
                             + str(fixture_port).encode() + b"\r\nX-DTLS-Session-ID: "
                             + b"ab" * 32 + b"\r\n\r\n")
                done.wait(15)
        except Exception as error:
            errors.append(repr(error))

    def serve_udp():
        try:
            while not done.is_set():
                data, peer = udp.recvfrom(65535)
                seen.append(data)
                udp.sendto(b"echo:" + data, peer)
        except Exception:
            pass

    threading.Thread(target=serve_tls, daemon=True).start()
    threading.Thread(target=serve_udp, daemon=True).start()
    local_port, echoes = None, []
    sent = [b"hello", bytes(range(256)) * 5 + b"x" * 120]
    try:
        with client_context(d, "relay-client").wrap_socket(
                socket.create_connection(("127.0.0.1", relay_port), timeout=10),
                server_hostname="localhost") as conn:
            conn.sendall(b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: localhost\r\n"
                         b"X-DTLS-Master-Secret: " + b"00" * 48 + b"\r\n"
                         b"X-DTLS-CipherSuite: PSK-NEGOTIATE:OC-DTLS1_2-AES256-GCM:AES128-SHA\r\n"
                         b"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n\r\n")
            header = b""
            while b"\r\n\r\n" not in header:
                header += conn.recv(4096)
            for line in header.split(b"\r\n"):
                if line.lower().startswith(b"x-dtls-port:"):
                    local_port = int(line.split(b":", 1)[1])
            if local_port:
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.settimeout(3)
                for payload in sent:
                    client.sendto(payload, ("127.0.0.1", local_port))
                    try:
                        echoes.append(client.recvfrom(65535)[0])
                    except socket.timeout:
                        echoes.append(None)
                client.close()
    finally:
        done.set()
        time.sleep(0.2)
        listener.close()
        udp.close()
    request = request_box[0] if request_box else b""
    ok = True
    for label, good in (
            ("CONNECT reaches the gateway without PSK-NEGOTIATE, other suites intact",
             b"X-DTLS-CipherSuite: OC-DTLS1_2-AES256-GCM:AES128-SHA\r\n" in request
             and b"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384\r\n" in request
             and b"X-DTLS-Master-Secret: " + b"00" * 48 in request
             and b"PSK-NEGOTIATE" not in request),
            ("X-DTLS-Port is rewritten to a local relay port",
             local_port is not None and local_port != fixture_port),
            ("datagrams reach the gateway's DTLS port unchanged", seen == sent),
            ("the gateway's datagrams come back, small and full-size",
             echoes == [b"echo:" + p for p in sent])):
        print(("PASS " if good else "FAIL ") + label)
        ok = ok and good
    if errors:
        print("fixture error: " + "; ".join(errors))
    return ok


def access(relay_port, fixture_port, d, name):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "gateway.pem", d / "gateway.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(d / "ca.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", fixture_port))
    listener.listen()
    listener.settimeout(8)

    def serve():
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as conn:
                conn.settimeout(8)
                request = b""
                while b"\r\n\r\n" not in request:
                    request += conn.recv(4096)
                conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                time.sleep(0.3)
        except Exception:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with client_context(d, name).wrap_socket(
                socket.create_connection(("127.0.0.1", relay_port), timeout=8),
                server_hostname="localhost") as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            answered = conn.recv(4096).startswith(b"HTTP/1.1 204")
    except (ssl.SSLError, ConnectionError, OSError):
        answered = False
    thread.join(timeout=3)
    listener.close()
    if name == "relay-client":
        good, label = answered, "relay passes the Helper's own certificate through (control)"
    else:
        good = not answered
        label = "relay refuses " + ("no client certificate" if name == "none"
                                    else "a certificate other than the relay's (" + name + ")")
    print(("PASS " if good else "FAIL ") + label)
    return good


def presents(relay_port, fixture_port, d, expected):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "gateway.pem", d / "gateway.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(d / "ca.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", fixture_port))
    listener.listen()
    listener.settimeout(8)
    seen = []

    def serve():
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as conn:
                conn.settimeout(8)
                subject = dict(item[0] for item in conn.getpeercert().get("subject", ()))
                seen.append(subject.get("commonName", ""))
                request = b""
                while b"\r\n\r\n" not in request:
                    request += conn.recv(4096)
                conn.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                time.sleep(0.3)
        except Exception:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with client_context(d, "relay-client").wrap_socket(
                socket.create_connection(("127.0.0.1", relay_port), timeout=8),
                server_hostname="localhost") as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            conn.recv(4096)
    except (ssl.SSLError, ConnectionError, OSError):
        pass
    thread.join(timeout=3)
    listener.close()
    got = seen[0] if seen else "nothing"
    good = got == expected
    print(("PASS " if good else "FAIL ") + "relay presented the " + expected
          + " certificate" + ("" if good else " (got " + got + ")"))
    return good


def main():
    mode = sys.argv[1]
    if mode == "frames":
        ok = frames(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]))
    elif mode == "dtls":
        ok = dtls(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]))
    elif mode == "access":
        ok = access(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]), sys.argv[5])
    elif mode == "presents":
        ok = presents(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]), sys.argv[5])
    else:
        sys.exit(2)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
