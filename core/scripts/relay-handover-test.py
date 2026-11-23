#!/usr/bin/env python3
"""Production App redirect methods -> HelperSession -> real relay -> OpenConnect.

UI/keychain selection, DNS and XPC transport are fixture adapters; all policy,
process replacement, loopback TLS, response parsing and destination auth are
production code. TestSeam substitutes PF/routes. No App installation occurs.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


def bootstrap_cli(arguments):
    options = dict(arg[2:].split("=", 1) for arg in arguments if arg.startswith("--") and "=" in arg)
    server = urlsplit(options["server"])
    if server.hostname != "localhost":
        # No password read here: the real destination CLI inherits its stdin.
        os.execv(os.environ["FIXTURE_OPENCONNECT"], [os.environ["FIXTURE_OPENCONNECT"], *arguments])
    sys.stdin.readline()  # provided by engine, never sent in the early GET
    assert options["resolve"] == "localhost:127.0.0.1" and server.port == 4473
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Verify the production engine's SPKI pin below.
    ctx.load_cert_chain(options["certificate"], options["sslkey"])
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 4473), timeout=8),
                         server_hostname="localhost") as peer:
        certificate = peer.getpeercert(binary_form=True)
        public = subprocess.run(["/usr/bin/openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
                                input=certificate, capture_output=True, check=True).stdout
        spki = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
                              input=public, capture_output=True, check=True).stdout
        pin = "pin-sha256:" + base64.b64encode(hashlib.sha256(spki).digest()).decode()
        assert pin == options["servercert"], "initial listener pin mismatch"
        peer.sendall(b"GET / HTTP/1.1\r\nHost: localhost:4473\r\n\r\n")
        try:
            received = peer.recv(4096)
        except (ssl.SSLError, ConnectionError, OSError):
            received = b""
        if received:
            Path(os.environ["ALWAYSCONNECT_TEST_ROOT"], "location-leaked").touch()
            raise AssertionError("cross-node response reached the initial CLI")
    # Stay alive until production HelperSession stops this engine. Otherwise an
    # early EOF can start another attempt before the App handles the callback.
    time.sleep(60)
    return 1


def extract_methods(root):
    source = (root / "Sources/App/HelperClient.swift").read_text()
    start = source.index("    private func failRelayHandover(")
    end = source.index("    /// The relay's gateway address", start)
    methods = source[start:end]
    assert all(methods.count("private func " + name + "(") == 1
               for name in ("failRelayHandover", "beginRelayHandover", "handleRelayRedirect"))
    start = source.index("    private func takeRelay(")
    end = source.index("    /// Switch between Cisco", start)
    methods += source[start:end]
    start = source.index("    private func resumeOwnSessionIfOrphaned(")
    end = source.index("    /// Launch:", start)
    methods += source[start:end]
    assert "armRelayDeadline(session: sessionId)" in source
    assert "armRelayDeadline(session: context.session)" in methods
    return methods


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pki", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    pki = args.pki.resolve()
    cli = os.environ.get("ALWAYSCONNECT_TEST_OPENCONNECT") or shutil.which("openconnect")
    if not cli:
        raise RuntimeError("real destination OpenConnect is required")
    with tempfile.TemporaryDirectory(prefix="ac-handover-") as temporary:
        work = Path(temporary)
        fixture = (root / "core/scripts/RelayHandoverAppFixture.swift").read_text()
        assert fixture.count("// PRODUCTION_HANDOVER_METHODS") == 1
        (work / "Fixture.swift").write_text(fixture.replace("// PRODUCTION_HANDOVER_METHODS", extract_methods(root)))
        relay = (root / "Sources/App/CertificateRelay.swift").read_text()
        # Helper/PfAnchor.swift already declares this same C function. No
        # production method is changed by the extraction.
        declaration = '@_silgen_name("ac_string_free")\nfunc ac_string_free(_ s: UnsafeMutablePointer<CChar>?)'
        assert relay.count(declaration) == 1
        (work / "CertificateRelay.swift").write_text(relay.replace(declaration, ""))
        sources = sorted((root / "Sources/Helper").glob("*.swift"))
        sources = [s for s in sources if s.name != "HelperMain.swift"]
        sources += sorted((root / "Sources/Shared").glob("*.swift"))
        subprocess.run(["swiftc", "-O", "-parse-as-library", "-module-name", "RelayHandoverFixture",
                        *map(str, sources), str(work / "CertificateRelay.swift"), str(work / "Fixture.swift"),
                        str(root / "core/target/release/libalwaysconnect_core.a"), "-o", str(work / "fixture")],
                       check=True)
        (work / "openconnect").write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I "
                                           + shlex.quote(str(Path(__file__).resolve())) + ' --as-cli "$@"\n')
        (work / "openconnect").chmod(0o700)
        (work / "pfctl").write_text("""#!/bin/sh
D=$(dirname "$0")
printf '%s\n' "$*" >> "$D/pfctl.log"
case "$*" in
  "-E") echo 'Token : 10042' >&2;;
  *" -f -"*) cat >/dev/null;;
esac
exit 0
""")
        (work / "pfctl").chmod(0o700)
        environment = dict(os.environ, ALWAYSCONNECT_TEST_ROOT=str(work),
                           ALWAYSCONNECT_NO_ROUTES="1", FIXTURE_OPENCONNECT=str(Path(cli).resolve()),
                           ALWAYSCONNECT_RELAY_LOG=str(work / "relay.log"))
        ready = threading.Event()
        errors = []
        stop = threading.Event()
        seen = []

        def entry():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(pki / "gateway.pem", pki / "gateway.key")
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(pki / "ca.pem")
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 4474))
                listener.listen()
                listener.settimeout(1)
                ready.set()
                while not stop.is_set():
                    try:
                        raw, _ = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        with ctx.wrap_socket(raw, server_side=True) as peer:
                            peer.settimeout(5)
                            request = b""
                            while b"\r\n\r\n" not in request:
                                part = peer.recv(4096)
                                if not part:
                                    raise EOFError("entry closed before its request")
                                request += part
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            assert b"testpass" not in request and b"Cookie:" not in request
                            seen.append(peer.getpeercert())
                            response = b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:4473/\r\nContent-Length: 0\r\n\r\n"
                            for index in range(0, len(response), 7):
                                peer.sendall(response[index:index + 7])
                                time.sleep(0.003)
                    except Exception as error:
                        errors.append(repr(error))

        thread = threading.Thread(target=entry, daemon=True)
        thread.start()
        assert ready.wait(5), "mock entry did not start"
        with (work / "destination.log").open("w+") as output:
            gateway = subprocess.Popen([sys.executable, "-I", str(root / "core/scripts/mock-anyconnect.py"),
                                        "4476", str(pki / "gateway.pem"), str(pki / "gateway.key"),
                                        str(pki / "ca.pem"), "--require-client-cert"], stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", 4476), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.03)
                results = []
                for scenario in ("success", "dns-stall", "prepare-stall"):
                    case_root = work / scenario
                    case_root.mkdir()
                    for tool in ("openconnect", "pfctl"):
                        shutil.copy2(work / tool, case_root / tool)
                    case_env = dict(environment, ALWAYSCONNECT_TEST_ROOT=str(case_root),
                                    ALWAYSCONNECT_RELAY_LOG=str(case_root / "relay.log"),
                                    FIXTURE_SCENARIO=scenario)
                    results.append(subprocess.run([str(work / "fixture"), str(pki)], env=case_env, timeout=55))
                    assert not (case_root / "location-leaked").exists(), "Location escaped to the initial CLI"
            finally:
                gateway.terminate()
                gateway.wait(timeout=5)
                stop.set()
                thread.join(timeout=3)
            output.seek(0)
            destination = output.read()
        assert all(result.returncode == 0 for result in results), "production handover/deadline chain failed"
        assert len(seen) == 3 and not errors, ("initial node connection count/errors", len(seen), errors)
        assert "MOCK client certificate verified" in destination and "MOCK POST /auth" in destination
        print("PASS fragmented 302 -> production App/Helper handover -> same-port relay -> destination certificate authentication")
        return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--as-cli"]:
        raise SystemExit(bootstrap_cli(sys.argv[2:]))
    raise SystemExit(main())
