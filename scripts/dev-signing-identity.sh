#!/bin/bash
# One-time local code-signing identity for builds WITHOUT a developer
# team (DESIGN.md §21.15). An ad-hoc signature's designated requirement
# is the binary's cdhash, so every rebuild is a "new program" to the
# keychain and "Always Allow" on the VPN password never sticks. Signed
# with this self-signed certificate, the requirement becomes
# identifier + certificate leaf, which survives rebuilds: allow once,
# then no more prompts.
#
# The certificate has no team identifier (the Helper's team check and
# HelperInstaller behave exactly as for ad-hoc builds) and is not
# marked trusted; codesign does not need it to be. Its private key goes
# into the login keychain, usable by /usr/bin/codesign without asking.
#
# Usage: scripts/dev-signing-identity.sh          create if missing
# Remove: security delete-identity -c "AlwaysConnect Local Dev"
set -euo pipefail

NAME="AlwaysConnect Local Dev"

if security find-identity -p codesigning | grep -q "\"$NAME\""; then
    echo "identity \"$NAME\" already present"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cat >"$TMP/cert.cnf" <<EOF
[req]
distinguished_name=dn
prompt=no
[dn]
CN=$NAME
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
    -config "$TMP/cert.cnf" -extensions ext 2>/dev/null
# The p12 only carries the key into the keychain; its password is
# throwaway. SHA1/3DES: `security import` rejects OpenSSL 3's default
# PBES2 + SHA-256 MAC ("MAC verification failed").
openssl pkcs12 -export -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
    -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
    -out "$TMP/id.p12" -passout pass:import
security import "$TMP/id.p12" -P import -T /usr/bin/codesign
security find-identity -p codesigning | grep "\"$NAME\""
