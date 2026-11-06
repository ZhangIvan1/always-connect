# Sourced by harnesses that need code signed with a certificate
# (DESIGN.md §36.3). Not a program.
#
#   test_identity_setup <scratch-dir>   sets TEST_SIGN_NAME and
#                                       TEST_SIGN_SHA1 (leaf, lowercase)
#   test_identity_cleanup               undo; call it from the EXIT trap
#
# Uses the local "AlwaysConnect Local Dev" identity when this Mac has
# it (scripts/dev-signing-identity.sh). Otherwise (CI, or
# AC_FORCE_TEMP_IDENTITY=1) a throwaway identity goes into a temporary
# keychain that is put on the user search list for the run and taken
# off again: codesign only finds identities on the search list. The
# login keychain is never written.

TEST_KEYCHAIN="" TEST_ORIG_KEYCHAINS=""

test_identity_setup() {
    local work=$1
    TEST_SIGN_NAME="AlwaysConnect Local Dev"
    if [ -z "${AC_FORCE_TEMP_IDENTITY:-}" ] &&
        security find-identity -p codesigning | grep -q "\"$TEST_SIGN_NAME\""; then
        TEST_SIGN_SHA1=$(security find-certificate -c "$TEST_SIGN_NAME" -Z | awk '/SHA-1/{print tolower($3); exit}')
        return 0
    fi
    TEST_SIGN_NAME="AC Test Signer"
    TEST_KEYCHAIN="$work/test-signing.keychain-db"
    TEST_ORIG_KEYCHAINS=$(security list-keychains -d user | sed -e 's/^ *"//' -e 's/"$//')
    security create-keychain -p test "$TEST_KEYCHAIN"
    security unlock-keychain -p test "$TEST_KEYCHAIN"
    security set-keychain-settings "$TEST_KEYCHAIN"   # no auto-lock during the run
    local IFS=$'\n'
    # shellcheck disable=SC2086
    security list-keychains -d user -s $TEST_ORIG_KEYCHAINS "$TEST_KEYCHAIN"
    unset IFS
    cat >"$work/test-signing.cnf" <<CNF
[req]
distinguished_name=dn
prompt=no
[dn]
CN=$TEST_SIGN_NAME
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
CNF
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$work/test-signing.key" \
        -out "$work/test-signing.pem" -config "$work/test-signing.cnf" -extensions ext 2>/dev/null
    openssl pkcs12 -export -inkey "$work/test-signing.key" -in "$work/test-signing.pem" \
        -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
        -out "$work/test-signing.p12" -passout pass:t
    security import "$work/test-signing.p12" -k "$TEST_KEYCHAIN" -P t -T /usr/bin/codesign >/dev/null
    security set-key-partition-list -S apple-tool:,apple: -s -k test "$TEST_KEYCHAIN" >/dev/null 2>&1 || true
    TEST_SIGN_SHA1=$(openssl x509 -in "$work/test-signing.pem" -noout -fingerprint -sha1 \
        | sed -e 's/.*=//' -e 's/://g' | tr 'A-F' 'a-f')
}

test_identity_cleanup() {
    [ -n "$TEST_KEYCHAIN" ] || return 0
    if [ -n "$TEST_ORIG_KEYCHAINS" ]; then
        local IFS=$'\n'
        # shellcheck disable=SC2086
        security list-keychains -d user -s $TEST_ORIG_KEYCHAINS 2>/dev/null || true
        unset IFS
    fi
    security delete-keychain "$TEST_KEYCHAIN" 2>/dev/null || true
    TEST_KEYCHAIN=""
}
