#!/usr/bin/env bash
#
# This script tests `openssl-xaes' on an empty file and NUL password.
#
: ${CAT_CMD:='/bin/cat'}
: ${CMP_CMD:='/usr/bin/cmp'}
: ${OPENSSL_XAES_CMD:="${top_srcdir}/openssl-xaes"}
: ${RM_CMD:='/bin/rm'}
: ${SCRIPT_CMD:='/usr/bin/script'}

if ! command -v $OPENSSL_XAES_CMD &>/dev/null; then
    echo 'openssl-xaes: Command not found.' >&2
    exit 1
elif ! command -v $SCRIPT_CMD &>/dev/null; then
    echo 'script: Command not found.' >&2
    exit 1
fi

echo 'Encrypting empty file with NUL password.' >&2
$CAT_CMD /dev/null >o.tmp
$SCRIPT_CMD -qc "$OPENSSL_XAES_CMD -e <o.tmp >o.enc.tmp 2>/dev/null" /dev/null <<<'' >/dev/null
$SCRIPT_CMD -qc "$OPENSSL_XAES_CMD -d <o.enc.tmp >o2.tmp 2>/dev/null" /dev/null <<<'' >/dev/null
$SCRIPT_CMD -qc "OPENSSL_XAES_CMD -e <o.tmp >o2.enc.tmp 2>/dev/null" /dev/null <<<'' >/dev/null

if test -s o.enc.tmp -a -f o2.tmp -a ! -s o2.tmp ; then
    echo 'PASS: Empty file encrypted and decrypted successfully.' >&2
else
    echo 'FAIL: Empty file encryption/decryption failed.' >&2
fi

if ! $CMP_CMD o.enc.tmp o2.enc.tmp &>/dev/null; then
    echo 'PASS: Cyphertexts from same source and password differ.' >&2
else
    echo 'FAIL: Cyphertexts from same source and password are identical.' >&2
fi

$RM_CMD -f o{,2}{,.enc}.tmp
