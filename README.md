# openssl-xaes: XAES-256-GCM-based File Encryption

## SYNOPSIS

```
openssl-xaes OPTIONS [AAD ...]
OPTIONS:
    --encrypt, -e
              Encrypt standard input with optional additional
              authenticated data (AAD) using XAES-256-GCM, and
              write to standard output.
    --decrypt, -d
              Decrypt standard input with optional additional
              authenticated data (AAD) using XAES-256-GCM, and
              write to standard output.
    --help, -h
              Display this message, then exit.
    --version, -v
              Display version info, then exit.

If no options are given, then a password is requested from /dev/tty,
plaintext is read from standard input, encrypted, and ciphertext is
written to standard output.
```

## DESCRIPTION

The `openssl-xaes` filter is an application of **XAES-256-GCM** for
password-based file encryption. Additional authenticated data (AAD)
can optionally be given on the command-line. Please note that no
amount of hashing or encryption can protect against weak passwords.

Whereas **XAES-256-GCM** is fully **FIPS 140** compliant, `openssl-xaes`
is not due to the use [Argon2id](https://en.wikipedia.org/wiki/Argon2)
for password hashing. And while **XAES-256-GCM** can, in theory,
encrypt large streams and files, the **OpenSSL** API used by
`openssl-xaes` to implement **XAES-256-GCM** limits input file size to
about 2 GiB (2147483631 bytes). On the other hand, given a strong
password, the number of files that can be safely encrypted is
virtually unlimited.

For a description of the algorithm, see
[XAES-256-GCM announcement](https://words.filippo.io/xaes-256-gcm/).
The specification and further discussion is available from
[The Community Crytography Specification Project - XAES-256-GCM](https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md).

Compared to the
[OpenSSL-based XAES-256-GCM reference](https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM/openssl/openssl.c),
this adds support for additional authenticated data (AAD) and includes
an OpenSSL-based accumulated vector test.

## BUILD AND INSTALL

`openssl-xaes` is only available in source form. To build requires a C
compiler, OpenSSL v3.2+ (for Argon2) libraries and headers, GNU `make`
and the `pkgconf` utility. With those installed, run:

```bash
git clone https://github.com/slewsys/openssl-xaes
cd openssl-xaes
make
make check
DESTDIR=/usr/local make install
```
