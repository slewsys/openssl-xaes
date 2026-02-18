/* openssl-xaes.c: Entry point for openssl-xaes file-encryption utility.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 *
 * This utility is an application of XAES-256-GCM for password-based
 * file encryption. The password in hashed with Argon2id to derive a
 * 256-bit root key for XAES-256-GCM. Please note that no amount of
 * encryption can protect against weak passwords.
 *
 * While XAES-256-GCM can, in theory, encrypt large streams and files,
 * the OpenSSL API used here limits the input file size to about 2 GiB
 * (2147483631 bytes). On the other hand, given a strong password, the
 * number of files that can be safely encrypted is virtually
 * unlimited.
 *
 * For a description of XAES-256-GCM algorithm, see: https://words.filippo.io/xaes-256-gcm/
 * The specification of XAES-256-GCM is available at: https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
 *
 */
#include <openssl/rand.h>

#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include "openssl-xaes.h"

/*
 * Per NIST SP 800-38D¹, GCM tag size <= 128 bits (16 bytes).
 *
 * ¹https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf,
 *  Section 5.2.1.2 Output Data
 */
#define GCM_TAG_MAX 16

static int decrypt (const unsigned char *[]);
static int encrypt (const unsigned char *[]);
static void usage (const char *);

int
main (int argc, char *argv[])
{
  int (*cmd) (const unsigned char *[]) = encrypt;
  const struct option long_opts[] =
    {
      {"decrypt",  no_argument, NULL, 'd'},
      {"encrypt",  no_argument, NULL, 'e'},
      {"help",    no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 'v'},
      {NULL,     0,           NULL, 0},
    };
  const char *short_opts = "dehv";
  int c;

  while ((c = getopt_long (argc, argv, short_opts, long_opts, NULL)) != -1)
    switch (c)
      {
      case 0:
        break;
      case 'd':
        cmd = decrypt;
        break;
      case 'e':
        cmd = encrypt;
        break;
      case 'h':                 /* Display help, then exit. */
        usage (argv[0]);
        return 0;
      case 'v':                 /* Display version, then exit. */
        printf ("%s", OPENSSL_XAES_VERSION_STRING);
        return 0;
      default:
        usage (argv[0]);
        return 0;
      }
  argv += optind;
  argc -= optind;

  return cmd ((const unsigned char **) argv);
}

/*
 * encrypt: Password is read from /dev/tty. Plaintext is read from
 *     standard input (stdin). Ciphertext is written to standard
 *     output (stdout). The parameter `aadv' is an optional string
 *     vector of additional authenticated data (AAD). If provided, it
 *     must include at least a terminating NULL pointer.
 */
static int
encrypt (const unsigned char *aadv[])
{
  unsigned char password[BUFSIZ];
  unsigned char nonce[24];
  unsigned char salt[16];
  unsigned char xaes_key[32];
  unsigned char *enc = NULL;
  unsigned char *str = NULL;
  size_t str_len = 0;
  size_t enc_len = 0;

  if (!read_passphrase ("Password: ", password, BUFSIZ)
      || RAND_bytes ((unsigned char *) salt, 16) != 1
      || !derive_xaes_key (password, salt, xaes_key))
    return 0;

#if HAVE_MEMSET_EXPLICIT
  memset_explicit (password, 0, strlen ((char *) password));
#elif HAVE_EXPLICIT_BZERO
  explicit_bzero (password, strlen ((char *) password));
#else
  memset (password, 0, strlen ((char *) password));
#endif

  if (!read_stream (&str, &str_len, 0, stdin))
    return 0;

  /* OpenSSL 3.x API imposes file size limit INT_MAX. */
  else if (INT_MAX - GCM_TAG_MAX < str_len)
    {
      fprintf (stderr, "Input too large\n");
      return 0;
    }
  else if (RAND_bytes ((unsigned char *) nonce, 24) != 1
           || !seal_xaes_256_gcm (str, str_len, aadv, xaes_key, nonce,
                                  &enc, &enc_len)
           || !write_stream (salt, 16, stdout)
           || !write_stream (nonce, 24, stdout)
           || !write_stream (enc, enc_len, stdout))
    return 0;
  OPENSSL_free (enc);
  return 1;
}

/*
 * decocde: Password is read from /dev/tty. Ciphertext is read from
 *     standard input (stdin). Plaintext is written to standard output
 *     (stdout). The parameter `aadv' is a string vector of any
 *     additional authenticated data (AAD). If provided, it must
 *     include at least a terminating NULL pointer.
 */
static int
decrypt (const unsigned char *aadv[])
{
  unsigned char password[BUFSIZ];
  unsigned char nonce[24];
  unsigned char salt[16];
  unsigned char xaes_key[32];
  unsigned char *dec = NULL;
  unsigned char *str = NULL;
  size_t dec_len = 0;
  size_t str_len = 0;

  if (!read_passphrase ("Password: ", password, BUFSIZ)
      || !read_stream (&str, &str_len, 16, stdin)
      || !memcpy (salt, str, 16)
      || !derive_xaes_key (password, salt, xaes_key))
    return 0;

#if HAVE_MEMSET_EXPLICIT
  memset_explicit (password, 0, strlen ((char *) password));
#elif HAVE_EXPLICIT_BZERO
  explicit_bzero (password, strlen ((char *) password));
#else
  memset (password, 0, strlen ((char *) password));
#endif

  if (!read_stream (&str, &str_len, 24, stdin)
      || !memcpy (nonce, str, 24)
      || !read_stream (&str, &str_len, 0, stdin))
    return 0;

  /* OpenSSL 3.x API imposes file size limit INT_MAX. */
  else if (INT_MAX - GCM_TAG_MAX < str_len)
    {
      fprintf (stderr, "Input too large\n");
      return 0;
    }

  else if (!open_xaes_256_gcm (str, str_len, aadv, xaes_key, nonce,
                             &dec, &dec_len)
      || !write_stream (dec, dec_len, stdout))
    return 0;
  OPENSSL_free (dec);
  return 1;
}

static void
usage (const char *argv0)
{
  const char *pgm;

  pgm = strrchr (argv0, '/');
  fprintf (stderr, "Usage: %s OPTIONS [AAD ...]\n", pgm ? pgm + 1 : argv0);
  fprintf (stderr, "OPTIONS:\n\
    --encrypt, -e\n\
              Encrypt standard input with optional additional\n\
              authenticated data (AAD) using XAES-256-GCM, and\n\
              write to standard output.\n\
    --decrypt, -d\n\
              Decrypt standard input with optional additional\n\
              authenticated data (AAD) using XAES-256-GCM, and\n\
              write to standard output.\n\
    --help, -h\n\
              Display this message, then exit.\n\
    --version, -v\n\
              Display version info, then exit.\n\
\n\
If no options are given, then a password is requested from /dev/tty,\n\
plaintext is read from standard input, encrypted, and ciphertext is\n\
written to standard output.\n");
}
