/* openssl-xaes.c: Entry point for openssl-xaes file-encryption filter.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 *
 * This filter is an application of XAES-256-GCM for password-based
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

#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "xaes.h"
#include "version.h"

static xaes_aad_t **argv2aadv (int, char *[]);
static void clean_up (unsigned char *pwd1, int pwd1_len,
                      unsigned char *pwd2, int pwd2_len,
                      unsigned char *str, unsigned char *ciph);
static int decrypt (const xaes_aad_t *[]);
static int encrypt (const xaes_aad_t *[]);
static void usage (const char *);

int
main (int argc, char *argv[])
{
  int (*cmd) (const xaes_aad_t *[]) = encrypt;
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

  exit (!cmd ((const xaes_aad_t **) argv2aadv (argc, argv)));
}

/*
 * argv2aadv: Converts a NULL-terminated vector of NUL-terminated strings (i.e., argv)
 *     to a NULL-terminated vector of xaes_aad_t pointers.
 */
static xaes_aad_t **
argv2aadv (int argc, char *argv[])
{
  static xaes_aad_t **aadv = NULL;;
  static int aadv_size = 0;

  if (!argc)
    return NULL;

  for (int i = 0; i < aadv_size; ++i)
    free (aadv[i]);

  aadv_size = (argc + 1) * sizeof (xaes_aad_t *);
  if ((aadv = (xaes_aad_t **) realloc (aadv, aadv_size)) == NULL)
    {
      fprintf (stderr, "%s\n", strerror (errno));
      aadv_size = 0;
      return NULL;
    }

  for (int i = 0; i < argc; ++i)
    {
      if ((aadv[i] = (xaes_aad_t *) malloc (sizeof (xaes_aad_t))) == NULL)
        {
          fprintf (stderr, "%s\n", strerror (errno));
          aadv_size = i ? i - 1 : 0;
          return NULL;
        }

      aadv[i]->data = (unsigned char *) argv[i];
      aadv[i]->len = strlen (argv[i]);
    }

  aadv[argc] = NULL;
  return aadv;
}

/*
 * encrypt: Password is read from /dev/tty. Plaintext is read from
 *     standard input (stdin). Ciphertext is written to standard
 *     output (stdout). The parameter `aadv' is an optional vector of
 *     additional authenticated data (AAD). If provided, it must
 *     include at least a terminating NULL pointer.
 */
static int
encrypt (const xaes_aad_t *aadv[])
{
  unsigned char password[BUFSIZ];
  unsigned char confirm[BUFSIZ];
  unsigned char salt[ARGON2_SALT_SIZE];
  unsigned char xaes_key[XAES_KEY_SIZE];
  unsigned char nonce[XAES_NONCE_SIZE];
  unsigned char *enc = NULL;
  unsigned char *str = NULL;
  size_t str_len = 0;
  size_t enc_len = 0;
  unsigned int salt_bits = ARGON2_SALT_SIZE << 3;
  unsigned int nonce_bits = XAES_NONCE_SIZE << 3;
  int password_len = 0;
  int confirm_len = 0;

  if (!read_passphrase ("Password: ", password, BUFSIZ, &password_len)
      || !read_passphrase ("Confirm password: ", confirm, BUFSIZ, &confirm_len))
    {
        fprintf (stderr, "Failed to read password.\n");
        goto err;
    }
  else if (password_len != confirm_len
           || strncmp ((char *)password, (char *)confirm, password_len))
    {
      fprintf (stderr, "Passwords do not match.\n");
      goto err;
    }

  clean_up (confirm, confirm_len, NULL, 0, NULL, NULL);
  confirm_len = 0;

  if (RAND_bytes_ex (NULL, (unsigned char *) salt, ARGON2_SALT_SIZE,
                     salt_bits) != 1
      || !derive_xaes_key (password, salt, xaes_key)
      || !read_stream (&str, &str_len, 0, stdin))
    goto err;

  /* OpenSSL 3.x API imposes file size limit INT_MAX. */
  else if (INT_MAX - GCM_TAG_MAX < str_len)
    {
      fprintf (stderr, "Input too long\n");
      goto err;
    }
  else if (RAND_bytes_ex (NULL, (unsigned char *) nonce, XAES_NONCE_SIZE,
                          nonce_bits) != 1
           || !seal_xaes_256_gcm (str, str_len, aadv, xaes_key, nonce,
                                  &enc, &enc_len)
           || !write_stream (salt, ARGON2_SALT_SIZE, stdout)
           || !write_stream (nonce, XAES_NONCE_SIZE, stdout)
           || !write_stream (enc, enc_len, stdout))
    goto err;

  clean_up (NULL, 0, NULL, 0, str, enc);
  return 1;

err:
  clean_up (password, password_len, confirm, confirm_len, str, enc);
  return 0;
}

/*
 * decocde: Password is read from /dev/tty. Ciphertext is read from
 *     standard input (stdin). Plaintext is written to standard output
 *     (stdout). The parameter `aadv' is a vector of any additional
 *     authenticated data (AAD). If provided, it must include at least
 *     a terminating NULL pointer.
 */
static int
decrypt (const xaes_aad_t *aadv[])
{
  unsigned char password[BUFSIZ];
  unsigned char salt[ARGON2_SALT_SIZE];
  unsigned char xaes_key[XAES_KEY_SIZE];
  unsigned char nonce[XAES_NONCE_SIZE];
  unsigned char *dec = NULL;
  unsigned char *str = NULL;
  size_t dec_len = 0;
  size_t str_len = 0;
  int password_len = 0;

  if (!read_passphrase ("Password: ", password, BUFSIZ, &password_len))
    {
      fprintf (stderr, "Failed to read password.\n");
      goto err;
    }


  if (!read_stream (&str, &str_len, ARGON2_SALT_SIZE, stdin)
      || !memcpy (salt, str, ARGON2_SALT_SIZE)
      || !derive_xaes_key (password, salt, xaes_key)
      || !read_stream (&str, &str_len, XAES_NONCE_SIZE, stdin)
      || !memcpy (nonce, str, XAES_NONCE_SIZE)
      || !read_stream (&str, &str_len, 0, stdin))
    goto err;

  /* OpenSSL 3.x API imposes file size limit INT_MAX. */
  else if (INT_MAX - GCM_TAG_MAX < str_len)
    {
      fprintf (stderr, "Input too long\n");
      goto err;
    }
  else if (!open_xaes_256_gcm (str, str_len, aadv, xaes_key, nonce,
                             &dec, &dec_len)
      || !write_stream (dec, dec_len, stdout))
    goto err;

  clean_up (NULL, 0, NULL, 0, str, dec);
  return 1;

err:
  clean_up (password, password_len, NULL, 0, str, dec);
  return 0;
}

void
clean_up (unsigned char pwd1[], int pwd1_len,
            unsigned char pwd2[], int pwd2_len,
            unsigned char *plain, unsigned char *cipher)
{
  if (pwd1_len)
    {
#if HAVE_MEMSET_EXPLICIT
      memset_explicit (pwd1, 0, pwd1_len);
#elif HAVE_EXPLICIT_BZERO
      explicit_bzero (pwd1, pwd1_len);
#else
      memset (pwd1, 0, pwd1_len);
#endif
    }

  if (pwd2_len)
    {
#if HAVE_MEMSET_EXPLICIT
      memset_explicit (pwd2, 0, pwd2_len);
#elif HAVE_EXPLICIT_BZERO
      explicit_bzero (pwd2, pwd2_len);
#else
      memset (pwd2, 0, pwd2_len);
#endif
    }

    if (plain)
      free (plain);

    if (cipher)
      free (cipher);
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
