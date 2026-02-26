/* xaes-test.c: Testsuite for XAES-256-GCM in C.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

#include "xaes.h"
#include "shake_stream.h"

static int test_vectors (void);
static int test_accumulated (void);

int
main (int argc, char *argv[])
{
  if (argc > 1)
    {
      fprintf (stderr, "Usage: %s\n", argv[0]);
      exit (1);
    }

  exit (!(test_vectors () && test_accumulated ()));
}

static int
test_vectors (void)
{
  const unsigned char keys[2][32] =
    {
      { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
      },
      {
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
      }
    };
  unsigned char key[32];
  const unsigned char nonce[24] =
      {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X'
      };
  const unsigned char ciphertext_expected[2][56] =
    {
      {
         0xce, 0x54, 0x6e, 0xf6, 0x3c, 0x9c, 0xc6,
         0x07, 0x65, 0x92, 0x36, 0x09, 0xb3, 0x3a,
         0x9a, 0x19, 0x74, 0xe9, 0x6e, 0x52, 0xda,
         0xf2, 0xfc, 0xf7, 0x07, 0x5e, 0x22, 0x71
      },
      {
        0x98, 0x6e, 0xc1, 0x83, 0x25, 0x93, 0xdf,
        0x54, 0x43, 0xa1, 0x79, 0x43, 0x7f, 0xd0,
        0x83, 0xbf, 0x3f, 0xdb, 0x41, 0xab, 0xd7,
        0x40, 0xa2, 0x1f, 0x71, 0xeb, 0x76, 0x9d
      }
    };
  const unsigned char *plaintext = (unsigned char *) "XAES-256-GCM";
  const unsigned char *aad[2] =
    {
        (unsigned char *) "",
        (unsigned char *) "c2sp.org/XAES-256-GCM"
    };
  unsigned char *ciphertext = NULL;
  unsigned char *decrypted = NULL;;
  size_t plaintext_len = strlen ((char *) plaintext);
  size_t ciphertext_len;
  size_t decrypted_len;
  xaes_aad_t *aadv[2] = { NULL };
  xaes_aad_t xaes_aad;
  int errs = 0;

  /*
   * Test encryption and decryption with and without additional
   * authenticated data (AAD).
   */
  for (int i = 0; i < 2; ++i)
    {
      xaes_aad.data = (unsigned char *) aad[i];
      xaes_aad.len = strlen ((char *) aad[i]);
      aadv[0] = &xaes_aad;
      fprintf (stderr, "Plaintext: %.*s\n", (int) plaintext_len, plaintext);
      for (int j = 0; aadv[j]; ++j)
        printf ("AAD: %s\n", aadv[j]->data);

      memcpy (key, keys[i], XAES_KEY_SIZE);
      if (!seal_xaes_256_gcm (plaintext, plaintext_len,
                              (const xaes_aad_t **) aadv,
                              key, nonce, &ciphertext, &ciphertext_len))
        {
          fprintf (stderr, "Iteration %d: Encryption failed\n", i);
          errs++;
          goto err;
        }
      else if (strncmp ((char *) ciphertext,
                        (char *) ciphertext_expected[i], ciphertext_len))
        {
          fprintf (stderr, "Iteration %d: Ciphertext mismatch\n", i);
          errs++;
          goto err;
        }

      fprintf (stderr, "Ciphertext: ");
      for (size_t j = 0; j < ciphertext_len; ++j)
        fprintf (stderr, "%02x", ciphertext[j]);
      fprintf (stderr, "\n");

      memcpy (key, keys[i], XAES_KEY_SIZE);
      if (!open_xaes_256_gcm (ciphertext, ciphertext_len,
                              (const xaes_aad_t **) aadv, key, nonce,
                              &decrypted, &decrypted_len))
        {
          fprintf (stderr, "Iteration %d: Decryption failed\n", i);
          errs++;
          goto err;
        }
      else if (strncmp ((char *) decrypted, (char *) plaintext, decrypted_len))
        {
          fprintf (stderr, "Iteration %d: Deciphertext mismatch\n", i);
          errs++;
          goto err;
        }

      fprintf (stderr, "Decrypted: %.*s\n\n", (int) decrypted_len, decrypted);

    err:
      free (ciphertext);
      ciphertext = NULL;
      free (decrypted);
      decrypted = NULL;
    }

  return !errs;
}

static int
test_accumulated (void)
{
  /*
   * const unsigned char iter_16_expected[32] =
   *   {
   *     0xbd, 0x7c, 0x19, 0xfa, 0x37, 0x33, 0xb6, 0x1e,
   *     0x95, 0xa0, 0xcb, 0x80, 0x41, 0xd7, 0x83, 0xb8,
   *     0xb4, 0xb8, 0xb7, 0x9d, 0x24, 0xb2, 0x9a, 0x0f,
   *     0x6e, 0x3c, 0x4b, 0x74, 0x2b, 0x6c, 0xfe, 0x41
   *   };
   * const unsigned char iter_10_000_expected[32] =
   *   {
   *     0xe6, 0xb9, 0xed, 0xf2, 0xdf, 0x6c, 0xec, 0x60,
   *     0xc8, 0xcb, 0xd8, 0x64, 0xe2, 0x21, 0x1b, 0x59,
   *     0x7f, 0xb6, 0x9a, 0x52, 0x91, 0x60, 0xcd, 0x04,
   *     0x0d, 0x56, 0xc0, 0xc2, 0x10, 0x08, 0x19, 0x39
   *   };
   */
  const unsigned char iter_1_000_000_expected[32] =
    {
      0x21, 0x63, 0xae, 0x14, 0x45, 0x98, 0x5a, 0x30,
      0xb6, 0x05, 0x85, 0xee, 0x67, 0xda, 0xa5, 0x56,
      0x74, 0xdf, 0x06, 0x90, 0x1b, 0x89, 0x05, 0x93,
      0xe8, 0x24, 0xb8, 0xa7, 0xc8, 0x85, 0xab, 0x15
    };

  xaes_aad_t *aadv[2] = { NULL };
  xaes_aad_t xaes_aad;
  unsigned char aad[256];
  unsigned char key[XAES_KEY_SIZE];
  unsigned char decryption_key[XAES_KEY_SIZE];
  unsigned char nonce[XAES_NONCE_SIZE];
  unsigned char byte[1];
  unsigned char plaintext[256];
  unsigned char *ciphertext = NULL;
  unsigned char *decrypted = NULL;
  unsigned char writer_digest[32];
  size_t aad_len = 0;
  size_t plaintext_len = 0;
  size_t ciphertext_len = 0;
  size_t decrypted_len = 0;
  size_t reader_digest_size = XAES_KEY_SIZE + XAES_NONCE_SIZE + 512;
  size_t writer_digest_size = 32;
  int iterations = 1'000'000;

  if (!shake_reader_init (reader_digest_size, iterations)
      || !shake_writer_init (writer_digest_size))
    goto err;

  for (int i = 0; i < iterations; ++i)
    {
      if (!shake_read (key, XAES_KEY_SIZE)
          || !memcpy (decryption_key, key, XAES_KEY_SIZE)
          || !shake_read (nonce, XAES_NONCE_SIZE)
          || !shake_read (byte, 1))
        goto err;

      plaintext_len = (int) *byte;

      if (!shake_read (plaintext, plaintext_len)
          || !shake_read (byte, 1))
        goto err;

      aad_len = (int) *byte;

      if (!shake_read (aad, aad_len))
        goto err;

      xaes_aad.data = aad;
      xaes_aad.len = aad_len;
      aadv[0] = &xaes_aad;

      if (!seal_xaes_256_gcm (plaintext, plaintext_len,
                              (const xaes_aad_t **) aadv,
                              key, nonce, &ciphertext, &ciphertext_len))
        {
          fprintf (stderr, "Iteration %d: Encryption failed\n", i);
          goto err;
        }
      else if (!open_xaes_256_gcm (ciphertext, ciphertext_len,
                                   (const xaes_aad_t **) aadv, decryption_key, nonce,
                                   &decrypted, &decrypted_len))
        {
          fprintf (stderr, "Iteration %d: Decryption failed\n", i);
          goto err;
        }
      else if (memcmp (decrypted, plaintext, decrypted_len))
        {
          fprintf (stderr, "Iteration %d: Plaintext and decrypted differ\n", i);
          goto err;
        }

      shake_write (ciphertext, ciphertext_len);
      free (decrypted);
      decrypted = NULL;
      free (ciphertext);
      ciphertext = NULL;
    }

  shake_writer_final (writer_digest, writer_digest_size);
  /*
   * fprintf (stderr, "Writer digest: ");
   * for (size_t j = 0; j < writer_digest_size; ++j)
   *   fprintf (stderr, "%02x", writer_digest[j]);
   * fprintf (stderr, "\n");
   */

  if (memcmp (writer_digest, iter_1_000_000_expected, writer_digest_size))
    {
      fprintf (stderr, "Writer digest mismatch\n");
      goto err;
    }

  fprintf (stderr, "PASS: %d iterations of accumulated vectors.\n", iterations);
  shake_reader_free ();
  shake_writer_free ();
  return 1;

err:
  if (decrypted)
    free (decrypted);
  if (ciphertext)
    free (ciphertext);
  shake_reader_free ();
  shake_writer_free ();
  return 0;
}
