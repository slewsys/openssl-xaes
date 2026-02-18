#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

#include "xaes.h"


int
main (void)
{
  const unsigned char key[2][32] =
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
  unsigned char *aadv[2] = { NULL };

  for (int i = 0; i < 2; ++i)
    {
      aadv[0] = (unsigned char *) aad[i];
      fprintf (stderr, "Plaintext: %.*s\n", (int) plaintext_len, plaintext);
      if (!seal_xaes_256_gcm (plaintext, plaintext_len,
                              (const unsigned char **) aadv,
                              key[i], nonce, &ciphertext, &ciphertext_len))
        return 1;

      for (int j = 0; aadv[j]; ++j)
        printf ("AAD: %s\n", aadv[j]);

      if (strncmp ((char *) ciphertext,
                   (char *) ciphertext_expected[i], ciphertext_len))
        fprintf (stderr, "Iteration %d: Ciphertext mismatch\n", i);

      fprintf (stderr, "Ciphertext: ");
      for (size_t j = 0; j < ciphertext_len; ++j)
        fprintf (stderr, "%02x", ciphertext[j]);
      fprintf (stderr, "\n");

      if (!open_xaes_256_gcm (ciphertext, ciphertext_len,
                              (const unsigned char **) aadv,
                              key[i], nonce, &decrypted, &decrypted_len))
        return 1;

      fprintf (stderr, "Decrypted: %.*s\n\n", (int) decrypted_len, decrypted);
      OPENSSL_free (ciphertext);
      ciphertext = NULL;
      OPENSSL_free (decrypted);
      decrypted = NULL;
    }
  return 0;
}
