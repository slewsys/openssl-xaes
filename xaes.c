/* xaes.c: Implementation of XAES-256-GCM in C.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <string.h>

#define utf8_str_new(key, buf_p, bufsiz)                  \
  OSSL_PARAM_construct_utf8_string (key, buf_p, bufsiz)
#define int_new(key, val_p)                               \
  OSSL_PARAM_construct_int (key, val_p)
#define uint32_new(key, val_p)                            \
  OSSL_PARAM_construct_uint32 (key, val_p)
#define octet_str_new(key, buf_p, bufsiz)                 \
  OSSL_PARAM_construct_octet_string (key, buf_p, bufsiz)

/*
 * derive_xaes_key: Given a password and salt, derives a 256-bit key
 *     for XAES-256-GCM using Argon2id. The salt used for generating
 *     an encryption key must be also be provided for generating the
 *     decryption key, e.g., by concatenating the salt and ciphertext.
 *     Returns 0 on failure, and 1 on success.
 */
int
derive_xaes_key (const unsigned char *pwd,
                 const unsigned char salt[16],
                 unsigned char out[32])
{
  /*
   * Per RFC 9106, Section 4, Parameter Choice. Select, in order of
   * preference:
   *   I.   1 iteration,  4 lanes,  2 GiB RAM, 128-bit salt, 256-bit tag
   *   II.  3 iterations, 4 lanes, 64 MiB RAM, 128-bit salt, 256-bit tag
   *   III. 3 iterations, 4 lanes, 19 MiB RAM, 128-bit salt, 256-bit tag
   *
   * "Evaluating Argon2 Adoption and Effectiveness in Real-World Software"¹
   * emphasizes that Argon2id cannot protect against weak passwords.
   * Furthermore, increasing RAM yields diminishing returns (see Section 5,
   * Synthetic Dataset).
   *
   * ¹https://arxiv.org/pdf/2504.17121
   */
  uint32_t threads = 1;
  uint32_t iter = 3;
  uint32_t lanes = 4;
  uint32_t memcost = 65536;     /* 64 MiB */
  uint32_t early_clean = 1;     /* Zero password quickly. */
  OSSL_PARAM params[] =
    {
      uint32_new (OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost),
      uint32_new (OSSL_KDF_PARAM_ITER, &iter),
      uint32_new (OSSL_KDF_PARAM_THREADS, &threads),
      uint32_new (OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      uint32_new (OSSL_KDF_PARAM_EARLY_CLEAN, &early_clean),
      octet_str_new (OSSL_KDF_PARAM_SALT, (void *) salt, 32),
      octet_str_new (OSSL_KDF_PARAM_PASSWORD, (void *) pwd, strlen ((char *) pwd)),
      OSSL_PARAM_construct_end ()
    };
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;
  int status;

  if (!(kdf = EVP_KDF_fetch (NULL, "ARGON2ID", NULL)))
    return 0;
  else if (!(ctx = EVP_KDF_CTX_new (kdf)))
    {
      EVP_KDF_free (kdf);
      return 0;
    }
  status = EVP_KDF_derive (ctx, out, 32, params);
  EVP_KDF_free (kdf);
  EVP_KDF_CTX_free (ctx);
  return status;
}

/*
 * derive_aes_key: Derives a per-nonce encryption key for AES-256-GCM
 *     to reduce collision probability between the given nonce and
 *     root key. Returns 0 on failure, and 1 on success.
 */
int
derive_aes_key (const unsigned char key[32],
                const unsigned char nonce[24],
                unsigned char out[32])
{
  int use_l = 0;
  int r = 16;
  OSSL_PARAM params[] =
    {
      utf8_str_new (OSSL_KDF_PARAM_CIPHER, "AES256", 0),
      utf8_str_new (OSSL_KDF_PARAM_MAC, "CMAC", 0),
      utf8_str_new (OSSL_KDF_PARAM_MODE, "COUNTER", 0),
      int_new (OSSL_KDF_PARAM_KBKDF_USE_L, &use_l),
      int_new (OSSL_KDF_PARAM_KBKDF_R, &r),
      octet_str_new (OSSL_KDF_PARAM_KEY, (void *) key, 32),
      octet_str_new (OSSL_KDF_PARAM_SALT, "X", 1),
      octet_str_new (OSSL_KDF_PARAM_INFO, (void *) nonce, 12),
      OSSL_PARAM_construct_end ()
    };
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;;
  int status;

  if (!(kdf = EVP_KDF_fetch (NULL, "KBKDF", NULL)))
    return 0;
  else if (!(ctx = EVP_KDF_CTX_new (kdf)))
    {
      EVP_KDF_free (kdf);
      return 0;
    }
  status = EVP_KDF_derive (ctx, out, 32, params);
  EVP_KDF_free (kdf);
  EVP_KDF_CTX_free (ctx);
  return status;
}

/*
 * seal_aes_256_gcm: Encrypts plaintext using AES-256-GCM with the
 *     given derived key and lower 96 bits of a uniformally random
 *     192-bit nonce. A string vector of additional authenticated data
 *     (AAD) must include at least a terminating NULL pointer. An
 *     authentication tag is appended to ciphertext. Returns 0 on
 *     failure, and 1 on success.
 */
int
seal_aes_256_gcm (const unsigned char *plaintext, size_t plaintext_len,
                  const unsigned char *aadv[], const unsigned char key[32],
                  const unsigned char nonce[12], unsigned char **ciphertext,
                  size_t *ciphertext_len_p)
{
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_CIPHER *cipher = NULL;
  int tag_len;
  int ciphertext_len;
  int final_len;

  if (!(ctx  = EVP_CIPHER_CTX_new ())
      || !(cipher = EVP_CIPHER_fetch (NULL, "AES-256-GCM", NULL)))
    return 0;

  if (!EVP_EncryptInit_ex2 (ctx, cipher, key, nonce, NULL)
      || !(tag_len = EVP_CIPHER_CTX_get_tag_length (ctx)))
    goto err;

  if (aadv)
    for (int aadv_len; *aadv; ++aadv)
      {
        aadv_len = (int) strlen ((char *) *aadv);
        if (!EVP_EncryptUpdate (ctx, NULL, &ciphertext_len, *aadv, aadv_len)
            || ciphertext_len != aadv_len)
          goto err;
      }

  if (!(*ciphertext = OPENSSL_malloc (plaintext_len + tag_len))
      || !EVP_EncryptUpdate (ctx, *ciphertext, &ciphertext_len,
                             plaintext, (int) plaintext_len)
      || !EVP_EncryptFinal_ex (ctx, *ciphertext + ciphertext_len, &final_len)
      || !EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_GET_TAG, tag_len,
                               *ciphertext + ciphertext_len))
    {
      if (*ciphertext)
        OPENSSL_free (*ciphertext);
      *ciphertext = NULL;
      goto err;
    }

  EVP_CIPHER_free (cipher);
  EVP_CIPHER_CTX_free (ctx);
  *ciphertext_len_p = ciphertext_len + tag_len;
  return 1;

 err:
  EVP_CIPHER_free (cipher);
  EVP_CIPHER_CTX_free (ctx);
  return 0;
}

/*
 * open_aes_256_gcm: Decrypts ciphertext using AES-256-GCM with the
 *     given key and nonce. A string vector of additional
 *     authenticated data (AAD) must include at least a terminating
 *     NULL pointer. Returns 0 on failure, and 1 on success.
 */
int
open_aes_256_gcm (const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *aadv[], const unsigned char key[32],
                  const unsigned char nonce[12], unsigned char **plaintext,
                  size_t *plaintext_len_p)
{
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_CIPHER *cipher = NULL;
  int tag_len;
  int plaintext_len;
  int final_len;

  if (!(ctx  = EVP_CIPHER_CTX_new ())
      || !(cipher = EVP_CIPHER_fetch (NULL, "AES-256-GCM", NULL)))
    return 0;

  if (!EVP_DecryptInit_ex (ctx, cipher, NULL, key, nonce)
      || !(tag_len = EVP_CIPHER_CTX_get_tag_length (ctx)))
    goto err;

  if (aadv)
    for (int aadv_len; *aadv; ++aadv)
      {
        aadv_len = (int) strlen ((char *) *aadv);
        if (!EVP_DecryptUpdate (ctx, NULL, &plaintext_len, *aadv, aadv_len)
            || plaintext_len != aadv_len)
          goto err;
      }

  if (!(*plaintext = OPENSSL_malloc (ciphertext_len - tag_len))
           || !EVP_DecryptUpdate (ctx, *plaintext, &plaintext_len, ciphertext,
                                  (int) ciphertext_len - tag_len)
           || plaintext_len < 0
           || !EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_SET_TAG, tag_len,
                                    (void *) (ciphertext + (int) ciphertext_len
                                              - tag_len))
           || !EVP_DecryptFinal_ex (ctx, *plaintext + plaintext_len, &final_len))
    {
      if (*plaintext)
        OPENSSL_free (*plaintext);
      *plaintext = NULL;
      goto err;
    }

  EVP_CIPHER_free (cipher);
  EVP_CIPHER_CTX_free (ctx);
  *plaintext_len_p = plaintext_len;
  return 1;

 err:
  EVP_CIPHER_free (cipher);
  EVP_CIPHER_CTX_free (ctx);
  return 0;
}

/*
 * seal_xaes_256_gcm: Encrypts plaintext using XAES-256-GCM with the
 *     given 256-bit key and uniformally random 192-bit nonce. Since
 *     the nonce is used to derive an encryption key it must be also
 *     be provided to derive the decryption key, e.g., by prepending
 *     it to the ciphertext. A string vector of additional
 *     authenticated data (AAD) must include at least a terminating
 *     NULL pointer. Returns 0 on failure, and 1 on success.
 */
int
seal_xaes_256_gcm (const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *aadv[], const unsigned char key[32],
                   const unsigned char nonce[24], unsigned char **ciphertext,
                   size_t *ciphertext_len_p)
{
  unsigned char derived_key[32];

  if (!derive_aes_key (key, nonce, derived_key))
    return 0;
  return seal_aes_256_gcm (plaintext, plaintext_len, aadv,  derived_key,
                           nonce + 12, ciphertext, ciphertext_len_p);
}

/*
 * open_xaes_256_gcm: Decrypts ciphertext using XAES-256-GCM with a
 *     given 256-bit key and the same nonce used for encryption. A
 *     string vector of additional authenticated data (AAD) must
 *     include at least a terminating NULL pointer. Returns 0 on
 *     failure, and 1 on success.
 */
int
open_xaes_256_gcm (const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *aadv[], const unsigned char key[32],
                   const unsigned char nonce[24], unsigned char **plaintext,
                   size_t *plaintext_len_p)
{
  unsigned char derived_key[32];

  if (!derive_aes_key (key, nonce, derived_key))
    return 0;
  return open_aes_256_gcm (ciphertext, ciphertext_len, aadv, derived_key,
                           nonce + 12, plaintext, plaintext_len_p);
}
