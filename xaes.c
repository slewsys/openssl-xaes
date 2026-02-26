/* xaes.c: Implementation of XAES-256-GCM in C.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <string.h>

#include "xaes.h"

#define utf8_str_new(key, buf_p, bufsiz)                                      \
  OSSL_PARAM_construct_utf8_string (key, buf_p, bufsiz)
#define int_new(key, val_p)                                                   \
  OSSL_PARAM_construct_int (key, val_p)
#define uint32_new(key, val_p)                                                \
  OSSL_PARAM_construct_uint32 (key, val_p)
#define octet_str_new(key, buf_p, bufsiz)                                     \
  OSSL_PARAM_construct_octet_string (key, buf_p, bufsiz)

static void
xaes_kdf_cleanup (EVP_KDF_CTX *ctx, EVP_KDF *kdf,
                 unsigned char *key, size_t key_len)
{
#if HAVE_MEMSET_EXPLICIT
  memset_explicit (key, 0, key_len);
#elif HAVE_EXPLICIT_BZERO
  explicit_bzero (key, key_len);
#else
  memset (key, 0, key_len);
#endif

  EVP_KDF_CTX_free (ctx);
  EVP_KDF_free (kdf);
}

/*
 * derive_xaes_key: Given a password and salt, derives a 256-bit key
 *     for XAES-256-GCM using Argon2id. The salt used for generating
 *     an encryption key must be also be provided for decryption,
 *     e.g., by concatenating the salt and ciphertext. The given
 *     password is automatically zero'ed after use. Returns 0 on
 *     failure, and 1 on success.
 */
int
derive_xaes_key (unsigned char *pwd,
                 const unsigned char salt[ARGON2_SALT_SIZE],
                 unsigned char out[ARGON2_TAG_SIZE])
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
  size_t pwd_len = strlen ((char *) pwd);
  uint32_t threads = 1;
  uint32_t iter = 3;
  uint32_t lanes = 4;
  uint32_t memcost = 65536;     /* 64 MiB */
  OSSL_PARAM params[] =
    {
      uint32_new (OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost),
      uint32_new (OSSL_KDF_PARAM_ITER, &iter),
      uint32_new (OSSL_KDF_PARAM_THREADS, &threads),
      uint32_new (OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      octet_str_new (OSSL_KDF_PARAM_SALT, (void *) salt, ARGON2_SALT_SIZE),
      octet_str_new (OSSL_KDF_PARAM_PASSWORD, (void *) pwd, pwd_len),
      OSSL_PARAM_construct_end ()
    };
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;
  int status;

  if (!(kdf = EVP_KDF_fetch (NULL, "ARGON2ID", NULL))
      || !(ctx = EVP_KDF_CTX_new (kdf)))
    goto err;

  status = EVP_KDF_derive (ctx, out, ARGON2_TAG_SIZE, params);
  xaes_kdf_cleanup (ctx, kdf, pwd, pwd_len);
  return status;

 err:
  xaes_kdf_cleanup (ctx, kdf, pwd, pwd_len);
  return 0;
}

/*
 * derive_aes_key: Derives a per-nonce encryption key for AES-256-GCM
 *     to reduce collision probability between the given nonce and
 *     root key. The given key is automatically zero'ed after use.
 *     Returns 0 on failure, and 1 on success.
 */
int
derive_aes_key (unsigned char key[XAES_KEY_SIZE],
                const unsigned char nonce[XAES_NONCE_SIZE],
                unsigned char out[XAES_KEY_SIZE])
{
  /* Per XAES-256-GCM spec: */
  int use_l = 0;                /* Omit optional L field. */
  int r = 16;                   /* 16-bit counter. */
  OSSL_PARAM params[] =
    {
      utf8_str_new (OSSL_KDF_PARAM_CIPHER, "AES256", 0),
      utf8_str_new (OSSL_KDF_PARAM_MAC, "CMAC", 0),
      utf8_str_new (OSSL_KDF_PARAM_MODE, "COUNTER", 0),
      int_new (OSSL_KDF_PARAM_KBKDF_USE_L, &use_l),
      int_new (OSSL_KDF_PARAM_KBKDF_R, &r),
      octet_str_new (OSSL_KDF_PARAM_KEY, (void *) key, XAES_KEY_SIZE),
      octet_str_new (OSSL_KDF_PARAM_SALT, "X", 1),
      octet_str_new (OSSL_KDF_PARAM_INFO, (void *) nonce, XAES_NONCE_SIZE >> 1),
      OSSL_PARAM_construct_end ()
    };
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;;
  int status;

  if (!(kdf = EVP_KDF_fetch (NULL, "KBKDF", NULL))
      || !(ctx = EVP_KDF_CTX_new (kdf)))
    goto err;

  status = EVP_KDF_derive (ctx, out, XAES_KEY_SIZE, params);
  xaes_kdf_cleanup (ctx, kdf, key, XAES_KEY_SIZE);
  return status;

 err:
  xaes_kdf_cleanup (ctx, kdf, key, XAES_KEY_SIZE);
  return 0;
}

static void
xaes_cipher_cleanup (EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher,
                    unsigned char *key, size_t key_len)


{
#if HAVE_MEMSET_EXPLICIT
  memset_explicit (key, 0, key_len);
#elif HAVE_EXPLICIT_BZERO
  explicit_bzero (key, key_len);
#else
  memset (key, 0, key_len);
#endif

  EVP_CIPHER_free (cipher);
  EVP_CIPHER_CTX_free (ctx);
}


/*
 * seal_aes_256_gcm: Encrypts plaintext using AES-256-GCM with the
 *     given derived key and lower 96 bits of a uniformally random
 *     192-bit nonce. The optional string vector of additional
 *     authenticated data (AAD) must include at least a terminating
 *     NULL pointer. An authentication tag is appended to ciphertext.
 *     The given key is automatically zero'ed after use. Returns 0 on
 *     failure, and 1 on success.
 */
static int
seal_aes_256_gcm (const unsigned char *plaintext, size_t plaintext_len,
                  const unsigned char *aadv[],
                  unsigned char key[XAES_KEY_SIZE],
                  const unsigned char nonce[XAES_NONCE_SIZE >> 1],
                  unsigned char **ciphertext, size_t *ciphertext_len_p)
{
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_CIPHER *cipher = NULL;
  int tag_len = 0;
  int ciphertext_len;
  int final_len;

  *ciphertext = NULL;
  *ciphertext_len_p = 0;

  if (!(ctx = EVP_CIPHER_CTX_new ())
      || !(cipher = EVP_CIPHER_fetch (NULL, "AES-256-GCM", NULL))
      || !EVP_EncryptInit_ex2 (ctx, cipher, key, nonce, NULL)
      || !(tag_len = EVP_CIPHER_CTX_get_tag_length (ctx)))
    goto err;
  else if (aadv)
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
      || !EVP_EncryptFinal_ex (ctx, *ciphertext + ciphertext_len, &final_len))
    goto err;

  const unsigned char *tag = *ciphertext + (int) ciphertext_len;
  OSSL_PARAM params[] =
    {
      octet_str_new (OSSL_CIPHER_PARAM_AEAD_TAG, (void *) tag, tag_len),
      OSSL_PARAM_construct_end ()
    };

  if (!EVP_CIPHER_CTX_get_params (ctx, params))
    goto err;

  *ciphertext_len_p = ciphertext_len + tag_len;
  xaes_cipher_cleanup (ctx, cipher, key, XAES_KEY_SIZE);
  return 1;

 err:
  if (*ciphertext)
    {
      OPENSSL_free (*ciphertext);
      *ciphertext = NULL;
    }
  xaes_cipher_cleanup (ctx, cipher, key, XAES_KEY_SIZE);
  return 0;
}

/*
 * open_aes_256_gcm: Decrypts ciphertext using AES-256-GCM with the
 *     given key along with the same nonce and string vector of
 *     additional authenticated data (AAD) used for encryption. The
 *     given key is automatically zero'ed after use. Returns 0 on
 *     failure, and 1 on success.
 */
static int
open_aes_256_gcm (const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *aadv[],
                  unsigned char key[XAES_KEY_SIZE],
                  const unsigned char nonce[XAES_NONCE_SIZE >> 1],
                  unsigned char **plaintext, size_t *plaintext_len_p)
{
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_CIPHER *cipher = NULL;
  int tag_len = 0;
  int plaintext_len;
  int final_len;

  *plaintext = NULL;
  *plaintext_len_p = 0;

  if (!(ctx  = EVP_CIPHER_CTX_new ())
      || !(cipher = EVP_CIPHER_fetch (NULL, "AES-256-GCM", NULL))
      ||!EVP_DecryptInit_ex2 (ctx, cipher, key, nonce, NULL)
      || !(tag_len = EVP_CIPHER_CTX_get_tag_length (ctx)))
    goto err;
  else if (aadv)
    for (int aadv_len; *aadv; ++aadv)
      {
        aadv_len = (int) strlen ((char *) *aadv);
        if (!EVP_DecryptUpdate (ctx, NULL, &plaintext_len, *aadv, aadv_len)
            || plaintext_len != aadv_len)
          goto err;
      }

  const unsigned char *tag = ciphertext + (int) ciphertext_len - tag_len;
  OSSL_PARAM params[] =
    {
      octet_str_new (OSSL_CIPHER_PARAM_AEAD_TAG, (void *) tag, tag_len),
      OSSL_PARAM_construct_end ()
    };

  if (!(*plaintext = OPENSSL_malloc (ciphertext_len - tag_len))
      || !EVP_DecryptUpdate (ctx, *plaintext, &plaintext_len, ciphertext,
                             (int) ciphertext_len - tag_len)
      || !EVP_CIPHER_CTX_set_params (ctx, params)
      || !EVP_DecryptFinal_ex (ctx, *plaintext + plaintext_len, &final_len))
    goto err;

  *plaintext_len_p = plaintext_len;
  xaes_cipher_cleanup (ctx, cipher, key, XAES_KEY_SIZE);
  return 1;

 err:
  if (*plaintext)
    {
      OPENSSL_free (*plaintext);
      *plaintext = NULL;
    }
  xaes_cipher_cleanup (ctx, cipher, key, XAES_KEY_SIZE);
  return 0;
}

/*
 * seal_xaes_256_gcm: Encrypts a given plaintext up to about 2 GiB
 *     (2,147,483,631 bytes) using XAES-256-GCM with a given 256-bit
 *     key and uniformally random 192-bit nonce. Since the nonce is
 *     used to derive an encryption key, it must be also be provided
 *     for decryption, e.g., by prepending it to the ciphertext. An
 *     optional string vector of additional authenticated data (AAD)
 *     must include at least a terminating NULL pointer. The
 *     ciphertext buffer can be freed with `OPENSSL_free'. Both the
 *     given and derived keys are zero'ed after use. Returns 0 on
 *     failure, and 1 on success.
 */
int
seal_xaes_256_gcm (const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *aadv[],
                   unsigned char key[XAES_KEY_SIZE],
                   const unsigned char nonce[XAES_NONCE_SIZE],
                   unsigned char **ciphertext, size_t *ciphertext_len_p)
{
  unsigned char derived_key[XAES_KEY_SIZE];

  return derive_aes_key (key, nonce, derived_key)
    && seal_aes_256_gcm (plaintext, plaintext_len, aadv, derived_key,
                         nonce + (XAES_NONCE_SIZE >> 1),
                         ciphertext, ciphertext_len_p);
}

/*
 * open_xaes_256_gcm: Decrypts the given ciphertext using XAES-256-GCM
 *     with the same 256-bit key, nonce and string vector of
 *     additional authenticated data (AAD) used for encryption. The
 *     plaintext buffer can be freed with `OPENSSL_free'. Both the
 *     given and derived keys are zero'ed after use. Returns 0 on
 *     failure, and 1 on success.
 */
int
open_xaes_256_gcm (const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *aadv[],
                   unsigned char key[XAES_KEY_SIZE],
                   const unsigned char nonce[XAES_NONCE_SIZE],
                   unsigned char **plaintext, size_t *plaintext_len_p)
{
  unsigned char derived_key[XAES_KEY_SIZE];

  return derive_aes_key (key, nonce, derived_key)
    && open_aes_256_gcm (ciphertext, ciphertext_len, aadv, derived_key,
                         nonce + (XAES_NONCE_SIZE >> 1), plaintext,
                         plaintext_len_p);
}
