/* shake_stream.c: Shake-128 reader and writer for XAES-256-GCM in C.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
/*
 * #include <openssl/params.h>
 */

#include <string.h>

#define ulong_new(key, val_p)                                                 \
  OSSL_PARAM_construct_ulong (key, val_p)

#define READ_SHAKE(buf, val_p)                                                \
  do                                                                          \
    {                                                                         \
      if (!EVP_DigestFinalXOF (ctx, buf, sizeof buf))                         \
        goto err;                                                             \
    } while (0)


EVP_MD_CTX *reader_ctx = NULL;
EVP_MD *reader_md = NULL;
unsigned char *reader_md_buf = NULL;
size_t reader_md_buf_size = 0;

void
shake_reader_free (void)
{
  if (reader_md_buf)
    {
      OPENSSL_free (reader_md_buf);
      reader_md_buf = NULL;
    }
  EVP_MD_free (reader_md);
  EVP_MD_CTX_free (reader_ctx);
  reader_md = NULL;
  reader_ctx = NULL;
}

int
shake_reader_init (int digest_size, int iterations)
{
  if (reader_ctx)
    {
      EVP_MD_free (reader_md);
      EVP_MD_CTX_free (reader_ctx);
      reader_md = NULL;
      reader_ctx = NULL;
    }

  if (reader_md_buf)
    {
      OPENSSL_free (reader_md_buf);
      reader_md_buf = NULL;
    }

  reader_md_buf_size = (size_t) digest_size * iterations;

  if (!(reader_md_buf = OPENSSL_malloc (reader_md_buf_size))
      || !(reader_ctx = EVP_MD_CTX_new ())
      || !(reader_md = EVP_MD_fetch (NULL, "SHAKE-128", NULL))
      || !EVP_DigestInit_ex2 (reader_ctx, reader_md, NULL))
    goto err;

  OSSL_PARAM params[] =
    {
      ulong_new (OSSL_DIGEST_PARAM_XOFLEN, &reader_md_buf_size),
      OSSL_PARAM_construct_end ()
    };

  if (!EVP_MD_CTX_set_params (reader_ctx, params)
      || !EVP_DigestUpdate (reader_ctx, "", 0)
      || !EVP_DigestFinalXOF (reader_ctx, reader_md_buf, reader_md_buf_size))
    goto err;

  return 1;

 err:
  shake_reader_free ();
  return 0;
}

int
shake_read (unsigned char *buf, size_t buf_size)
{
  static size_t offset = 0;

  if (offset + buf_size > reader_md_buf_size)
    return 0;

  memcpy (buf, reader_md_buf + offset, buf_size);
  offset += buf_size;
  return 1;
}

EVP_MD_CTX *writer_ctx = NULL;
EVP_MD *writer_md = NULL;
unsigned char *writer_md_buf = NULL;
size_t writer_md_buf_size = 0;

void
shake_writer_free (void)
{
  if (writer_md_buf)
    {
      OPENSSL_free (writer_md_buf);
      writer_md_buf = NULL;
    }
  EVP_MD_free (writer_md);
  EVP_MD_CTX_free (writer_ctx);
  writer_md = NULL;
  writer_ctx = NULL;
}

int
shake_writer_init (size_t digest_size)
{
  if (writer_ctx)
    {
      EVP_MD_free (writer_md);
      EVP_MD_CTX_free (writer_ctx);
      writer_md = NULL;
      writer_ctx = NULL;
    }

  if (writer_md_buf)
    {
      OPENSSL_free (writer_md_buf);
      writer_md_buf = NULL;
    }

  writer_md_buf_size = digest_size;

  if (!(writer_md_buf = OPENSSL_malloc (writer_md_buf_size))
      || !(writer_ctx = EVP_MD_CTX_new ())
      || !(writer_md = EVP_MD_fetch (NULL, "SHAKE-128", NULL))
      || !EVP_DigestInit_ex2 (writer_ctx, writer_md, NULL))
    goto err;

  OSSL_PARAM params[] =
    {
      ulong_new (OSSL_DIGEST_PARAM_XOFLEN, &writer_md_buf_size),
      OSSL_PARAM_construct_end ()
    };

  if (!EVP_MD_CTX_set_params (writer_ctx, params))
    goto err;

  return 1;

 err:
  shake_writer_free ();
  return 0;
}

int
shake_write (unsigned char *buf, size_t buf_size)
{
  if (!EVP_DigestUpdate (writer_ctx, (void *) buf, buf_size))
    {
      shake_writer_free ();
      return 0;
    }

  return 1;
}

int
shake_writer_final (unsigned char *buf, size_t buf_size)
{
  if (!EVP_DigestFinalXOF (writer_ctx, buf, buf_size))
    {
      shake_writer_free ();
      return 0;
    }

  shake_writer_free ();
  return 1;
}
