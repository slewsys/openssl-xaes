/* xaes.h: Macros and declarations for XAES-256-GCM in C.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#ifndef _XAES_H
#define _XAES_H

#include <stddef.h>

/*
 * Per NIST SP 800-38D¹, GCM tag size <= 128 bits (16 bytes).
 *
 * ¹https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf,
 *  Section 5.2.1.2 Output Data
 */
#define GCM_TAG_MAX 16
#define XAES_KEY_SIZE 32
#define XAES_NONCE_SIZE 24

/*
 * Per RFC 9106, Section 4, Parameter Choice.
*/
#define ARGON2_SALT_SIZE 16
#define ARGON2_TAG_SIZE 32

typedef struct xaes_aad
{
  unsigned char *data;
  size_t len;
} xaes_aad_t;

int derive_xaes_key (unsigned char *,
                     const unsigned char[ARGON2_SALT_SIZE],
                     unsigned char[ARGON2_TAG_SIZE]);
int derive_aes_key (unsigned char[XAES_KEY_SIZE],
                    const unsigned char[XAES_NONCE_SIZE],
                    unsigned char[XAES_KEY_SIZE]);
int seal_xaes_256_gcm (const unsigned char *, size_t,
                       const xaes_aad_t *[],
                       unsigned char[XAES_KEY_SIZE],
                       const unsigned char[XAES_NONCE_SIZE],
                       unsigned char **, size_t *);
int open_xaes_256_gcm (const unsigned char *, size_t,
                       const xaes_aad_t *[],
                       unsigned char[XAES_KEY_SIZE],
                       const unsigned char[XAES_NONCE_SIZE],
                       unsigned char **, size_t *);
#endif  /* _XAES_H */
