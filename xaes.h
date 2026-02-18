#include <stddef.h>

int derive_xaes_key (const unsigned char *, const unsigned char[],
                     unsigned char[]);
int derive_aes_key (const unsigned char[], const unsigned char[],
                    unsigned char[]);
int seal_aes_256_gcm (const unsigned char *, int, const unsigned char[],
                      const unsigned char *[], const unsigned char[],
                      unsigned char **, size_t *);
int open_aes_256_gcm (const unsigned char *, int, const unsigned char[],
                      const unsigned char *[], const unsigned char[],
                      unsigned char **, size_t *);
int seal_xaes_256_gcm (const unsigned char *, int, const unsigned char *[],
                       const unsigned char[], const unsigned char[],
                       unsigned char **, size_t *);
int open_xaes_256_gcm (const unsigned char *, int, const unsigned char *[],
                       const unsigned char[], const unsigned char[],
                       unsigned char **, size_t *);
