/* io.h: I/O function declarations for openssl-xaes file-encryption filter.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#ifndef _IO_H
#define _IO_H

#include <stddef.h>
#include <stdio.h>

int set_terminal (int, int);
unsigned char *read_passphrase (const char *, unsigned char *, int, int *);
int read_stream (unsigned char **, size_t *, size_t, FILE *);
int write_stream (unsigned char *, size_t, FILE *);
#endif  /* _IO_H */
