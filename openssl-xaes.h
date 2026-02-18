#include <stddef.h>
#include <stdio.h>

#include "xaes.h"
#include "version.h"

int set_terminal (int, int);
unsigned char *read_passphrase (const char *, unsigned char *, int);
int read_stream (unsigned char **, size_t *, size_t, FILE *);
int write_stream (unsigned char *, size_t, FILE *);
