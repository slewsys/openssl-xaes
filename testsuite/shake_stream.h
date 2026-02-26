/* shake_stream.h: Declarations for shake-128 reader and writer.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#ifndef _SHAKE_STREAM_H
#define _SHAKE_STREAM_H

#include <stddef.h>

void shake_reader_free (void);
int shake_reader_init (int, int);
int shake_read (unsigned char *, size_t);

void shake_writer_free (void);
int shake_writer_init (size_t);
int shake_write (unsigned char *, size_t);
int shake_writer_final (unsigned char *, size_t);
#endif  /* _SHAKE_STREAM_H */
