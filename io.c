/* io.c: I/O functions for openssl-xaes file-encryption filter.
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/param.h>

/* set-terminal state argument. */
#define RAW 1

int
set_terminal (int fd, int raw)
{
  static struct termios tty_nom;
  static int tty_saved = 0;

  struct termios tty_bis;
  struct termios tty_raw;

  if (!tty_saved)
    {
      if (tcgetattr (fd, &tty_nom) == -1)
        {
          fprintf (stderr, "Failed to get line-terminal attributes\n");
          return 0;
        }
      tty_saved = 1;
    }

  if (!raw)
    {
      if (tcsetattr (fd, TCSANOW, &tty_nom) == -1)
      {
        fprintf (stderr, "Failed to get line-terminal attributes\n");
        return 0;
      }
      return 1;
    }

  if (tcgetattr (fd, &tty_raw) == -1)
    {
      fprintf (stderr, "Failed to get line-terminal attributes\n");
      return 0;
    }

  tty_raw.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP);
                       /*
                        * | INLCR | IGNCR | ICRNL | IXON);
                        */
  tty_raw.c_oflag &= ~OPOST;
  tty_raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  tty_raw.c_cflag &= ~(CSIZE | PARENB);
  tty_raw.c_cflag |= CS8;
  tty_raw.c_cc[VMIN] = 1;
  tty_raw.c_cc[VTIME] = 0;

  if (tcsetattr (fd, TCSANOW, &tty_raw) == -1)
    {
      fprintf (stderr, "Failed to set line-terminal attributes.\r\n");
      tcsetattr (fd, TCSANOW, &tty_nom);
      return 0;
    }

  if (tcgetattr (fd, &tty_bis) == -1
      || tty_raw.c_iflag != tty_bis.c_iflag
      || tty_raw.c_oflag != tty_bis.c_oflag
      || tty_raw.c_lflag != tty_bis.c_lflag
      || tty_raw.c_cflag != tty_bis.c_cflag)
    {
      fprintf (stderr, "Failed to verify line-terminal attributes.\r\n");
      tcsetattr (fd, TCSANOW, &tty_nom);
      return 0;
    }

  return 1;
}

unsigned char *
read_passphrase (const char *prompt, unsigned char *buf, int bufsiz)
{
  int fd = -1;
  int n;
  int status = -1;

  if (!buf)
    {
      fprintf (stderr, "Invalid buffer\n");
      return NULL;
    }
  else if ((fd = open ("/dev/tty", O_RDWR | O_NOCTTY | O_SYNC)) == -1)
    {
      fprintf (stderr, "%s\n", strerror (errno));
      errno = 0;
      return NULL;
    }
  else if (!set_terminal (fd, RAW))
    {
      close (fd);
      return NULL;
    }
  else if (prompt)
    {
      fprintf (stderr, "%s", prompt);
      fflush (stderr);
    }

 read_pass:
   for (n = 0; n < bufsiz
          && (status = read (fd, buf + n, 1)) == 1
          && buf[n] != '\n'; ++n)
     ;

   buf[n] = '\0';
   if (prompt)
     fprintf (stderr, "\r\n");

   if (status == -1)
     {
       if (errno == EINTR)
         {
           errno = 0;
           goto read_pass;
         }

       fprintf (stderr, "%s\r\n", strerror (errno));
       set_terminal (fd, !RAW);
       close (fd);
       errno = 0;
       return NULL;
     }
   else if (n == bufsiz)
     {
       fprintf (stderr, "Password too long\r\n");
       set_terminal (fd, !RAW);
       close (fd);
       return NULL;
     }

   set_terminal (fd, !RAW);
   close (fd);
   return buf;
}

/*
 * read_stream: Read `limit' bytes from file pointed to by `fp'. Return
 *     status. Content pointer and length are saved as `*str_p' and `*len_p',
 *     respctively. If `limit' is zero (0), then read to end of file.
 */
int
read_stream (unsigned char **str_p, size_t *len_p, size_t limit, FILE *fp)
{
  static  unsigned char *str = NULL;
  static size_t len = 0;

  size_t requested;
  size_t actual = 0;


  /* Assert: str_p != NULL && len_p != NULL && fp != NULL */
  *len_p = 0;
  do
    {
      requested = limit ? MIN (BUFSIZ, limit - *len_p) : BUFSIZ;
      if (len < *len_p + requested)
        {
          if (!(str = realloc (str, len + BUFSIZ)))
            {
              fprintf (stderr, "%s\n", strerror (errno));
              return 0;
            }
          len += BUFSIZ;
        }
      *len_p += actual = fread (str + *len_p, 1, requested, fp);
    }
  while (actual == requested && (limit == 0 || *len_p < limit));

  if (ferror (fp))
    {
      fprintf (stderr, "%s\n", strerror (errno));
      clearerr (fp);
      return 0;
    }
  *str_p = str;
  return 1;
}

/*
 * write_stream: Write `len' bytes to file pointed to by `fp' prefixed
 *     by `salt_size' bytes of `salt'. Return status.
 */
int
write_stream (unsigned char *str, size_t len, FILE *fp)
{
  if ((len && fwrite (str, 1, len, fp) != len))
    {
      fprintf (stderr, "%sn", strerror (errno));
      return 0;
    }
  return 1;
}
