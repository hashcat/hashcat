/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"

#if defined (__CYGWIN__)
// workaround for zlib with cygwin build
int _wopen(const char *path, int oflag, ...)
{
  va_list ap;
  va_start (ap, oflag);
  int r = open (path, oflag, ap);
  va_end (ap);
  return r;
}
#endif

bool hc_fopen (HCFILE *fp, const char *path, char *mode)
{
  if (path == NULL || mode == NULL) return false;

  int oflag = -1;

  int fmode = S_IRUSR|S_IWUSR;

  if (strncmp (mode, "a", 1) == 0 || strncmp (mode, "ab", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_APPEND;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "ab", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "r", 1) == 0 || strncmp (mode, "rb", 2) == 0)
  {
    oflag = O_RDONLY;
    fmode = -1;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "rb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else if (strncmp (mode, "w", 1) == 0 || strncmp (mode, "wb", 2) == 0)
  {
    oflag = O_WRONLY | O_CREAT | O_TRUNC;

    #if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__)
    if (strncmp (mode, "wb", 2) == 0) oflag |= O_BINARY;
    #endif
  }
  else
  {
    // ADD more strncmp to handle more "mode"
    return false;
  }

  fp->pfp = NULL;
  fp->is_gzip = false;

  unsigned char check[3] = { 0 };

  int fd_tmp = open (path, O_RDONLY);

  if (fd_tmp != -1)
  {
    lseek (fd_tmp, 0, SEEK_SET);

    if (read (fd_tmp, check, sizeof(check)) > 0)
    {
      if (check[0] == 0x1f && check[1] == 0x8b && check[2] == 0x08) fp->is_gzip = true;
    }

    close (fd_tmp);
  }

  if (fmode == -1)
  {
    fp->fd = open (path, oflag);
  }
  else
  {
    fp->fd = open (path, oflag, fmode);
  }

  if (fp->fd == -1) return false;

  if (fp->is_gzip)
  {
    if ((fp->gfp = gzdopen (fp->fd, mode)) == NULL) return false;
  }
  else
  {
    if ((fp->pfp = fdopen (fp->fd, mode)) == NULL)  return false;
  }

  fp->path = path;
  fp->mode = mode;

  return true;
}

size_t hc_fread (void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  size_t n = -1;

  if (fp == NULL) return n;

  if (fp->is_gzip)
  {
    n = gzfread (ptr, size, nmemb, fp->gfp);
  }
  else
  {
    n = fread (ptr, size, nmemb, fp->pfp);
  }

  return n;
}

size_t hc_fwrite (void *ptr, size_t size, size_t nmemb, HCFILE *fp)
{
  size_t n = -1;

  if (fp == NULL) return n;

  if (fp->is_gzip)
  {
    n = gzfwrite (ptr, size, nmemb, fp->gfp);
  }
  else
  {
    n = fwrite (ptr, size, nmemb, fp->pfp);
  }

  if (n != nmemb) return -1;

  return n;
}

int hc_fseek (HCFILE *fp, off_t offset, int whence)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzseek (fp->gfp, (z_off_t) offset, whence);
  }
  else
  {
    r = fseeko (fp->pfp, offset, whence);
  }

  return r;
}

void hc_rewind (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->is_gzip)
  {
    gzrewind (fp->gfp);
  }
  else
  {
    rewind (fp->pfp);
  }
}

off_t hc_ftell (HCFILE *fp)
{
  off_t n = 0;

  if (fp == NULL) return -1;

  if (fp->is_gzip)
  {
    n = (off_t) gztell (fp->gfp);
  }
  else
  {
    n = ftello (fp->pfp);
  }

  return n;
}

int hc_fputc (int c, HCFILE *fp)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzputc (fp->gfp, c);
  }
  else
  {
    r = fputc (c, fp->pfp);
  }

  return r;
}

int hc_fgetc (HCFILE *fp)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzgetc (fp->gfp);
  }
  else
  {
    r = fgetc (fp->pfp);
  }

  return r;
}

char *hc_fgets (char *buf, int len, HCFILE *fp)
{
  char *r = NULL;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzgets (fp->gfp, buf, len);
  }
  else
  {
    r = fgets (buf, len, fp->pfp);
  }

  return r;
}

int hc_vfprintf (HCFILE *fp, const char *format, va_list ap)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzvprintf (fp->gfp, format, ap);
  }
  else
  {
    r = vfprintf (fp->pfp, format, ap);
  }

  return r;
}

int hc_fprintf (HCFILE *fp, const char *format, ...)
{
  int r = -1;

  if (fp == NULL) return r;

  va_list ap;

  va_start (ap, format);

  if (fp->is_gzip)
  {
    r = gzvprintf (fp->gfp, format, ap);
  }
  else
  {
    r = vfprintf (fp->pfp, format, ap);
  }

  va_end (ap);

  return r;
}

int hc_fscanf (HCFILE *fp, const char *format, void *ptr)
{
  if (fp == NULL) return -1;

  char *buf = (char *) hcmalloc (HCBUFSIZ_TINY);

  if (buf == NULL) return -1;

  char *b = hc_fgets (buf, HCBUFSIZ_TINY - 1, fp);

  if (b == NULL)
  {
    hcfree (buf);

    return -1;
  }

  sscanf (b, format, (void *) ptr);

  hcfree (buf);

  return 1;
}

int hc_fileno (HCFILE *fp)
{
  if (fp == NULL) return 1;

  return fp->fd;
}

int hc_feof (HCFILE *fp)
{
  int r = -1;

  if (fp == NULL) return r;

  if (fp->is_gzip)
  {
    r = gzeof (fp->gfp);
  }
  else
  {
    r = feof (fp->pfp);
  }

  return r;
}

void hc_fflush (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->is_gzip)
  {
    gzflush (fp->gfp, Z_SYNC_FLUSH);
  }
  else
  {
    fflush (fp->pfp);
  }
}

void hc_fclose (HCFILE *fp)
{
  if (fp == NULL) return;

  if (fp->is_gzip)
  {
    gzclose (fp->gfp);
  }
  else
  {
    fclose (fp->pfp);
  }

  close (fp->fd);

  fp->fd = -1;
  fp->pfp = NULL;
  fp->is_gzip = false;

  fp->path = NULL;
  fp->mode = NULL;
}

size_t fgetl (HCFILE *fp, char *line_buf)
{
  size_t line_len = 0;

  while (!hc_feof (fp))
  {
    const int c = hc_fgetc (fp);

    if (c == EOF) break;

    line_buf[line_len] = (char) c;

    line_len++;

    if (line_len == HCBUFSIZ_LARGE) line_len--;

    if (c == '\n') break;
  }

  if (line_len == 0) return 0;

  while (line_len)
  {
    if (line_buf[line_len - 1] == '\n')
    {
      line_len--;

      continue;
    }

    if (line_buf[line_len - 1] == '\r')
    {
      line_len--;

      continue;
    }

    break;
  }

  line_buf[line_len] = 0;

  return (line_len);
}

u64 count_lines (HCFILE *fp)
{
  u64 cnt = 0;

  char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE + 1);

  char prev = '\n';

  while (!hc_feof (fp))
  {
    size_t nread = hc_fread (buf, sizeof (char), HCBUFSIZ_LARGE, fp);

    if (nread < 1) continue;

    size_t i;

    for (i = 0; i < nread; i++)
    {
      if (prev == '\n') cnt++;

      prev = buf[i];
    }
  }

  hcfree (buf);

  return cnt;
}

size_t in_superchop (char *buf)
{
  size_t len = strlen (buf);

  while (len)
  {
    if (buf[len - 1] == '\n')
    {
      len--;

      buf[len] = 0;

      continue;
    }

    if (buf[len - 1] == '\r')
    {
      len--;

      buf[len] = 0;

      continue;
    }

    break;
  }

  return len;
}

size_t superchop_with_length (char *buf, const size_t len)
{
  size_t new_len = len;

  while (new_len)
  {
    if (buf[new_len - 1] == '\n')
    {
      new_len--;

      buf[new_len] = 0;

      continue;
    }

    if (buf[new_len - 1] == '\r')
    {
      new_len--;

      buf[new_len] = 0;

      continue;
    }

    break;
  }

  return new_len;
}
