/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "logging.h"

static int last_len = 0;

static int log_final (FILE *fp, const char *fmt, va_list ap)
{
  if (last_len)
  {
    fputc ('\r', fp);

    for (int i = 0; i < last_len; i++)
    {
      fputc (' ', fp);
    }

    fputc ('\r', fp);
  }

  char s[4096] = { 0 };

  const size_t max_len = sizeof (s);

  const int len = vsnprintf (s, max_len, fmt, ap);

  //if (len > max_len) len = max_len;

  fwrite (s, (size_t) len, 1, fp);

  fflush (fp);

  last_len = len;

  return last_len;
}

int log_out_nn (FILE *fp, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (fp, fmt, ap);

  va_end (ap);

  return len;
}

int log_info_nn (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stdout, fmt, ap);

  va_end (ap);

  return len;
}

int log_error_nn (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stderr, fmt, ap);

  va_end (ap);

  return len;
}

int log_out (FILE *fp, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (fp, fmt, ap);

  va_end (ap);

  fputc ('\n', fp);

  last_len = 0;

  return len;
}

int log_info (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stdout, fmt, ap);

  va_end (ap);

  fputc ('\n', stdout);

  last_len = 0;

  return len;
}

int log_error (const char *fmt, ...)
{
  fputc ('\n', stderr);
  fputc ('\n', stderr);

  va_list ap;

  va_start (ap, fmt);

  const int len = log_final (stderr, fmt, ap);

  va_end (ap);

  fputc ('\n', stderr);
  fputc ('\n', stderr);

  last_len = 0;

  return len;
}
