/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "memory.h"
#include "logging.h"
#include "shared.h"
#include "loopback.h"

void loopback_init (loopback_ctx_t *loopback_ctx)
{
  loopback_ctx->fp = NULL;

  loopback_ctx->filename = (char *) mymalloc (HCBUFSIZ_TINY);
}

void loopback_destroy (loopback_ctx_t *loopback_ctx)
{
  myfree (loopback_ctx->filename);
}

int loopback_write_open (loopback_ctx_t *loopback_ctx, const char *induction_directory)
{
  time_t now;

  time (&now);

  const uint random_num = get_random_num (0, 9999);

  snprintf (loopback_ctx->filename, HCBUFSIZ_TINY - 1, "%s/%s.%d_%u", induction_directory, LOOPBACK_FILE, (int) now, random_num);

  loopback_ctx->fp = fopen (loopback_ctx->filename, "ab");

  if (loopback_ctx->fp == NULL)
  {
    log_error ("ERROR: %s: %s", loopback_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void loopback_write_unlink (loopback_ctx_t *loopback_ctx)
{
  if (loopback_ctx->filename == NULL) return;

  unlink (loopback_ctx->filename);
}

void loopback_write_close (loopback_ctx_t *loopback_ctx)
{
  if (loopback_ctx->fp == NULL) return;

  fclose (loopback_ctx->fp);
}

void loopback_format_plain (loopback_ctx_t *loopback_ctx, const u8 *plain_ptr, const unsigned int plain_len)
{
  int needs_hexify = 0;

  for (uint i = 0; i < plain_len; i++)
  {
    if (plain_ptr[i] < 0x20)
    {
      needs_hexify = 1;

      break;
    }

    if (plain_ptr[i] > 0x7f)
    {
      needs_hexify = 1;

      break;
    }
  }

  if (needs_hexify == 1)
  {
    fprintf (loopback_ctx->fp, "$HEX[");

    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (loopback_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (loopback_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, loopback_ctx->fp);
  }
}

void loopback_write_append (loopback_ctx_t *loopback_ctx, const u8 *plain_ptr, const unsigned int plain_len)
{
  FILE *fp = loopback_ctx->fp;

  loopback_format_plain (loopback_ctx, plain_ptr, plain_len);

  fputc ('\n', fp);

  fflush (fp);
}
