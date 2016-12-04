/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "loopback.h"
#include "locking.h"

static void loopback_format_plain (hashcat_ctx_t *hashcat_ctx, const u8 *plain_ptr, const unsigned int plain_len)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return;

  int needs_hexify = 0;

  for (u32 i = 0; i < plain_len; i++)
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

    for (u32 i = 0; i < plain_len; i++)
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

int loopback_init (hashcat_ctx_t *hashcat_ctx)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  loopback_ctx->enabled = false;

  if (user_options->benchmark   == true) return 0;
  if (user_options->keyspace    == true) return 0;
  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->stdout_flag == true) return 0;
  if (user_options->speed_only  == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  loopback_ctx->enabled  = true;
  loopback_ctx->fp       = NULL;
  loopback_ctx->filename = (char *) hcmalloc (HCBUFSIZ_TINY);

  return 0;
}

void loopback_destroy (hashcat_ctx_t *hashcat_ctx)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return;

  memset (loopback_ctx, 0, sizeof (loopback_ctx_t));
}

int loopback_write_open (hashcat_ctx_t *hashcat_ctx)
{
  induct_ctx_t   *induct_ctx   = hashcat_ctx->induct_ctx;
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return 0;

  if (induct_ctx->enabled == false) return 0;

  time_t now;

  time (&now);

  const u32 random_num = get_random_num (0, 9999);

  snprintf (loopback_ctx->filename, HCBUFSIZ_TINY - 1, "%s/%s.%d_%u", induct_ctx->root_directory, LOOPBACK_FILE, (int) now, random_num);

  FILE *fp = fopen (loopback_ctx->filename, "ab");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", loopback_ctx->filename, strerror (errno));

    return -1;
  }

  loopback_ctx->fp = fp;

  loopback_ctx->unused = true;

  return 0;
}

void loopback_write_unlink (hashcat_ctx_t *hashcat_ctx)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return;

  if (loopback_ctx->filename == NULL) return;

  unlink (loopback_ctx->filename);
}

void loopback_write_close (hashcat_ctx_t *hashcat_ctx)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return;

  if (loopback_ctx->fp == NULL) return;

  fclose (loopback_ctx->fp);

  if (loopback_ctx->unused == true)
  {
    loopback_write_unlink (hashcat_ctx);
  }
}

void loopback_write_append (hashcat_ctx_t *hashcat_ctx, const u8 *plain_ptr, const unsigned int plain_len)
{
  loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;

  if (loopback_ctx->enabled == false) return;

  FILE *fp = loopback_ctx->fp;

  loopback_format_plain (hashcat_ctx, plain_ptr, plain_len);

  lock_file (fp);

  fwrite (EOL, strlen (EOL), 1, fp);

  fflush (fp);

  unlock_file (fp);

  loopback_ctx->unused = false;
}
