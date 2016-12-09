/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "debugfile.h"
#include "locking.h"

static void debugfile_format_plain (hashcat_ctx_t *hashcat_ctx, const u8 *plain_ptr, const u32 plain_len)
{
  debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;

  if (debugfile_ctx->enabled == false) return;

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
    fprintf (debugfile_ctx->fp, "$HEX[");

    for (u32 i = 0; i < plain_len; i++)
    {
      fprintf (debugfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (debugfile_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, debugfile_ctx->fp);
  }
}

void debugfile_write_append (hashcat_ctx_t *hashcat_ctx, const u8 *rule_buf, const u32 rule_len, const u8 *mod_plain_ptr, const u32 mod_plain_len, const u8 *orig_plain_ptr, const u32 orig_plain_len)
{
  debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;

  if (debugfile_ctx->enabled == false) return;

  const u32 debug_mode = debugfile_ctx->mode;

  if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
  {
    debugfile_format_plain (hashcat_ctx, orig_plain_ptr, orig_plain_len);

    if ((debug_mode == 3) || (debug_mode == 4)) fputc (':', debugfile_ctx->fp);
  }

  fwrite (rule_buf, rule_len, 1, debugfile_ctx->fp);

  if (debug_mode == 4)
  {
    fputc (':', debugfile_ctx->fp);

    debugfile_format_plain (hashcat_ctx, mod_plain_ptr, mod_plain_len);
  }

  fwrite (EOL, strlen (EOL), 1, debugfile_ctx->fp);
}

int debugfile_init (hashcat_ctx_t *hashcat_ctx)
{
  debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  debugfile_ctx->enabled = false;

  if (user_options->benchmark     == true) return 0;
  if (user_options->keyspace      == true) return 0;
  if (user_options->left          == true) return 0;
  if (user_options->opencl_info   == true) return 0;
  if (user_options->show          == true) return 0;
  if (user_options->stdout_flag   == true) return 0;
  if (user_options->speed_only    == true) return 0;
  if (user_options->progress_only == true) return 0;
  if (user_options->usage         == true) return 0;
  if (user_options->version       == true) return 0;
  if (user_options->debug_mode    == 0)    return 0;

  debugfile_ctx->enabled = true;

  debugfile_ctx->mode = user_options->debug_mode;

  debugfile_ctx->filename = user_options->debug_file;

  if (debugfile_ctx->filename)
  {
    FILE *fp = fopen (debugfile_ctx->filename, "ab");

    if (fp == NULL)
    {
      event_log_error (hashcat_ctx, "Could not open debug-file for writing");

      return -1;
    }

    if (lock_file (fp) == -1)
    {
      fclose (fp);

      event_log_error (hashcat_ctx, "%s: %m", debugfile_ctx->filename);

      return -1;
    }

    debugfile_ctx->fp = fp;
  }
  else
  {
    debugfile_ctx->fp = stdout;
  }

  return 0;
}

void debugfile_destroy (hashcat_ctx_t *hashcat_ctx)
{
  debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;

  if (debugfile_ctx->enabled == false) return;

  if (debugfile_ctx->filename)
  {
    fclose (debugfile_ctx->fp);
  }

  memset (debugfile_ctx, 0, sizeof (debugfile_ctx_t));
}
