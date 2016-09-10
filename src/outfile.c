/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "logging.h"
#include "interface.h"
#include "outfile.h"

void outfile_init (outfile_ctx_t *outfile_ctx, char *outfile, const uint outfile_format, const uint outfile_autohex)
{
  if (outfile == NULL)
  {
    outfile_ctx->fp       = stdout;
    outfile_ctx->filename = NULL;
  }
  else
  {
    outfile_ctx->fp       = NULL;
    outfile_ctx->filename = outfile;
  }

  outfile_ctx->outfile_format   = outfile_format;
  outfile_ctx->outfile_autohex  = outfile_autohex;
}

void outfile_destroy (outfile_ctx_t *outfile_ctx)
{
  outfile_ctx->fp               = NULL;
  outfile_ctx->filename         = NULL;
  outfile_ctx->outfile_format   = 0;
  outfile_ctx->outfile_autohex  = 0;
}

void outfile_format_plain (outfile_ctx_t *outfile_ctx, const unsigned char *plain_ptr, const uint plain_len)
{
  int needs_hexify = 0;

  if (outfile_ctx->outfile_autohex == 1)
  {
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
  }

  if (needs_hexify == 1)
  {
    fprintf (outfile_ctx->fp, "$HEX[");

    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (outfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (outfile_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, outfile_ctx->fp);
  }
}

void outfile_write_open (outfile_ctx_t *outfile_ctx)
{
  if (outfile_ctx->filename == NULL) return;

  outfile_ctx->fp = fopen (outfile_ctx->filename, "ab");

  if (outfile_ctx->fp == NULL)
  {
    log_error ("ERROR: %s: %s", outfile_ctx->filename, strerror (errno));

    outfile_ctx->fp       = stdout;
    outfile_ctx->filename = NULL;
  }
}

void outfile_write_close (outfile_ctx_t *outfile_ctx)
{
  if (outfile_ctx->fp == stdout) return;

  fclose (outfile_ctx->fp);
}

void outfile_write (outfile_ctx_t *outfile_ctx, const char *out_buf, const unsigned char *plain_ptr, const uint plain_len, const u64 crackpos, const unsigned char *username, const uint user_len, const hashconfig_t *hashconfig)
{
  if (outfile_ctx->outfile_format & OUTFILE_FMT_HASH)
  {
    fprintf (outfile_ctx->fp, "%s", out_buf);

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }
  else if (user_len)
  {
    if (username != NULL)
    {
      for (uint i = 0; i < user_len; i++)
      {
        fprintf (outfile_ctx->fp, "%c", username[i]);
      }

      if (outfile_ctx->outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
      {
        fputc (hashconfig->separator, outfile_ctx->fp);
      }
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_PLAIN)
  {
    outfile_format_plain (outfile_ctx, plain_ptr, plain_len);

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_HEXPLAIN)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (outfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_CRACKPOS)
  {
    fprintf (outfile_ctx->fp, "%" PRIu64, crackpos);
  }

  fputs (EOL, outfile_ctx->fp);
}
