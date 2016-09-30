/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "logging.h"
#include "interface.h"
#include "hashes.h"
#include "outfile.h"

void outfile_init (outfile_ctx_t *outfile_ctx, const user_options_t *user_options)
{
  if (user_options->outfile == NULL)
  {
    outfile_ctx->fp       = stdout;
    outfile_ctx->filename = NULL;
  }
  else
  {
    outfile_ctx->fp       = NULL;
    outfile_ctx->filename = user_options->outfile;
  }

  outfile_ctx->outfile_format   = user_options->outfile_format;
  outfile_ctx->outfile_autohex  = user_options->outfile_autohex;
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
  bool needs_hexify = false;

  if (outfile_ctx->outfile_autohex == true)
  {
    for (uint i = 0; i < plain_len; i++)
    {
      if (plain_ptr[i] < 0x20)
      {
        needs_hexify = true;

        break;
      }

      if (plain_ptr[i] > 0x7f)
      {
        needs_hexify = true;

        break;
      }
    }
  }

  if (needs_hexify == true)
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

int outfile_and_hashfile (outfile_ctx_t *outfile_ctx, const char *hashfile)
{
  if (hashfile == NULL) return 0;

  char *outfile = outfile_ctx->filename;

  if (outfile == NULL) return 0;

  #if defined (_POSIX)
  struct stat tmpstat_outfile;
  struct stat tmpstat_hashfile;
  #endif

  #if defined (_WIN)
  struct stat64 tmpstat_outfile;
  struct stat64 tmpstat_hashfile;
  #endif

  FILE *tmp_outfile_fp = fopen (outfile, "r");

  if (tmp_outfile_fp)
  {
    #if defined (_POSIX)
    fstat (fileno (tmp_outfile_fp), &tmpstat_outfile);
    #endif

    #if defined (_WIN)
    _fstat64 (fileno (tmp_outfile_fp), &tmpstat_outfile);
    #endif

    fclose (tmp_outfile_fp);
  }

  FILE *tmp_hashfile_fp = fopen (hashfile, "r");

  if (tmp_hashfile_fp)
  {
    #if defined (_POSIX)
    fstat (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
    #endif

    #if defined (_WIN)
    _fstat64 (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
    #endif

    fclose (tmp_hashfile_fp);
  }

  if (tmp_outfile_fp && tmp_outfile_fp)
  {
    tmpstat_outfile.st_mode     = 0;
    tmpstat_outfile.st_nlink    = 0;
    tmpstat_outfile.st_uid      = 0;
    tmpstat_outfile.st_gid      = 0;
    tmpstat_outfile.st_rdev     = 0;
    tmpstat_outfile.st_atime    = 0;

    tmpstat_hashfile.st_mode    = 0;
    tmpstat_hashfile.st_nlink   = 0;
    tmpstat_hashfile.st_uid     = 0;
    tmpstat_hashfile.st_gid     = 0;
    tmpstat_hashfile.st_rdev    = 0;
    tmpstat_hashfile.st_atime   = 0;

    #if defined (_POSIX)
    tmpstat_outfile.st_blksize  = 0;
    tmpstat_outfile.st_blocks   = 0;

    tmpstat_hashfile.st_blksize = 0;
    tmpstat_hashfile.st_blocks  = 0;
    #endif

    #if defined (_POSIX)
    if (memcmp (&tmpstat_outfile, &tmpstat_hashfile, sizeof (struct stat)) == 0)
    {
      log_error ("ERROR: Hashfile and Outfile are not allowed to point to the same file");

      return -1;
    }
    #endif

    #if defined (_WIN)
    if (memcmp (&tmpstat_outfile, &tmpstat_hashfile, sizeof (struct stat64)) == 0)
    {
      log_error ("ERROR: Hashfile and Outfile are not allowed to point to the same file");

      return -1;
    }
    #endif
  }

  return 0;
}
