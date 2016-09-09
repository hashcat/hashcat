/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "potfile.h"



void potfile_init (potfile_ctx_t *potfile_ctx, const char *profile_dir, const char *potfile_path)
{
  potfile_ctx->fp = NULL;

  potfile_ctx->filename = (char *) mymalloc (HCBUFSIZ_TINY);

  if (potfile_path == NULL)
  {
    snprintf (potfile_ctx->filename, HCBUFSIZ_TINY - 1, "%s/hashcat.potfile", profile_dir);
  }
  else
  {
    strncpy (potfile_ctx->filename, potfile_path, HCBUFSIZ_TINY - 1);
  }
}

int potfile_read_open (potfile_ctx_t *potfile_ctx)
{
  potfile_ctx->fp = fopen (potfile_ctx->filename, "rb");

  if (potfile_ctx->fp == NULL)
  {
    //log_error ("ERROR: %s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_read_close (potfile_ctx_t *potfile_ctx)
{
  fclose (potfile_ctx->fp);
}

int potfile_write_open (potfile_ctx_t *potfile_ctx)
{
  potfile_ctx->fp = fopen (potfile_ctx->filename, "ab");

  if (potfile_ctx->fp == NULL)
  {
    log_error ("ERROR: %s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_write_close (potfile_ctx_t *potfile_ctx)
{
  fclose (potfile_ctx->fp);
}

void potfile_destroy (potfile_ctx_t *potfile_ctx)
{
  myfree (potfile_ctx->filename);
}
