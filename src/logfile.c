/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logfile.h"

static int logfile_generate_id ()
{
  const int n = rand ();

  time_t t;

  time (&t);

  return t + n;
}

void logfile_generate_topid (logfile_ctx_t *logfile_ctx)
{
  if (logfile_ctx->enabled == false) return;

  const int id = logfile_generate_id ();

  snprintf (logfile_ctx->topid, 1 + 16, "TOP%08x", id);
}

void logfile_generate_subid (logfile_ctx_t *logfile_ctx)
{
  if (logfile_ctx->enabled == false) return;

  const int id = logfile_generate_id ();

  snprintf (logfile_ctx->subid, 1 + 16, "SUB%08x", id);
}

void logfile_append (const logfile_ctx_t *logfile_ctx, const char *fmt, ...)
{
  if (logfile_ctx->enabled == false) return;

  FILE *fp = fopen (logfile_ctx->logfile, "ab");

  va_list ap;

  va_start (ap, fmt);

  vfprintf (fp, fmt, ap);

  va_end (ap);

  fputc ('\n', fp);

  fflush (fp);

  fclose (fp);
}

void logfile_init (logfile_ctx_t *logfile_ctx, const user_options_t *user_options, const folder_config_t *folder_config)
{
  if (user_options->logfile_disable == true) return;

  logfile_ctx->logfile = (char *) mymalloc (HCBUFSIZ_TINY);

  snprintf (logfile_ctx->logfile, HCBUFSIZ_TINY - 1, "%s/%s.log", folder_config->session_dir, user_options->session);

  logfile_ctx->subid = (char *) mymalloc (HCBUFSIZ_TINY);
  logfile_ctx->topid = (char *) mymalloc (HCBUFSIZ_TINY);

  logfile_ctx->enabled = true;
}

void logfile_destroy (logfile_ctx_t *logfile_ctx)
{
  if (logfile_ctx->enabled == false) return;

  myfree (logfile_ctx->logfile);
  myfree (logfile_ctx->topid);
  myfree (logfile_ctx->subid);

  memset (logfile_ctx, 0, sizeof (logfile_ctx_t));
}
