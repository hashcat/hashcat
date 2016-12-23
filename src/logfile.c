/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "logfile.h"
#include "locking.h"
#include "shared.h"

static int logfile_generate_id (void)
{
  const int n = rand ();

  time_t t;

  time (&t);

  return t + n;
}

void logfile_generate_topid (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  const int id = logfile_generate_id ();

  snprintf (logfile_ctx->topid, 1 + 16, "TOP%08x", (u32) id);
}

void logfile_generate_subid (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  const int id = logfile_generate_id ();

  snprintf (logfile_ctx->subid, 1 + 16, "SUB%08x", (u32) id);
}

void logfile_append (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  FILE *fp = fopen (logfile_ctx->logfile, "ab");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %m", logfile_ctx->logfile);

    return;
  }

  lock_file (fp);

  va_list ap;

  va_start (ap, fmt);

  vfprintf (fp, fmt, ap);

  va_end (ap);

  fwrite (EOL, strlen (EOL), 1, fp);

  fflush (fp);

  fclose (fp);
}

int logfile_init (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  logfile_ctx_t   *logfile_ctx   = hashcat_ctx->logfile_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  if (user_options->logfile_disable == true) return 0;

  hc_asprintf (&logfile_ctx->logfile, "%s/%s.log", folder_config->session_dir, user_options->session);

  logfile_ctx->subid = (char *) hcmalloc (HCBUFSIZ_TINY);
  logfile_ctx->topid = (char *) hcmalloc (HCBUFSIZ_TINY);

  logfile_ctx->enabled = true;

  FILE *fp = fopen (logfile_ctx->logfile, "ab");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %m", logfile_ctx->logfile);

    return -1;
  }

  fclose (fp);

  return 0;
}

void logfile_destroy (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  hcfree (logfile_ctx->logfile);
  hcfree (logfile_ctx->topid);
  hcfree (logfile_ctx->subid);

  memset (logfile_ctx, 0, sizeof (logfile_ctx_t));
}
