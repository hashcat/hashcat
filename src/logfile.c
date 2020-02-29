/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "locking.h"
#include "shared.h"
#include "logfile.h"

void logfile_generate_topid (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  struct timeval v;

  gettimeofday (&v, NULL);

  snprintf (logfile_ctx->topid, 40, "TOP.%08x.%08x", (u32) v.tv_sec, (u32) v.tv_usec);
}

void logfile_generate_subid (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  struct timeval v;

  gettimeofday (&v, NULL);

  snprintf (logfile_ctx->subid, 40, "SUB.%08x.%08x", (u32) v.tv_sec, (u32) v.tv_usec);
}

void logfile_append (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  if (logfile_ctx->enabled == false) return;

  HCFILE fp;

  if (hc_fopen (&fp, logfile_ctx->logfile, "ab") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", logfile_ctx->logfile, strerror (errno));

    return;
  }

  hc_lockfile (&fp);

  va_list ap;

  va_start (ap, fmt);

  hc_vfprintf (&fp, fmt, ap);

  va_end (ap);

  hc_fwrite (EOL, strlen (EOL), 1, &fp);

  hc_fflush (&fp);

  hc_unlockfile (&fp);

  hc_fclose (&fp);
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
