/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * The event log is how the core reports to the outside world, and reaching the
 * real implementation means linking the whole hashcat_ctx into every fuzz
 * target. The targets do not read what is logged, so these three take its
 * place. Everything else a target calls is the real code, compiled from the
 * same source the binary is built from.
 */

#include "common.h"
#include "types.h"

#include <stdarg.h>

size_t event_log_info    (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);
size_t event_log_error   (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  (void) hashcat_ctx;
  (void) fmt;

  return 0;
}
