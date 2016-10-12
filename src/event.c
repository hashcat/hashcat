/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "thread.h"
#include "event.h"

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  bool need_mux = true;

  switch (id)
  {
    case EVENT_LOG_INFO:    need_mux = false;
    case EVENT_LOG_WARNING: need_mux = false;
    case EVENT_LOG_ERROR:   need_mux = false;
  }

  if (need_mux == true)
  {
    event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

    hc_thread_mutex_lock (event_ctx->mux_event);
  }

  hashcat_ctx->event (id, hashcat_ctx, buf, len);

  if (need_mux == true)
  {
    event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

    hc_thread_mutex_unlock (event_ctx->mux_event);
  }
}

static int event_log (const char *fmt, va_list ap, char *s, const size_t sz)
{
  return vsnprintf (s, sz, fmt, ap);
}

size_t event_log_info_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  event_call (EVENT_LOG_INFO, hashcat_ctx, buf, len);

  return len;
}

size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  event_call (EVENT_LOG_WARNING, hashcat_ctx, buf, len);

  return len;
}

size_t event_log_error_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  event_call (EVENT_LOG_ERROR, hashcat_ctx, buf, len);

  return len;
}

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  #if defined (_WIN)

  buf[len + 0] = '\r';
  buf[len + 1] = '\n';

  event_call (EVENT_LOG_INFO, hashcat_ctx, buf, len + 2);

  #else

  buf[len] = '\n';

  event_call (EVENT_LOG_INFO, hashcat_ctx, buf, len + 1);

  #endif

  return len;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  #if defined (_WIN)

  buf[len + 0] = '\r';
  buf[len + 1] = '\n';

  event_call (EVENT_LOG_WARNING, hashcat_ctx, buf, len + 2);

  #else

  buf[len] = '\n';

  event_call (EVENT_LOG_WARNING, hashcat_ctx, buf, len + 1);

  #endif

  return len;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  char buf[BUFSIZ];

  const size_t len = event_log (fmt, ap, buf, sizeof (buf));

  va_end (ap);

  #if defined (_WIN)

  buf[len + 0] = '\r';
  buf[len + 1] = '\n';

  event_call (EVENT_LOG_ERROR, hashcat_ctx, buf, len + 2);

  #else

  buf[len] = '\n';

  event_call (EVENT_LOG_ERROR, hashcat_ctx, buf, len + 1);

  #endif

  return len;
}

int event_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_init (event_ctx->mux_event);

  event_ctx->last_len = 0;

  return 0;
}

void event_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_delete (event_ctx->mux_event);

  event_ctx->last_len = 0;
}
