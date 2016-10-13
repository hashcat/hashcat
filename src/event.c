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

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_INFO, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_WARNING, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

size_t event_log_error_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_ERROR, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_INFO, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_WARNING, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);

  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_TINY - 1);

  event_ctx->msg_buf[event_ctx->msg_len] = 0;

  va_end (ap);

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_ERROR, hashcat_ctx, NULL, 0);

  return event_ctx->msg_len;
}

int event_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_init (event_ctx->mux_event);

  event_ctx->msg_len = 0;

  return 0;
}

void event_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_delete (event_ctx->mux_event);

  event_ctx->msg_len = 0;
}
