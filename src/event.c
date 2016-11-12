/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "thread.h"
#include "event.h"

static int event_log (const char *fmt, va_list ap, char *s, const size_t sz) __attribute__ ((format (printf, 1, 0)));

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  bool is_log = false;

  switch (id)
  {
    case EVENT_LOG_INFO:    is_log = true; break;
    case EVENT_LOG_WARNING: is_log = true; break;
    case EVENT_LOG_ERROR:   is_log = true; break;
  }

  if (is_log == false)
  {
    hc_thread_mutex_lock (event_ctx->mux_event);
  }

  hashcat_ctx->event (id, hashcat_ctx, buf, len);

  if (is_log == false)
  {
    hc_thread_mutex_unlock (event_ctx->mux_event);
  }

  // add more back logs in case user wants to access them

  if (is_log == false)
  {
    for (int i = MAX_OLD_EVENTS - 1; i >= 1; i--)
    {
      memcpy (event_ctx->old_buf[i], event_ctx->old_buf[i - 1], event_ctx->old_len[i - 1]);

      event_ctx->old_len[i] = event_ctx->old_len[i - 1];
    }

    if (buf)
    {
      memcpy (event_ctx->old_buf[0], buf, len);
    }

    event_ctx->old_len[0] = len;
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

  memset (event_ctx, 0, sizeof (event_ctx_t));

  hc_thread_mutex_init (event_ctx->mux_event);

  return 0;
}

void event_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_delete (event_ctx->mux_event);
}
