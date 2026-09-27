/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "thread.h"
#include "event.h"

#include <stdarg.h>

#ifndef __MINGW_PRINTF_FORMAT
#define __MINGW_PRINTF_FORMAT printf
#endif

void event_call (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  bool is_log = false;

  switch (id)
  {
    case EVENT_LOG_INFO:    is_log = true; break;
    case EVENT_LOG_WARNING: is_log = true; break;
    case EVENT_LOG_ERROR:   is_log = true; break;
    case EVENT_LOG_ADVICE:  is_log = true; break;
  }

  if (is_log == true)
  {
    event_ctx->log_cnt++;

    event_ctx->log_blank = (event_ctx->msg_len == 0) && (event_ctx->msg_newline == true);
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

}

__attribute__ ((format (__MINGW_PRINTF_FORMAT, 1, 0)))
static int event_log (const char *fmt, va_list ap, char *s, const size_t sz)
{
  size_t length;

  length = vsnprintf (s, sz, fmt, ap);
  length = MIN (length, sz);

  s[length] = 0;

  return (int) length;
}

size_t event_log_advice_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_ADVICE, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_info_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_INFO, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_warning_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_WARNING, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_error_nn (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = false;

  event_call (EVENT_LOG_ERROR, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_advice (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_ADVICE, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_info (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_LARGE - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_INFO, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_warning (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_WARNING, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

size_t event_log_error (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_lock (event_ctx->mux_log);

  if (fmt == NULL)
  {
    event_ctx->msg_buf[0] = 0;

    event_ctx->msg_len = 0;
  }
  else
  {
    va_list ap;

    va_start (ap, fmt);

    event_ctx->msg_len = event_log (fmt, ap, event_ctx->msg_buf, HCBUFSIZ_SMALL - 1);

    va_end (ap);
  }

  event_ctx->msg_newline = true;

  event_call (EVENT_LOG_ERROR, hashcat_ctx, NULL, 0);

  const size_t msg_len = event_ctx->msg_len;

  hc_thread_mutex_unlock (event_ctx->mux_log);

  return msg_len;
}

int event_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  memset (event_ctx, 0, sizeof (event_ctx_t));

  hc_thread_mutex_init (event_ctx->mux_event);
  hc_thread_mutex_init (event_ctx->mux_log);

  return 0;
}

void event_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  hc_thread_mutex_delete (event_ctx->mux_log);
  hc_thread_mutex_delete (event_ctx->mux_event);
}

// How many lines have been logged so far. Take it before and after somebody else's work and the
// difference is how much that work had to say, which is the only way to know whether a block of
// output needs a blank line after it or would be adding a stray one.

u64 event_log_count (const hashcat_ctx_t *hashcat_ctx)
{
  const event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  return event_ctx->log_cnt;
}

// Whether the last line logged was a blank one. A caller adding a separator after somebody else's
// output asks this so as not to add a second one after output that already ended in its own.

bool event_log_last_blank (const hashcat_ctx_t *hashcat_ctx)
{
  const event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  return event_ctx->log_blank;
}
