/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef FEED_ERROR_H
#define FEED_ERROR_H

// How a feed says something went wrong, which is the same two lines whatever the feed reads. They
// live here rather than in one of the shared sources because a feed that includes two of those would
// otherwise get two copies of them, and a feed that includes neither would have none.

#include <stdarg.h>

// A failure in global_init (), global_term () or global_keyspace (). One feed, one message.

MAYBE_UNUSED static void error_set (generic_global_ctx_t *global_ctx, const char *fmt, ...)
{
  global_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (global_ctx->error_msg, sizeof (global_ctx->error_msg), fmt, ap);

  va_end (ap);
}

// The four per device entry points report here instead, so that one device's failure does not speak
// for the others and does not stay set for the rest of the run.

MAYBE_UNUSED static void thread_error_set (generic_thread_ctx_t *thread_ctx, const char *fmt, ...)
{
  thread_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), fmt, ap);

  va_end (ap);
}

#endif // FEED_ERROR_H
