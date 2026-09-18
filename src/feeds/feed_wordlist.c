/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The wordlist feed, which is attack mode 0 with a feed in front of it. Everything it does is in
// wordlist.c, because a feed that reads a wordlist and then does something else with the words wants
// the same reader. What is left here is the plugin itself: its context, and the eight entry points
// that find that context and hand it over.

#include "wordlist.c"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = hcmalloc (sizeof (feed_global_t));

  global_ctx->gbldata = feed_global;

  if (global_ctx->workc < 2)
  {
    error_set (global_ctx, "Invalid parameter count: %d. Count must be at least 2.", global_ctx->workc);

    return false;
  }

  // Every argument after the plugin name is a wordlist or a directory of them.

  const bool rc = wordlist_init (global_ctx, feed_global, 1, global_ctx->workc);

  return rc;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  if (feed_global == NULL) return;

  wordlist_term (global_ctx, feed_global);

  hcfree (feed_global);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  const u64 keyspace = wordlist_keyspace (global_ctx, thread_ctx[0], hashcat_ctx, global_ctx->gbldata);

  return keyspace;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  feed_thread_t *feed_thread = wordlist_thread_init (thread_ctx);

  if (feed_thread == NULL) return false;

  thread_ctx->thrdata = feed_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  wordlist_thread_term (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  const int word_len = wordlist_next (global_ctx, global_ctx->gbldata, thread_ctx, thread_ctx->thrdata, out_buf, out_size);

  return word_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  const bool rc = wordlist_seek (global_ctx->gbldata, thread_ctx, thread_ctx->thrdata, offset);

  return rc;
}
