/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The mask feed, which is attack mode 3 with a feed in front of it. Everything it does is in mask.c,
// because a feed that walks a mask and then does something else with the values wants the same
// reader. What is left here is the plugin itself: its context, and the eight entry points that find
// that context and hand it over.
//
// Why a mask attack becomes a feed at all: no kernel both walks a mask and applies a rule, so -a 3
// given rules has to produce its candidates somewhere else. A feed that is given rules gives up its
// own device kernel and its candidates become the base words the rule engine amplifies, which is the
// arrangement -a 4, -a 5 and -a 8 already run under.

#include "mask.c"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// No options. AUTOHEX and ICONV are for a feed that reads lines someone else wrote, and a mask
// produces its own bytes. RULES would have the core apply -j on top of a finished candidate, which
// is not what -j means.

const int GENERIC_PLUGIN_OPTIONS = 0 | GENERIC_PLUGIN_OPTIONS_MASK;

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  mask_feed_global_t *mask_global = hcmalloc (sizeof (mask_feed_global_t));

  global_ctx->gbldata = mask_global;

  if (mask_feed_init (global_ctx, mask_global, hashcat_ctx) == false) return false;

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  mask_feed_global_t *mask_global = global_ctx->gbldata;

  if (mask_global == NULL) return;

  mask_feed_term (mask_global);

  hcfree (mask_global);

  global_ctx->gbldata = NULL;
}

// The 128-bit forms, because a mask can pass 2^64. -a 3 without rules takes one up to 2^128, and the
// same mask given rules comes here.

u128 global_keyspace_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  const u128 keyspace = mask_feed_keyspace (global_ctx->gbldata);

  return keyspace;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  mask_feed_thread_t *mask_thread = mask_feed_thread_init (thread_ctx);

  if (mask_thread == NULL) return false;

  thread_ctx->thrdata = mask_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  mask_feed_thread_term (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  const int out_len = mask_feed_next (global_ctx->gbldata, thread_ctx, thread_ctx->thrdata, out_buf, out_size);

  return out_len;
}

bool thread_seek_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u128 offset)
{
  const bool rc = mask_feed_seek (thread_ctx->thrdata, offset);

  return rc;
}
