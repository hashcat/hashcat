/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Producing candidates from a mask, for the feeds that want one. Every feed that takes a mask wants
// all of it, so it is a file a feed includes rather than a plugin of its own, the same way
// wordlist.c is.
//
// THE MASK IS NOT PARSED HERE. hashcat's own mask processor parses it, applies the custom charsets,
// builds the Markov tables and sizes the keyspace, exactly as it does for a brute force attack, and
// what is left for a feed is the one call that turns a position into a candidate. Writing a second
// mask parser would mean --increment, mask files, --markov-*, -1 through -8 and --hex-charset all had
// to be taught to it, and the two would then disagree about what a mask means.
//
// So this is a reader over state the core owns, the way wordlist.c is a reader over files on disk.
// What it adds is the part a plugin cannot reach for itself: which mask this round is walking, how
// long its candidates are, and where the word markers sit in it.
//
// A mask is the easiest thing in hashcat to seek. Candidate number N is a pure function of N, so
// seek () is an assignment: no replay, no rewind, and no state to rebuild.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "mpsp.h"
#include "feed.h"
#include "feed_error.h"

// What a feed keeps for the whole run. The mask tables belong to the core and are re-made per round,
// so nothing is cached here: holding a pointer to them would go stale the first time --increment or a
// mask file moved the queue on.

typedef struct mask_feed_global
{
  hashcat_ctx_t *hashcat_ctx;

} mask_feed_global_t;

// One position in the mask. A feed that only walks the mask counts candidates with it; one that
// amplifies a base word with it counts amplifier slots.

typedef struct mask_feed_thread
{
  u64 pos;

} mask_feed_thread_t;

MAYBE_UNUSED static bool mask_feed_init (generic_global_ctx_t *global_ctx, mask_feed_global_t *mask_global, hashcat_ctx_t *hashcat_ctx)
{
  mask_global->hashcat_ctx = hashcat_ctx;

  if (hashcat_ctx->mask_ctx == NULL)
  {
    error_set (global_ctx, "the mask processor is not initialised");

    return false;
  }

  // A mask reaches the mask processor from the attack mode on the command line, and only the modes
  // that take a mask put one there. Named as a plugin on its own there is nothing to walk, and the
  // keyspace is zero, which ends the run with no candidates, no message and a success status.

  if (mask_is_feed (hashcat_ctx->user_options) == false)
  {
    error_set (global_ctx, "this feed is the mask processor that -a 3 and the hybrid modes run on when they are given rules, and it has no mask of its own. Use -a 3 with a mask instead");

    return false;
  }

  return true;
}

MAYBE_UNUSED static void mask_feed_term (mask_feed_global_t *mask_global)
{
  mask_global->hashcat_ctx = NULL;
}

// The mask this round is walking. It is read at the moment it is used rather than cached, because a
// queue built by --increment or read from a mask file is a different mask per round and
// mask_ctx_update_loop () is what moves that queue on.

MAYBE_UNUSED static const mask_ctx_t *mask_feed_ctx (const mask_feed_global_t *mask_global)
{
  if (mask_global->hashcat_ctx == NULL) return NULL;

  return mask_global->hashcat_ctx->mask_ctx;
}

// How many values this round's mask holds. Sized by the mask processor when it built the tables, so
// a feed asking before the first round gets 0 and has to ask again.

MAYBE_UNUSED static u64 mask_feed_keyspace (const mask_feed_global_t *mask_global)
{
  const mask_ctx_t *mask_ctx = mask_feed_ctx (mask_global);

  if (mask_ctx == NULL) return 0;

  return mask_ctx->feed_keyspace;
}

// How long one mask value is. Every value of a mask is the same length, which is what makes a mask
// cheap to walk and is why a mask attack has no length rejects.

MAYBE_UNUSED static u32 mask_feed_length (const mask_feed_global_t *mask_global)
{
  const mask_ctx_t *mask_ctx = mask_feed_ctx (mask_global);

  if (mask_ctx == NULL) return 0;

  return mask_ctx->css_cnt;
}

// Whether the mask names a second word. A ?q is a word from another wordlist, so a feed that sees one
// has a second source to read and an amplifier position that covers both.

MAYBE_UNUSED static bool mask_feed_has_q (const mask_feed_global_t *mask_global)
{
  const mask_ctx_t *mask_ctx = mask_feed_ctx (mask_global);

  if (mask_ctx == NULL) return false;

  return mask_ctx->has_q;
}

// The mask value at one position, whole. It is cut at the markers by mask_feed_assemble () rather
// than here, because the pieces are only meaningful once there is a word to put between them.

MAYBE_UNUSED static int mask_feed_value (const mask_feed_global_t *mask_global, const u64 pos, char *mask_buf, const int mask_size)
{
  const mask_ctx_t *mask_ctx = mask_feed_ctx (mask_global);

  if (mask_ctx == NULL) return -1;

  const int mask_len = (int) mask_ctx->css_cnt;

  if (mask_len > mask_size) return -1;

  sp_exec (pos, mask_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);

  return mask_len;
}

// Put one candidate together out of the mask, a base word and, where the mask names one, a second
// word. The mask is cut at its ?w and ?q, so the five pieces are what the markers say they are, and
// any of them is allowed to be empty.
//
// hybrid_assemble () is the core's own, and it is used here rather than copied so that a feed and the
// attack it replaces can never disagree about what a candidate looks like.

MAYBE_UNUSED static int mask_feed_assemble (const mask_feed_global_t *mask_global, u8 *out_buf, const int out_size, const char *mask_buf, const u8 *base_buf, const u32 base_len, const u8 *word_buf, const u32 word_len)
{
  const mask_ctx_t *mask_ctx = mask_feed_ctx (mask_global);

  if (mask_ctx == NULL) return -1;

  // Refused rather than cut. hybrid_assemble () stops at PW_MAX and says nothing, and half a
  // candidate hashes to nothing: it would be written to the potfile as though it were the password.

  const u64 want = (u64) mask_ctx->css_cnt + base_len + word_len;

  if (want > (u64) out_size) return -1;

  const int out_len = (int) hybrid_assemble (mask_global->hashcat_ctx, out_buf, mask_buf, base_buf, base_len, word_buf, word_len);

  return out_len;
}

MAYBE_UNUSED static mask_feed_thread_t *mask_feed_thread_init (generic_thread_ctx_t *thread_ctx)
{
  mask_feed_thread_t *mask_thread = hcmalloc (sizeof (mask_feed_thread_t));

  if (mask_thread == NULL)
  {
    thread_error_set (thread_ctx, "hcmalloc failed");

    return NULL;
  }

  mask_thread->pos = 0;

  return mask_thread;
}

MAYBE_UNUSED static void mask_feed_thread_term (mask_feed_thread_t *mask_thread)
{
  hcfree (mask_thread);
}

// One candidate, for a feed whose whole attack is the mask. A feed that amplifies a base word with
// the mask does not come through here: it holds its own position and calls mask_feed_value ().

MAYBE_UNUSED static int mask_feed_next (const mask_feed_global_t *mask_global, generic_thread_ctx_t *thread_ctx, mask_feed_thread_t *mask_thread, u8 *out_buf, const int out_size)
{
  if (mask_feed_ctx (mask_global) == NULL)
  {
    thread_error_set (thread_ctx, "the mask processor is not initialised");

    return GENERIC_RC_ERROR;
  }

  if (mask_thread->pos >= mask_feed_keyspace (mask_global)) return GENERIC_RC_EOF;

  const int out_len = mask_feed_value (mask_global, mask_thread->pos, (char *) out_buf, out_size);

  if (out_len < 0)
  {
    thread_error_set (thread_ctx, "the mask is longer than the candidate buffer");

    return GENERIC_RC_ERROR;
  }

  mask_thread->pos++;

  return out_len;
}

MAYBE_UNUSED static bool mask_feed_seek (mask_feed_thread_t *mask_thread, const u64 offset)
{
  mask_thread->pos = offset;

  return true;
}
