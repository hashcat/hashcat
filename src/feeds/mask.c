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

// A MASK AS A FILTER RATHER THAN AS A SOURCE
//
// A feed can also be handed a mask to select by, which is the shape of what the user already knows
// about one password. The mask processor still parses it, so the section above and this one differ
// only in what the parsed mask is for: there it names every candidate in turn, here it says which
// candidates a feed's own generator is allowed to keep.
//
// The charsets arrive as lists of characters, and a list is the wrong shape for a question asked once
// per byte of every candidate: ?a is 95 entries to walk. So they are turned into one bit per byte per
// position, and everything below is a bit test.

#define MASK_CSS_MAXPOS 256

// The case mapping a feed uses on its own terminals. A generator that stores a word in one case and a
// capitalisation beside it decides per character which of the two the candidate carries, so the table
// below has to be built with the same mapping that generator applies, and not with an assumption about
// which bytes are letters. Passing it in is what keeps a single byte code page working: the feed knows
// that 0xe4 has a capital and this file does not.

typedef u8 (*mask_css_upper_t) (const u8 chr);

typedef struct mask_css
{
  u32 cnt;

  // The bytes the position admits. A candidate byte is tested against this one directly, and so is a
  // stored byte that the capitalisation leaves alone.

  u32 any[MASK_CSS_MAXPOS][8];

  // The stored bytes whose capital the position admits, which is the preimage of any under the feed's
  // own mapping. A capitalisation that puts a U at this character may only spell one of these.

  u32 up[MASK_CSS_MAXPOS][8];

  // Whether the position admits any stored byte at all, and any capitalised one, and whether the two
  // sets differ. The last is what decides whether the case a capitalisation puts here changes which
  // letters are left, which is the only thing a group of capitalisations has to agree on.

  bool has_any[MASK_CSS_MAXPOS];
  bool has_up[MASK_CSS_MAXPOS];
  bool amb[MASK_CSS_MAXPOS];

} mask_css_t;

MAYBE_UNUSED static void mask_css_set (u32 *bits, const u8 chr)
{
  bits[chr / 32] |= 1u << (chr % 32);
}

MAYBE_UNUSED static bool mask_css_get (const u32 *bits, const u8 chr)
{
  const bool hit = ((bits[chr / 32] & (1u << (chr % 32))) != 0);

  return hit;
}

// Every position of the mask, as two sets of bytes and three answers about them. Called once per run,
// so it walks all 256 bytes rather than being clever about it.

MAYBE_UNUSED static bool mask_css_build (mask_css_t *m, const cs_t *css_buf, const u32 css_cnt, const mask_css_upper_t upper, const bool pt_upper)
{
  // Shortening the mask here would leave the feed holding a length the user never wrote, and every
  // candidate of the length they did write would then be refused.

  if (css_cnt > MASK_CSS_MAXPOS) return false;

  memset (m, 0, sizeof (mask_css_t));

  m->cnt = css_cnt;

  for (u32 pos = 0; pos < m->cnt; pos++)
  {
    // The charset as the mask processor handed it over, which is what the candidate is measured against.

    u32 raw[8];

    memset (raw, 0, sizeof (raw));

    const cs_t *cs = &css_buf[pos];

    for (u32 i = 0; i < cs->cs_len; i++)
    {
      mask_css_set (raw, (u8) (cs->cs_buf[i] & 0xff));
    }

    // A hash mode that takes uppercase plaintext only sees the candidate capitalised, and the mask
    // processor has already capitalised the charset to match. So the byte a feed produces is admitted
    // when its capital is in the charset, and every position of such a mask takes both cases of a
    // letter. Without this a lowercase terminal is measured against an uppercase charset and the whole
    // grammar is filtered away.

    for (u32 b = 0; b < 256; b++)
    {
      const u8 chr = (u8) b;

      if (mask_css_get (raw, (pt_upper == true) ? upper (chr) : chr) == true) mask_css_set (m->any[pos], chr);

      if (mask_css_get (raw, upper (chr)) == true) mask_css_set (m->up[pos], chr);
    }

    for (u32 w = 0; w < 8; w++)
    {
      if (m->any[pos][w] != 0) m->has_any[pos] = true;
      if (m->up[pos][w]  != 0) m->has_up[pos]  = true;

      if (m->any[pos][w] != m->up[pos][w]) m->amb[pos] = true;
    }
  }

  return true;
}

// Whether the mask says nothing at all about a stretch of positions, which is every byte admitted at every
// one of them. A slot the mask does not constrain needs no filtering, so nothing about how its terminals
// are encoded has to be worked out either.

MAYBE_UNUSED static bool mask_css_open (const mask_css_t *m, const u32 off, const u32 len)
{
  if ((off + len) > m->cnt) return false;

  for (u32 i = 0; i < len; i++)
  {
    for (u32 w = 0; w < 8; w++)
    {
      if (m->any[off + i][w] != 0xffffffff) return false;
    }
  }

  return true;
}

// Whether the mask admits a byte no single byte character set has a letter at. A generator that stores a
// character in more than one byte cannot be filtered per byte, and where the answer here is false it does
// not have to be: such a character always carries a lead byte above 0x7e, which the mask never takes.

MAYBE_UNUSED static bool mask_css_high (const mask_css_t *m)
{
  for (u32 pos = 0; pos < m->cnt; pos++)
  {
    for (u32 b = 0x80; b < 256; b++)
    {
      if (mask_css_get (m->any[pos], (u8) b) == true) return true;
    }
  }

  return false;
}

MAYBE_UNUSED static bool mask_css_allows (const mask_css_t *m, const u32 pos, const u8 chr)
{
  if (pos >= m->cnt) return false;

  const bool ok = mask_css_get (m->any[pos], chr);

  return ok;
}

// Whether this position takes the stored byte as it stands, and whether it takes its capital. Both
// false means the position admits no letter at all, which rules it out for a letter run before any
// word is looked at.

MAYBE_UNUSED static bool mask_css_takes_lower (const mask_css_t *m, const u32 pos, const u8 stored)
{
  if (pos >= m->cnt) return false;

  const bool ok = mask_css_get (m->any[pos], stored);

  return ok;
}

MAYBE_UNUSED static bool mask_css_takes_upper (const mask_css_t *m, const u32 pos, const u8 stored)
{
  if (pos >= m->cnt) return false;

  const bool ok = mask_css_get (m->up[pos], stored);

  return ok;
}

MAYBE_UNUSED static bool mask_css_any_lower (const mask_css_t *m, const u32 pos)
{
  if (pos >= m->cnt) return false;

  return m->has_any[pos];
}

MAYBE_UNUSED static bool mask_css_any_upper (const mask_css_t *m, const u32 pos)
{
  if (pos >= m->cnt) return false;

  return m->has_up[pos];
}

// Whether the case a capitalisation puts at this position changes which stored bytes are left. Where it
// does not, a group of capitalisations does not have to agree about it.

MAYBE_UNUSED static bool mask_css_ambiguous (const mask_css_t *m, const u32 pos)
{
  if (pos >= m->cnt) return false;

  return m->amb[pos];
}
