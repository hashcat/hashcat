/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The hybrid feed, which is attack modes 1, 6, 7 and 12 with a feed in front of them. It reads its
// words with wordlist.c and its mask with mask.c, the same two files feed_wordlist.c and feed_mask.c
// use, so a candidate it builds is built out of the same parts as the attack it replaces.
//
// Why these modes become a feed: no kernel both joins two pieces of a candidate and applies a rule
// to the result, so -a 1, -a 6, -a 7 and -a 12 given rules have to produce their candidates
// somewhere else. A feed that is given rules gives up its own device kernel and its candidates
// become the base words the rule engine amplifies. Without rules none of this happens and the
// attack runs on the device exactly as it always did.
//
// WHAT A POSITION MEANS HERE. One candidate is a base word, a mask value and, where the mask has a
// ?q, a second word. The two amplifying parts are counted as one amplifier the way the combinator
// counts them, so a position divides three ways:
//
//   combs    = mask values * words in the ?q wordlist, or just the mask values with no ?q
//   base     = pos / combs
//   mask     = (pos % combs) / words2
//   word     = (pos % combs) % words2
//
// which is the same arithmetic slow_candidates.c uses for the same four attack modes, and the same
// order, so the two producers walk the keyspace identically.
//
// -j AND -k ARE APPLIED HERE, to the two words, before they are joined. That is what they mean: -j
// is the base word's rule and -k the amplifier word's, and neither has ever applied to a mask. The
// feed declares no GENERIC_PLUGIN_OPTIONS_RULES so that hashcat does not apply -j a second time, on
// top of a candidate that is already assembled, which would be a different attack.

#include "wordlist.c"
#include "mask.c"

#include "rp.h"
#include "rp_cpu.h"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// No options, and each for its own reason. AUTOHEX and ICONV would have hashcat apply them to the
// finished candidate, where they belong to the words that went into it. RULES would have it apply
// -j there too. All three are done below instead, to the halves.

const int GENERIC_PLUGIN_OPTIONS = 0 | GENERIC_PLUGIN_OPTIONS_MASK;

typedef struct hybrid_global
{
  mask_feed_global_t mask;

  // The word the ?w names, and the word the ?q names. Two readers, because they are two positions in
  // two files and each has its own line to be on.

  feed_global_t base;
  feed_global_t amp;

  bool has_q;

  u64 base_cnt;
  u64 amp_cnt;                 // 1 with no ?q, so that the arithmetic above needs no second form

  // -j and -k, held rather than looked up per candidate

  const char *rule_base;
  int         rule_base_len;

  const char *rule_amp;
  int         rule_amp_len;

} hybrid_global_t;

typedef struct hybrid_thread
{
  feed_thread_t *base;
  feed_thread_t *amp;

  // Where this thread is, and whether it has been put there yet. A chunk begins with a seek and is
  // read forward from it, so the walk below is what runs and the seek is rare.

  bool placed;
  u64  pos;

  u64  mask_pos;
  u64  word_idx;

  // The base word this block of candidates shares, already through -j. It is fetched once per block
  // rather than once per candidate, which is the whole reason a base word is worth being a base word.

  u8   base_buf[PW_MAX];
  u32  base_len;
  bool base_usable;

  char mask_buf[SP_PW_MAX];

  u8   word_buf[PW_MAX];
  u32  word_len;

} hybrid_thread_t;

// One rule over one word, which is what pw_transform_apply () does for the producers inside the
// core. Spelled out here because a plugin cannot reach that one, and kept to the same two calls so
// that a rule cannot mean one thing in a feed and another in the attack it replaces.

static int hybrid_rule (const char *rule_buf, const int rule_len, u8 *buf, const int len, const int buf_size)
{
  if (run_rule_engine (rule_len, rule_buf) == 0) return len;

  if (len >= RP_PASSWORD_SIZE) return -1;

  char rule_buf_out[RP_PASSWORD_SIZE];

  const int out_len = _old_apply_rule (rule_buf, rule_len, (char *) buf, len, rule_buf_out);

  if (out_len < 0) return -1;

  if (out_len > buf_size) return -1;

  memcpy (buf, rule_buf_out, (size_t) out_len);

  return out_len;
}

// Pull the base word at base_idx and put -j on it. A word the rule throws away leaves the block it
// heads unusable rather than being replaced, because the position it occupies is still spent: that
// is what keeps --skip, --restore and the brain counting the same candidates on every run.

static bool hybrid_base_fetch (hybrid_global_t *hybrid_global, generic_thread_ctx_t *thread_ctx, hybrid_thread_t *hybrid_thread, const u64 base_idx)
{
  hybrid_thread->base_usable = false;
  hybrid_thread->base_len    = 0;

  // Past the last base word is the end of the attack rather than a failure of it. The caller says so
  // by the position it reached, so this leaves the block unusable and lets the end of keyspace test
  // in thread_next () be the one place that decides a run is over.

  if (base_idx >= hybrid_global->base_cnt) return true;

  if (wordlist_seek (&hybrid_global->base, thread_ctx, hybrid_thread->base, base_idx) == false) return false;

  const int base_len = wordlist_next (NULL, &hybrid_global->base, thread_ctx, hybrid_thread->base, hybrid_thread->base_buf, PW_MAX);

  if (base_len < 0) return true;

  const int ruled_len = hybrid_rule (hybrid_global->rule_base, hybrid_global->rule_base_len, hybrid_thread->base_buf, base_len, PW_MAX);

  if (ruled_len < 0) return true;

  hybrid_thread->base_len    = (u32) ruled_len;
  hybrid_thread->base_usable = true;

  return true;
}

// Put the thread at a position. Everything it needs is a function of that position, so this is three
// divisions and two seeks, and it happens once per chunk rather than once per candidate.

static bool hybrid_place (hybrid_global_t *hybrid_global, generic_thread_ctx_t *thread_ctx, hybrid_thread_t *hybrid_thread, const u64 pos)
{
  const u64 mask_cnt = mask_feed_keyspace (&hybrid_global->mask);

  if (mask_cnt == 0) return false;

  const u64 combs = mask_cnt * hybrid_global->amp_cnt;

  const u64 base_idx = pos / combs;
  const u64 comb_idx = pos % combs;

  hybrid_thread->mask_pos = comb_idx / hybrid_global->amp_cnt;
  hybrid_thread->word_idx = comb_idx % hybrid_global->amp_cnt;

  if (hybrid_base_fetch (hybrid_global, thread_ctx, hybrid_thread, base_idx) == false) return false;

  if (hybrid_global->has_q == true)
  {
    if (wordlist_seek (&hybrid_global->amp, thread_ctx, hybrid_thread->amp, hybrid_thread->word_idx) == false) return false;
  }

  hybrid_thread->pos    = pos;
  hybrid_thread->placed = true;

  return true;
}

// Step one candidate on. The ?q word runs fastest, then the mask, then the base word, which is the
// order the amplifier position was divided in and the order the device combinator walks.

static bool hybrid_advance (hybrid_global_t *hybrid_global, generic_thread_ctx_t *thread_ctx, hybrid_thread_t *hybrid_thread)
{
  hybrid_thread->pos++;

  hybrid_thread->word_idx++;

  if (hybrid_thread->word_idx < hybrid_global->amp_cnt) return true;

  hybrid_thread->word_idx = 0;

  // Back to the first word of the ?q wordlist for the next mask value. Said rather than left to
  // wherever the reader stopped, which is the same thing the core's own rewind does.

  if (hybrid_global->has_q == true)
  {
    if (wordlist_seek (&hybrid_global->amp, thread_ctx, hybrid_thread->amp, 0) == false) return false;
  }

  hybrid_thread->mask_pos++;

  if (hybrid_thread->mask_pos < mask_feed_keyspace (&hybrid_global->mask)) return true;

  hybrid_thread->mask_pos = 0;

  // A whole block of candidates is done, so the next base word heads the next one. It is read
  // forward from where the last one left off rather than seeked to, which is what makes a base word
  // cheap.

  const u64 base_idx = hybrid_thread->pos / (mask_feed_keyspace (&hybrid_global->mask) * hybrid_global->amp_cnt);

  if (hybrid_base_fetch (hybrid_global, thread_ctx, hybrid_thread, base_idx) == false) return false;

  return true;
}

bool global_init (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  hybrid_global_t *hybrid_global = hcmalloc (sizeof (hybrid_global_t));

  global_ctx->gbldata = hybrid_global;

  // The feed's own name, then the mask, then one dictionary or two.

  if (global_ctx->workc < 3)
  {
    error_set (global_ctx, "Invalid parameter count: %d. Count must be at least 3.", global_ctx->workc);

    return false;
  }

  if (mask_feed_init (global_ctx, &hybrid_global->mask, hashcat_ctx) == false) return false;

  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  hybrid_global->has_q = user_options_extra->hybrid_q;

  hybrid_global->rule_base     = user_options_extra->rule_buf_base;
  hybrid_global->rule_base_len = user_options_extra->rule_len_base;

  hybrid_global->rule_amp      = user_options_extra->rule_buf_amp;
  hybrid_global->rule_amp_len  = user_options_extra->rule_len_amp;

  // With a ?q the last argument is that word's wordlist and everything between the mask and it is the
  // base. With no ?q every argument after the mask is the base, so a folder of wordlists works there
  // the way it does for -a 0.

  const int base_to = global_ctx->workc - ((hybrid_global->has_q == true) ? 1 : 0);

  if (base_to <= 2)
  {
    error_set (global_ctx, "no wordlist was given for the ?w.");

    return false;
  }

  if (wordlist_init (global_ctx, &hybrid_global->base, 2, base_to) == false) return false;

  if (hybrid_global->has_q == true)
  {
    if (wordlist_init (global_ctx, &hybrid_global->amp, base_to, global_ctx->workc) == false) return false;
  }

  // What the status line calls this attack. The mask says more than the feed's name does, and the
  // wordlists are named by the arguments the user typed, so the mask is what is worth adding.

  const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  if (mask_ctx->mask != NULL)
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", mask_ctx->mask);
  }

  return true;
}

void global_term (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  hybrid_global_t *hybrid_global = global_ctx->gbldata;

  if (hybrid_global == NULL) return;

  if (hybrid_global->has_q == true) wordlist_term (global_ctx, &hybrid_global->amp);

  wordlist_term (global_ctx, &hybrid_global->base);

  mask_feed_term (&hybrid_global->mask);

  hcfree (hybrid_global);

  global_ctx->gbldata = NULL;
}

// What this feed can count, which is the words and not the mask. A mask is sized once per round and
// this runs before the first round, so the mask is the factor straight_ctx_update_loop () supplies
// afterwards and the product of the two is the run's base.

u64 global_keyspace (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  hybrid_global_t *hybrid_global = global_ctx->gbldata;

  hybrid_global->base_cnt = wordlist_keyspace (global_ctx, thread_ctx[0], hashcat_ctx, &hybrid_global->base);

  if (hybrid_global->base_cnt == GENERIC_KEYSPACE_ERROR)   return GENERIC_KEYSPACE_ERROR;
  if (hybrid_global->base_cnt == GENERIC_KEYSPACE_UNKNOWN) return GENERIC_KEYSPACE_UNKNOWN;

  hybrid_global->amp_cnt = 1;

  if (hybrid_global->has_q == true)
  {
    hybrid_global->amp_cnt = wordlist_keyspace (global_ctx, thread_ctx[0], hashcat_ctx, &hybrid_global->amp);

    if (hybrid_global->amp_cnt == GENERIC_KEYSPACE_ERROR)   return GENERIC_KEYSPACE_ERROR;
    if (hybrid_global->amp_cnt == GENERIC_KEYSPACE_UNKNOWN) return GENERIC_KEYSPACE_UNKNOWN;

    if (hybrid_global->amp_cnt == 0)
    {
      error_set (global_ctx, "the ?q wordlist holds no words.");

      return GENERIC_KEYSPACE_ERROR;
    }
  }

  const u64 keyspace = hybrid_global->base_cnt * hybrid_global->amp_cnt;

  return keyspace;
}

bool thread_init (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  hybrid_global_t *hybrid_global = global_ctx->gbldata;

  hybrid_thread_t *hybrid_thread = hcmalloc (sizeof (hybrid_thread_t));

  if (hybrid_thread == NULL)
  {
    thread_error_set (thread_ctx, "hcmalloc failed");

    return false;
  }

  hybrid_thread->base = wordlist_thread_init (thread_ctx);

  if (hybrid_thread->base == NULL)
  {
    hcfree (hybrid_thread);

    return false;
  }

  if (hybrid_global->has_q == true)
  {
    hybrid_thread->amp = wordlist_thread_init (thread_ctx);

    if (hybrid_thread->amp == NULL)
    {
      wordlist_thread_term (hybrid_thread->base);

      hcfree (hybrid_thread);

      return false;
    }
  }

  hybrid_thread->placed = false;

  thread_ctx->thrdata = hybrid_thread;

  return true;
}

void thread_term (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  hybrid_global_t *hybrid_global = global_ctx->gbldata;

  hybrid_thread_t *hybrid_thread = thread_ctx->thrdata;

  if (hybrid_thread == NULL) return;

  if (hybrid_global->has_q == true) wordlist_thread_term (hybrid_thread->amp);

  wordlist_thread_term (hybrid_thread->base);

  hcfree (hybrid_thread);

  thread_ctx->thrdata = NULL;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  hybrid_global_t *hybrid_global = global_ctx->gbldata;

  hybrid_thread_t *hybrid_thread = thread_ctx->thrdata;

  if (hybrid_thread->placed == false)
  {
    if (hybrid_place (hybrid_global, thread_ctx, hybrid_thread, hybrid_thread->pos) == false)
    {
      thread_error_set (thread_ctx, "cannot place the producer at offset %" PRIu64, hybrid_thread->pos);

      return GENERIC_RC_ERROR;
    }
  }

  const u64 mask_cnt = mask_feed_keyspace (&hybrid_global->mask);

  if (mask_cnt == 0)
  {
    thread_error_set (thread_ctx, "the mask processor has not sized this round's mask");

    return GENERIC_RC_ERROR;
  }

  if (hybrid_thread->pos >= (hybrid_global->base_cnt * mask_cnt * hybrid_global->amp_cnt)) return GENERIC_RC_EOF;

  bool usable = hybrid_thread->base_usable;

  // The mask value this amplifier position stands for, produced whole and cut at the markers by the
  // assembly below.

  if (mask_feed_value (&hybrid_global->mask, hybrid_thread->mask_pos, hybrid_thread->mask_buf, (int) sizeof (hybrid_thread->mask_buf)) < 0)
  {
    thread_error_set (thread_ctx, "the mask is longer than the mask buffer");

    return GENERIC_RC_ERROR;
  }

  hybrid_thread->word_len = 0;

  // The second word, when the mask names one. It is consumed whatever happens to it, because the
  // amplifier is counted in words too: a word -k throws away gives up the candidate it would have
  // made rather than handing its slot to the word behind it.

  if (hybrid_global->has_q == true)
  {
    const int word_len = wordlist_next (NULL, &hybrid_global->amp, thread_ctx, hybrid_thread->amp, hybrid_thread->word_buf, PW_MAX);

    if (word_len < 0)
    {
      usable = false;
    }
    else
    {
      const int ruled_len = hybrid_rule (hybrid_global->rule_amp, hybrid_global->rule_amp_len, hybrid_thread->word_buf, word_len, PW_MAX);

      if (ruled_len < 0) usable = false;
      else               hybrid_thread->word_len = (u32) ruled_len;
    }
  }

  int out_len = GENERIC_RC_SKIP;

  if (usable == true)
  {
    out_len = mask_feed_assemble (&hybrid_global->mask, out_buf, out_size, hybrid_thread->mask_buf, hybrid_thread->base_buf, hybrid_thread->base_len, hybrid_thread->word_buf, hybrid_thread->word_len);

    if (out_len < 0) out_len = GENERIC_RC_SKIP;
  }

  if (hybrid_advance (hybrid_global, thread_ctx, hybrid_thread) == false)
  {
    thread_error_set (thread_ctx, "cannot advance the producer past offset %" PRIu64, hybrid_thread->pos);

    return GENERIC_RC_ERROR;
  }

  return out_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  hybrid_thread_t *hybrid_thread = thread_ctx->thrdata;

  // Placed on the next read rather than here, because the mask this round walks is what a position
  // divides by and a seek can arrive before the round has sized it.

  hybrid_thread->pos    = offset;
  hybrid_thread->placed = false;

  return true;
}
