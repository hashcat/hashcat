/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A feed hashes the account names it was given to name the seek database that belongs to them. That
// is the feed's own business and not something the core promises, so xxHash is compiled into this
// plugin rather than resolved out of the library.

#define XXH_INLINE_ALL

#include "xxhash.h"

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "generic.h"
#include "hlfmt.h"
#include "rp.h"
#include "rp_cpu.h"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// Rules are the whole point of this feed. A username is a hint rather than a password, so what turns it
// into a candidate is the rule engine applied to it.
//
// Nothing is read off a disk here, the words are already in memory in the form the hash file parser left
// them, so there is no encoding pass for --hex-wordlist or --encoding-from to make.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_RULES;

typedef struct feed_global
{
  // The account names the hash file parser split off, kept per hash and in the order the hashes ended up
  // in. The pairing -a 9 makes is word N with hash N, so a line that failed to parse is not a hash and
  // has no word here either, and nothing has to count which lines were dropped.

  hashinfo_t **hash_info;

  u64 words_cnt;

  // Which word of the account name this instance is for. Every word is its own round over the same
  // hashes, and this is the round.

  u32 round;

} feed_global_t;

typedef struct feed_thread
{
  u64 pos;

} feed_thread_t;

static void error_set (generic_global_ctx_t *global_ctx, const char *fmt, ...)
{
  global_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (global_ctx->error_msg, sizeof (global_ctx->error_msg), fmt, ap);

  va_end (ap);
}

static void thread_error_set (generic_thread_ctx_t *thread_ctx, const char *fmt, ...)
{
  thread_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), fmt, ap);

  va_end (ap);
}

static const char *const ASSOCIATION_PAD_RULE[] = ASSOCIATION_PAD_RULES;

/**
 * interface
 */

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = hcmalloc (sizeof (feed_global_t));

  global_ctx->gbldata = feed_global;

  // An account name becomes several words, and each of them is its own round over the same hashes. The
  // round this instance is for is the one argument this feed takes, because that is how hashcat names a
  // source: the wordlist feed is given a path and this one is given a number.

  if (global_ctx->workc != 2)
  {
    error_set (global_ctx, "Invalid parameter count: %d. Count must be 2.", global_ctx->workc);

    return false;
  }

  feed_global->round = (u32) atoll (global_ctx->workv[1]);

  const hashes_t *hashes = hashcat_ctx->hashes;

  // The account names are only kept when the hash file was read as username plus hash, which is exactly
  // what this feed is for, so hashcat turns that on for it. Reaching here without them means something
  // opened this feed for an attack that is not the one it belongs to.

  if (hashes->hash_info == NULL)
  {
    error_set (global_ctx, "Hash file was not read as username and hash, so there are no words to feed.");

    return false;
  }

  feed_global->hash_info = hashes->hash_info;
  feed_global->words_cnt = hashes->digests_cnt;

  for (u64 i = 0; i < feed_global->words_cnt; i++)
  {
    const user_t *user = feed_global->hash_info[i]->user;

    if (user == NULL) continue;

    global_ctx->source_ident = XXH64 (user->user_name, user->user_len, global_ctx->source_ident);
  }

  // Say what the candidates are and where they came from. "Feed (wordlist.txt)" is enough for a feed
  // reading a wordlist, because a wordlist holds candidates. This one holds hashes, and the candidates
  // are cut out of the account names in front of them, so the file name on its own would read as though
  // hashcat were trying the hashes.
  //
  // Which word of the account name this round is trying is not said here. Each word is a round, so it is
  // the queue position, and Guess.Queue is where hashcat says that for every other attack that is really
  // a queue of rounds.

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "account names in %s", hashes->hashfile);

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  if (feed_global == NULL) return;

  // The words are cut out of the account names, which belong to the hash list and outlive this feed, so
  // there is nothing of theirs to free either.

  hcfree (feed_global);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  return feed_global->words_cnt;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  feed_thread_t *feed_thread = hcmalloc (sizeof (feed_thread_t));

  if (feed_thread == NULL)
  {
    thread_error_set (thread_ctx, "hcmalloc failed");

    return false;
  }

  feed_thread->pos = 0;

  thread_ctx->thrdata = feed_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  feed_thread_t *feed_thread = thread_ctx->thrdata;

  if (feed_thread == NULL) return;

  hcfree (feed_thread);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  feed_thread_t *feed_thread = thread_ctx->thrdata;

  if (feed_thread->pos >= feed_global->words_cnt) return GENERIC_RC_EOF;

  const user_t *user = feed_global->hash_info[feed_thread->pos]->user;

  feed_thread->pos++;

  // A line with nothing in front of the separator has no account name and so no word. That is a
  // candidate of length zero, which hashcat takes the same way it takes one out of a wordlist, and it
  // keeps this feed's position lined up with the hash list.

  if (user == NULL) return 0;

  // Cut here rather than once at startup because the words are cheap to cut and keeping them for every
  // account would cost more memory than the hash list itself on a large file.

  hlfmt_word_t words[ASSOCIATION_WORDS_MAX];

  const u32 words_cnt = hlfmt_user_words (user->user_name, user->user_len, words, ASSOCIATION_WORDS_MAX);

  if (words_cnt == 0) return 0;

  // hashcat hands out a pointer into the buffer it uploads, so there is no room past out_size. Write no
  // more than that and still report the real length, the same way the wordlist feed does.

  if (feed_global->round < words_cnt)
  {
    const int word_len = (int) words[feed_global->round].len;

    const int copy_len = MIN (word_len, out_size);

    memcpy (out_buf, words[feed_global->round].buf, (size_t) copy_len);

    return word_len;
  }

  // This account has run out of words of its own, and the round is already paid for by the account with
  // the most. So it is spent on a rule applied to one of this account's words instead of on repeating
  // one. Rules move slower than words, so every word is tried with a rule before the next rule starts.

  const u32 slot = feed_global->round - words_cnt;

  const u32 rule_idx = slot / words_cnt;
  const u32 word_idx = slot % words_cnt;

  if (rule_idx >= (sizeof (ASSOCIATION_PAD_RULE) / sizeof (ASSOCIATION_PAD_RULE[0]))) return 0;

  const char *rule = ASSOCIATION_PAD_RULE[rule_idx];

  char rule_in[RP_PASSWORD_SIZE];
  char rule_out[RP_PASSWORD_SIZE];

  const int in_len = (int) MIN (words[word_idx].len, RP_PASSWORD_SIZE);

  memcpy (rule_in, words[word_idx].buf, (size_t) in_len);

  const int out_len = _old_apply_rule (rule, (int) strlen (rule), rule_in, in_len, rule_out);

  // A rule that rejects this word leaves the round with nothing to try for this account, which is a
  // candidate of length zero rather than a reason to stop.

  if (out_len < 0) return 0;

  const int copy_len = MIN (out_len, out_size);

  memcpy (out_buf, rule_out, (size_t) copy_len);

  return out_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  if (offset >= feed_global->words_cnt)
  {
    thread_error_set (thread_ctx, "seek target past EOF: %zu", (size_t) offset);

    return false;
  }

  feed_thread_t *feed_thread = thread_ctx->thrdata;

  feed_thread->pos = offset;

  return true;
}
