/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A feed hashes what it enumerates so that two runs over different material are two attacks. This one
// has no file to stat, so it hashes the words themselves, and what reads that is the brain: a run over
// a second hash file must not be refused as work the first one already did. paw64 is part of what the
// core offers a plugin, so the feed calls the one in the library rather than carrying a copy of its
// own.

#include <stdarg.h>

#include "common.h"
#include "types.h"
#include "paw64.h"
#include "memory.h"
#include "shared.h"
#include "feed.h"
#include "hlfmt.h"
#include "rp.h"
#include "rp_cpu.h"
#include "filehandling.h"
#include "path.h"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// Rules are the whole point of this feed. A username is a hint rather than a password, so what turns it
// into a candidate is the rule engine applied to it.
//
// Nothing is read off a disk here, the words are already in memory in the form the hash file parser left
// them, so there is no encoding pass for --hex-wordlist or --encoding-from to make.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_RULES
                                 | GENERIC_PLUGIN_OPTIONS_EXPLAIN;

typedef struct feed_global
{
  // Kept so that a candidate can reach the fields of the hash it belongs to. The words are not cut here
  // any more: the module supplies them, because only the module can interpret its own salt and esalt,
  // and a mode carrying something better than an account name returns that instead.

  hashcat_ctx_t *hcctx;

  // The rules phase. Every rule of the list, laid end to end and indexed, and the order the
  // (hint, rule) pairs are tried in.
  //
  // Both axes are already sorted by how well they do: a rule list orders its rules by how often each
  // one won, and hlfmt_user_hints () orders an account's hints by how likely each is to be a stem. So
  // the order over the grid is a merge of the two rather than one of them nested inside the other,
  // which is what john does. Nesting spends the whole first axis before it touches the second, so the
  // first rule on the eighth hint would wait for every rule on the seven hints in front of it.
  //
  // The two axes are priced the same way, by the log of the rank, so the eighth hint costs what the
  // eighth rule costs and neither is spent before the other is touched. The one exception is the first
  // rule of the list, which is priced at zero on any hint: every hint gets it before any hint gets a second
  // rule, and in a list ordered by yield that first rule is the one that leaves the word alone.
  //
  // The schedule does not depend on the account at all, so it is one array built once and read by every
  // round.

  char *rule_buf;
  u32  *rule_off;
  u32  *rule_len;
  u32   rule_cnt;

  u32   hint_max;

  u32  *sched;
  u32   sched_cnt;

  // Whether this instance is the words phase, which has no rule list and no schedule: a round is one
  // word and the candidate is that word. Kept as a flag because thread_next () would otherwise compare
  // the phase name once per candidate.

  bool  phase_words;

  // The account names the hash file parser split off, kept per hash and in the order the hashes ended up
  // in. The pairing -a 9 makes is word N with hash N, so a line that failed to parse is not a hash and
  // has no word here either, and no count of dropped lines has to be kept.

  hashinfo_t **hash_info;

  u64 words_cnt;

  // How many rounds this phase covers. A round is "try the Nth candidate of every account name", and a
  // phase holds as many of them as that phase can produce.
  //
  // The words are written round major, every account once for round 0 and then every account again for
  // round 1, because the attack pairs word N with salt N and the salts are walked in order. So the
  // phase's keyspace is the account count times the round count, and the position inside it divides
  // into the two.

  u32 rounds_cnt;

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

// How many bits a rank is worth. The n'th of anything ranked costs log2 (n), which is what a zipf
// distribution gives. Both axes are priced by it, so where a cell sits in the schedule is the two ranks
// added: the fourth hint under the second rule costs three bits and arrives behind the tenth rule on the
// best hint, which costs three as well and holds the tie on the lower rule. The first rule is the
// exception and assoc_sched_build () covers why.

static u32 assoc_rank_cost (const u32 rank)
{
  u32 bits = 0;
  u32 n    = rank + 1;

  while (n > 1)
  {
    n = n >> 1;

    bits++;
  }

  return bits;
}

// A cell of the grid, packed so the schedule is one u32 per round. A sort key rides in front of it so
// that qsort orders by cost first, then by the rule, then by the hint.
//
// The hint index takes the low byte and the rule takes the rest, because the two axes are not alike in
// the same length: the grid is at most ASSOCIATION_WORDS_MAX wide and rulemax reaches a million. Half
// the word each looks even and is wrong, since a rule index of 65536 then wraps onto rule 0 and the
// phase applies a rule that was never requested, silently.

#define ASSOC_SCHED_HINT_BITS 8
#define ASSOC_SCHED_HINT_MAX  ((1u << ASSOC_SCHED_HINT_BITS) - 1)
#define ASSOC_SCHED_RULE_MAX  (0xffffffffu >> ASSOC_SCHED_HINT_BITS)

static int assoc_cell_cmp (const void *a, const void *b)
{
  const u64 x = *(const u64 *) a;
  const u64 y = *(const u64 *) b;

  if (x < y) return -1;
  if (x > y) return  1;

  return 0;
}

// Read a rule file into the shape the phase walks. Blank lines and comments are skipped, the same as
// hashcat's own rule reader does, and only the first rule_max survive because a list ordered by yield
// has a long tail that is not worth a round over the whole hash file.

static bool assoc_rules_load (generic_global_ctx_t *global_ctx, feed_global_t *feed_global, const char *path, const u32 rule_max)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false)
  {
    error_set (global_ctx, "%s: %s", path, strerror (errno));

    return false;
  }

  size_t cap = 1024 * 1024;
  size_t len = 0;

  char *buf = (char *) hcmalloc (cap);

  while (true)
  {
    if (len == cap)
    {
      char *nb = (char *) hcrealloc (buf, cap, cap);

      if (nb == NULL) break;

      buf = nb;
      cap = cap * 2;
    }

    const size_t got = hc_fread (buf + len, 1, cap - len, &fp);

    if (got == 0) break;
    if (got == (size_t) -1) break;

    len += got;
  }

  hc_fclose (&fp);

  if (len == 0)
  {
    hcfree (buf);

    error_set (global_ctx, "%s: holds no rules", path);

    return false;
  }

  // Each rule is terminated where its line ends, so the last one needs a byte behind it to write the
  // terminator into.

  if (len == cap)
  {
    char *nb = (char *) hcrealloc (buf, cap, 1);

    if (nb == NULL)
    {
      hcfree (buf);

      error_set (global_ctx, "%s: out of memory", path);

      return false;
    }

    buf = nb;
    cap = cap + 1;
  }

  u32 lines = 1;

  for (size_t i = 0; i < len; i++) if (buf[i] == '\n') lines++;

  feed_global->rule_buf = buf;
  feed_global->rule_off = (u32 *) hcmalloc (lines * sizeof (u32));
  feed_global->rule_len = (u32 *) hcmalloc (lines * sizeof (u32));

  size_t at = 0;

  while ((at < len) && (feed_global->rule_cnt < rule_max))
  {
    size_t end = at;

    while ((end < len) && (buf[end] != '\n')) end++;

    size_t stop = end;

    if ((stop > at) && (buf[stop - 1] == '\r')) stop--;

    const u32 rl = (u32) (stop - at);

    buf[stop] = 0;

    if ((rl > 0) && (buf[at] != '#'))
    {
      feed_global->rule_off[feed_global->rule_cnt] = (u32) at;
      feed_global->rule_len[feed_global->rule_cnt] = rl;

      feed_global->rule_cnt++;
    }

    at = end + 1;
  }

  if (feed_global->rule_cnt == 0)
  {
    error_set (global_ctx, "%s: holds no rules", path);

    return false;
  }

  return true;
}

static bool assoc_sched_build (feed_global_t *feed_global)
{
  const u64 cells = (u64) feed_global->hint_max * (u64) feed_global->rule_cnt;

  if (cells == 0) return false;
  if (cells > 0x40000000) return false;

  // Either axis running past what a cell holds would fold two rules or two hints onto one another, so
  // it is refused rather than truncated.

  if (feed_global->hint_max > ASSOC_SCHED_HINT_MAX) return false;
  if (feed_global->rule_cnt > ASSOC_SCHED_RULE_MAX) return false;

  u64 *key = (u64 *) hcmalloc ((size_t) cells * sizeof (u64));

  u64 n = 0;

  for (u32 sd = 0; sd < feed_global->hint_max; sd++)
  {
    for (u32 r = 0; r < feed_global->rule_cnt; r++)
    {
      // The first rule of the list is priced at zero on any hint, so every hint gets it before any hint gets
      // a second rule. In a list ordered by how often each rule won that first rule is the do-nothing
      // rule, which makes "every word is tried unmodified before anything is done to it" true, and that
      // sentence is the whole reason this attack has no phase of its own for trying the words. It was
      // not true: the first rule on the eighth hint sat at position 17 and the second rule on the best
      // hint at position 3, so the eighth word of a name waited behind manglings of the first.
      //
      // It costs the hint count at the front of the schedule and reorders no other cell. Eight hints and
      // a thousand rules move the eight cells to positions 0 to 7, and every cell behind them keeps the
      // position it had to within those eight.

      const u64 cost = (r == 0) ? 0 : (u64) assoc_rank_cost (sd) + assoc_rank_cost (r);

      // cost first, then the rule, then the hint, all in one integer so the sort needs no comparator
      // of its own beyond less than.

      key[n] = (cost << 48) | ((u64) r << 24) | (u64) sd;

      n++;
    }
  }

  qsort (key, (size_t) cells, sizeof (u64), assoc_cell_cmp);

  feed_global->sched = (u32 *) hcmalloc ((size_t) cells * sizeof (u32));

  for (u64 i = 0; i < cells; i++)
  {
    const u32 r  = (u32) ((key[i] >> 24) & 0xffffff);
    const u32 sd = (u32) ((key[i] >>  0) & 0xffffff);

    feed_global->sched[i] = (r << ASSOC_SCHED_HINT_BITS) | sd;
  }

  feed_global->sched_cnt = (u32) cells;

  hcfree (key);

  return true;
}

/**
 * interface
 */

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = hcmalloc (sizeof (feed_global_t));

  global_ctx->gbldata = feed_global;

  // Which phase of the attack this instance is. That is the one argument this feed takes, because that
  // is how hashcat names a source: the wordlist feed is given a path and this one is given a phase.

  if (global_ctx->workc < 2)
  {
    error_set (global_ctx, "Invalid parameter count: %d. Count must be at least 2.", global_ctx->workc);

    return false;
  }

  const char *phase = global_ctx->workv[1];

  u64 rulemax = 1000;
  u64 hints   = ASSOCIATION_WORDS_MAX;

  const char *rulefile = NULL;

  const feed_param_t params[] =
  {
    { "rulefile", FEED_PARAM_TYPE_STR, &rulefile, 0, 0, "the rule list the rules phase applies, best first" },
    { "rulemax",  FEED_PARAM_TYPE_U64, &rulemax,  1, 1000000, "how many rules of it to use" },
    { "hints",    FEED_PARAM_TYPE_U64, &hints,    1, ASSOCIATION_WORDS_MAX, "how many words of an account name to use" },
    { NULL, 0, NULL, 0, 0, NULL }
  };

  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  feed_global->hint_max = (u32) hints;

  const hashes_t *hashes = hashcat_ctx->hashes;

  feed_global->hcctx     = hashcat_ctx;
  feed_global->hash_info = hashes->hash_info;
  feed_global->words_cnt = hashes->digests_cnt;

  // How many rounds this phase needs, settled here because it is a property of the words in front of
  // the hashes and no caller outside the feed has them cut up. The names are walked once for it, which is
  // the same walk the seek database name is built in.

  u32 words_max = 0;

  for (u64 i = 0; i < feed_global->words_cnt; i++)
  {
    hlfmt_word_t words[ASSOCIATION_WORDS_MAX];

    char scratch[ASSOCIATION_HINT_SCRATCH];

    const u32 words_cnt = hlfmt_hash_hints (hashcat_ctx, i, words, ASSOCIATION_WORDS_MAX, scratch, sizeof (scratch));

    if (words_cnt > words_max) words_max = words_cnt;

    // The words themselves are what this attack enumerates, so they are what names it. Hashing the
    // account name instead would name two runs the same when the module answered with something else.

    for (u32 k = 0; k < words_cnt; k++)
    {
      global_ctx->source_ident = paw64 ((const u8 *) words[k].buf, words[k].len, global_ctx->source_ident);
    }
  }

  // Nothing to guess from. For most modes that means the hash file had no account names in front of the
  // hashes; for a mode that implements module_hash_hints itself it means the module found no field in this
  // particular hash. Naming both is what makes the message useful without knowing which mode this is.

  if (words_max == 0)
  {
    error_set (global_ctx, "Nothing is known about these hashes to guess from. This attack takes its words from the account names in front of the hashes, and from whatever the hash mode itself can tell about them.");

    return false;
  }

  // The words phase is the account's own words, one round each and unmodified. There is no
  // rule list to read and no schedule to build: round r is word r, so the round count is the width of
  // the grid and the widest account is what sets it.

  if (strcmp (phase, "words") == 0)
  {
    feed_global->phase_words = true;

    if (words_max < feed_global->hint_max) feed_global->hint_max = words_max;

    feed_global->rounds_cnt = feed_global->hint_max;
  }
  else if (strcmp (phase, "rules") == 0)
  {
    // The grid is only as wide as the widest account, because a hint slot no account can fill is a round
    // over the whole hash list that produces no candidate.

    if (words_max < feed_global->hint_max) feed_global->hint_max = words_max;

    if (rulefile == NULL)
    {
      error_set (global_ctx, "The rules phase needs a rule list.");

      return false;
    }

    // Named as it was given first, so a path the user wrote is used verbatim, and then beside the
    // rule files hashcat ships. That is the same order everything else shipped is looked for in.

    // Sized the way every other path in the feed layer is. At 192 bytes a longer path was cut in half
    // and then tested, so a rule file that is there was reported as one that is not.

    char resolved[HCBUFSIZ_TINY];

    snprintf (resolved, sizeof (resolved), "%s", rulefile);

    if (hc_path_read (resolved) == false)
    {
      snprintf (resolved, sizeof (resolved), "%s/%s", global_ctx->shared_dir, rulefile);

      // Named as the user wrote it, because the second path is hashcat's guess and reporting that one
      // sends somebody looking for a file they never asked for.

      if (hc_path_read (resolved) == false)
      {
        error_set (global_ctx, "%s: cannot read, and there is no rule file of that name in %s either", rulefile, global_ctx->shared_dir);

        return false;
      }
    }

    if (assoc_rules_load (global_ctx, feed_global, resolved, (u32) rulemax) == false) return false;

    if (assoc_sched_build (feed_global) == false)
    {
      error_set (global_ctx, "%s: %u rules and %u hints is more grid than this phase can hold.", resolved, feed_global->rule_cnt, feed_global->hint_max);

      return false;
    }

    feed_global->rounds_cnt = feed_global->sched_cnt;

    // The rule list is named rather than read into this. Nothing reads the answer yet: the only consumer
    // of source_ident is the brain attack id, and --brain-client is refused for -a 9, so the number this
    // builds is computed and never looked at. Whoever lifts that refusal has to hash what the file holds
    // as well as where it is, or two different rule lists at one path are one attack to the brain and
    // the second run's candidates are refused as work the first already did. feed_pcfg's
    // pcfg_ident_content () is the shape to copy.

    global_ctx->source_ident = paw64 ((const u8 *) resolved, (u32) strlen (resolved), global_ctx->source_ident);
  }
  else
  {
    error_set (global_ctx, "Unknown attack phase '%s'.", phase);

    return false;
  }

  // Say what the candidates are and where they came from. "Feed (wordlist.txt)" is enough for a feed
  // reading a wordlist, because a wordlist holds candidates. This one holds hashes, and the candidates
  // are cut out of the account names in front of them, so the file name on its own would read as though
  // hashcat were trying the hashes.
  //
  // Which word of the account name this round is trying is not said here. Each word is a round, so it is
  // the queue position, and Guess.Queue is where hashcat reports that for every other attack that is really
  // a queue of rounds.

  // What the status screen reports this run is guessing from. The hash file is the base, because the words
  // come out of it and out of whatever the hash mode carries, and the rule list is what this phase does
  // to them. Guess.Queue reports which phase of how many, so this only has to name the current one.

  if (feed_global->phase_words == true)
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s, words phase", hashes->hashfile);
  }
  else
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s, rules phase: %s", hashes->hashfile, (rulefile != NULL) ? rulefile : "none");
  }

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  if (feed_global == NULL) return;

  // The words are cut out of the account names, which belong to the hash list and outlive this feed, so
  // none of their memory is this feed's to free either. The rule list is this feed's own.

  hcfree (feed_global->rule_buf);
  hcfree (feed_global->rule_off);
  hcfree (feed_global->rule_len);
  hcfree (feed_global->sched);

  hcfree (feed_global);

  global_ctx->gbldata = NULL;
}

// One word per account per round, so the instance is as long as the two multiplied. hashcat checks
// that this is a whole multiple of the salt count, which it is by construction.

static u64 feed_keyspace (const feed_global_t *feed_global)
{
  const u64 keyspace = feed_global->words_cnt * feed_global->rounds_cnt;

  return keyspace;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  const u64 keyspace = feed_keyspace (feed_global);

  return keyspace;
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

  if (feed_thread->pos >= feed_keyspace (feed_global)) return GENERIC_RC_EOF;

  // Round major: the position divides into which round this is and which account inside it. The
  // account is the remainder because the attack pairs word N with salt N and the salts are walked in
  // order, so a round has to be one pass over the accounts and not one account's whole run.

  const u64 idx = feed_thread->pos;

  const u32 round = (u32) (idx / feed_global->words_cnt);

  const u64 acct = idx % feed_global->words_cnt;

  feed_thread->pos++;

  hlfmt_word_t hints[ASSOCIATION_WORDS_MAX];

  char scratch[ASSOCIATION_HINT_SCRATCH];

  // The whole list, not hint_max of it. What an account contributes is a property of the account, and
  // asking for fewer changes which words come back rather than only how many: a list capped at five is
  // not the first five of a list capped at eight. global_init () measured the widest account with the
  // hard cap, so asking for anything narrower here would leave a round with no word in it for an
  // account that has one.

  const u32 hints_cnt = hlfmt_hash_hints (feed_global->hcctx, acct, hints, ASSOCIATION_WORDS_MAX, scratch, sizeof (scratch));

  // The words phase has no schedule. Round r is word r, and the word is the candidate.

  const u32 sd = (feed_global->phase_words == true) ? round : (feed_global->sched[round] & ASSOC_SCHED_HINT_MAX);

  // This account has fewer hints than the grid is wide, so this round has no word for it. A candidate
  // of length zero keeps its place, which the pairing of word N with salt N needs.

  if (sd >= hints_cnt) return 0;

  if (feed_global->phase_words == true)
  {
    const int copy_len = (int) MIN (hints[sd].len, (u32) out_size);

    memcpy (out_buf, hints[sd].buf, (size_t) copy_len);

    return (int) hints[sd].len;
  }

  const u32 ri = (feed_global->sched[round] >> ASSOC_SCHED_HINT_BITS);

  char rule_in[RP_PASSWORD_SIZE];
  char rule_out[RP_PASSWORD_SIZE];

  const int in_len = (int) MIN (hints[sd].len, RP_PASSWORD_SIZE);

  memcpy (rule_in, hints[sd].buf, (size_t) in_len);

  const char *rule = feed_global->rule_buf + feed_global->rule_off[ri];

  const int out_len = _old_apply_rule (rule, (int) feed_global->rule_len[ri], rule_in, in_len, rule_out);

  // A rule that rejects this hint produces no candidate. That is what makes a long rule list affordable
  // here: the reject is decided before the candidate is built, and building it is what this attack
  // spends its time on.

  if (out_len < 0) return 0;

  const int copy_len = MIN (out_len, out_size);

  memcpy (out_buf, rule_out, (size_t) copy_len);

  return out_len;
}

// Which rule made this candidate, for --debug-mode.
//
// The attack has no cell and no pool: it hands hashcat finished candidates and decides what to make
// from where it is in its own keyspace. So the position is the whole of the answer. It divides into the
// round and the account the same way thread_next () divides it, and the round names a cell of the grid,
// which names the rule.
//
// The rule alone is written, because that is what the field means everywhere else. Which word of the
// account it was applied to is not said here: the candidate is the base word as far as hashcat is
// concerned, so --debug-mode 2 and 4 already show what came out.
//
// This runs once per crack and on whichever thread found it, and everything it reads was settled in
// global_init () and is not written again.

int global_explain (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED const pcfg_cell_t *cell, MAYBE_UNUSED const u32 *pool, MAYBE_UNUSED const u8 *base, MAYBE_UNUSED const int base_len, MAYBE_UNUSED const u32 il_pos, const u64 pos, char *out_buf, const int out_size)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  if (feed_global == NULL) return -1;

  if (feed_global->words_cnt == 0) return -1;

  if (pos >= feed_keyspace (feed_global)) return -1;

  const u32 round = (u32) (pos / feed_global->words_cnt);

  if (round >= feed_global->sched_cnt) return -1;

  const u32 ri = feed_global->sched[round] >> ASSOC_SCHED_HINT_BITS;

  if (ri >= feed_global->rule_cnt) return -1;

  const u32 len = feed_global->rule_len[ri];

  const int room = (len < (u32) out_size) ? (int) len : out_size;

  memcpy (out_buf, feed_global->rule_buf + feed_global->rule_off[ri], (size_t) room);

  return room;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  const feed_global_t *feed_global = global_ctx->gbldata;

  if (offset >= feed_keyspace (feed_global))
  {
    thread_error_set (thread_ctx, "seek target past EOF: %zu", (size_t) offset);

    return false;
  }

  feed_thread_t *feed_thread = thread_ctx->thrdata;

  feed_thread->pos = offset;

  return true;
}
