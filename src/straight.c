/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "logfile.h"
#include "shared.h"
#include "path.h"
#include "filehandling.h"
#include "hlfmt.h"
#include "folder.h"
#include "rp.h"
#include "wordlist.h"
#include "convert.h"
#include "feed_ctx.h"
#include "straight.h"

static int straight_ctx_add_wl (hashcat_ctx_t *hashcat_ctx, const char *dict)
{
  if (hc_path_has_bom (dict) == true)
  {
    event_log_warning (hashcat_ctx, "%s: Byte Order Mark (BOM) was detected", dict);

    //return -1;
  }

  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  if (straight_ctx->dicts_avail == straight_ctx->dicts_cnt)
  {
    straight_ctx->dicts = (char **) hcrealloc (straight_ctx->dicts, straight_ctx->dicts_avail * sizeof (char *), INCR_DICTS * sizeof (char *));

    straight_ctx->dicts_avail += INCR_DICTS;
  }

  straight_ctx->dicts[straight_ctx->dicts_cnt] = hcstrdup (dict);

  straight_ctx->dicts_cnt++;

  return 0;
}

// The rounds of -a 9 splitting its own hash file. There is no file per round: a round is "try the Nth
// word of every account name", so the list is as long as the widest account name in the file.
//
// The names are walked here rather than the count being asked of the feed, because the round list has to
// exist before any round is opened and the feed is opened one round at a time.

static int straight_ctx_add_association_rounds (hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t *hashes = hashcat_ctx->hashes;

  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  u32 words_max = 1;

  if (hashes->hash_info)
  {
    hlfmt_word_t words[ASSOCIATION_WORDS_MAX];

    for (u32 i = 0; i < hashes->digests_cnt; i++)
    {
      const user_t *user = hashes->hash_info[i]->user;

      if (user == NULL) continue;

      const u32 words_cnt = hlfmt_user_words (user->user_name, user->user_len, words, ASSOCIATION_WORDS_MAX);

      if (words_cnt > words_max) words_max = words_cnt;
    }
  }

  straight_ctx->dicts = (char **) hcmalloc (words_max * sizeof (char *));

  straight_ctx->dicts_avail = words_max;
  straight_ctx->dicts_cnt   = words_max;

  for (u32 i = 0; i < words_max; i++)
  {
    char *name = NULL;

    hc_asprintf (&name, "%u", i);

    straight_ctx->dicts[i] = name;
  }

  return 0;
}

// Turn a range of the work arguments into the dictionary list. A directory becomes every readable file
// inside it, sorted by name so the keyspace is the same on every machine, and anything else is added as
// it stands.
//
// The range is the only thing the attack modes disagree about. -a 0 and -a 9 take every argument, -a 6
// leaves the last one to the mask, and -a 7 leaves the first one to it.

static int straight_ctx_add_workv (hashcat_ctx_t *hashcat_ctx, const int from, const int to)
{
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  for (int i = from; i < to; i++)
  {
    char *l0_filename = user_options_extra->hc_workv[i];

    // at this point we already verified the path actually exist and is readable

    if (hc_path_is_directory (l0_filename) == false)
    {
      if (straight_ctx_add_wl (hashcat_ctx, l0_filename) == -1) return -1;

      continue;
    }

    char **dictionary_files = scan_directory (l0_filename);

    if (dictionary_files != NULL)
    {
      qsort (dictionary_files, (size_t) count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

      for (int d = 0; dictionary_files[d] != NULL; d++)
      {
        char *l1_filename = dictionary_files[d];

        if (hc_path_read (l1_filename) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", l1_filename, strerror (errno));

          hcfree (dictionary_files);

          return -1;
        }

        if (hc_path_is_file (l1_filename) == true)
        {
          if (straight_ctx_add_wl (hashcat_ctx, l1_filename) == -1)
          {
            hcfree (dictionary_files);

            return -1;
          }
        }
      }
    }

    hcfree (dictionary_files);
  }

  if (straight_ctx->dicts_cnt == 0)
  {
    event_log_error (hashcat_ctx, "No usable dictionary file found.");

    return -1;
  }

  return 0;
}

// Point the base word instance at the one dictionary this round reads, and say how many base words
// that is. Only the per round scope comes here: an induction round, and -a 9 over more than one
// dictionary. Everything else opened its instance once, over every source at once.
//
// An empty dictionary is not an error, it is a round with nothing in it, and the caller skips the
// round. A feed refuses a source it can get no words out of, which is right when that source is the
// whole attack and wrong when it is one file of a directory, so the empty case is answered before the
// feed is asked.

static u64 straight_ctx_round_words (hashcat_ctx_t *hashcat_ctx, const char *dict)
{
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // An empty dictionary is a round with nothing in it rather than a failure, and that is worth knowing
  // before a feed is stood up for it. -a 9 splitting its own hash file has no file here: its rounds are
  // the words an account name became, so there is nothing to stat and nothing that can be empty.

  if (user_options_extra->association_autosplit == false)
  {
    HCFILE fp;

    if (hc_fopen (&fp, dict, "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", dict, hc_fopen_strerror ());

      return GENERIC_KEYSPACE_ERROR;
    }

    struct stat st;

    const int rc_stat = hc_fstat (&fp, &st);

    hc_fclose (&fp);

    if (rc_stat == 0)
    {
      if (st.st_size == 0) return 0;
    }
  }

  if (generic_ctx_base_round (hashcat_ctx, dict) == -1) return GENERIC_KEYSPACE_ERROR;

  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  if (generic_ctx->keyspace == GENERIC_KEYSPACE_UNKNOWN)
  {
    event_log_error (hashcat_ctx, "%s: feed cannot report a keyspace.", dict);

    return GENERIC_KEYSPACE_ERROR;
  }

  return generic_ctx->keyspace;
}

// Finish a keyspace: base words times whatever one base word stands for. That is the rules for a
// straight attack, the amplifier words for a combinator one and the mask for the hybrids. It cannot
// happen any earlier than here, because mask_ctx_update_loop sizes the mask once per round.

static int straight_ctx_words_apply (hashcat_ctx_t *hashcat_ctx, const u64 words_cnt, const u64 amplifier, MAYBE_UNUSED const char *dict)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // The base is what the run is addressed by: --skip, --limit, --restore and the split across devices
  // are all positions in it, and it is what --keyspace answers with. The product is the number of
  // guesses, which only the progress display reads.
  //
  // So a product too large to hold is not a reason to refuse the run. It saturates, the progress
  // display is short of the truth in a regime no run reaches the end of anyway, and the base is
  // stated here rather than recovered by division from a number that no longer divides.

  status_ctx->words_base_given = words_cnt;

  status_ctx->words_cnt = (overflow_check_u64_mul (words_cnt, amplifier) == true) ? UINT64_MAX : (words_cnt * amplifier);

  return 0;
}

int straight_ctx_update_loop (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  induct_ctx_t         *induct_ctx         = hashcat_ctx->induct_ctx;
  logfile_ctx_t        *logfile_ctx        = hashcat_ctx->logfile_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // Whichever scope the base word instance has, what is left to do here is the amplifier, and that is
  // why this happens per round rather than at init. -a 6 and -a 7 amplify with the mask, and the mask
  // is only sized a few lines earlier, by mask_ctx_update_loop.

  // A pipe comes here too and is the one whose keyspace is never known, so it leaves below with
  // words_cnt set to GENERIC_KEYSPACE_UNKNOWN and the run has no denominator.

  if (user_options_extra->base_source == BASE_SOURCE_FEED)
  {
    // An attack that is really a queue of attacks reads one dictionary per round, and this is the
    // round that says which. The instance is opened here rather than at init because an induction
    // dictionary does not exist until the round before it is read.

    if (user_options_extra->base_scope == BASE_SCOPE_PER_ROUND)
    {
      if (induct_ctx->induction_dictionaries_cnt)
      {
        straight_ctx->dict = induct_ctx->induction_dictionaries[induct_ctx->induction_dictionaries_pos];
      }
      else
      {
        straight_ctx->dict = straight_ctx->dicts[straight_ctx->dicts_pos];
      }

      logfile_sub_string (straight_ctx->dict);

      for (u32 i = 0; i < user_options->rp_files_cnt; i++)
      {
        logfile_sub_var_string ("rulefile", user_options->rp_files[i]);
      }

      const u64 round_words = straight_ctx_round_words (hashcat_ctx, straight_ctx->dict);

      if (round_words == GENERIC_KEYSPACE_ERROR) return -1;

      if (round_words == 0)
      {
        status_ctx->words_cnt = 0;

        logfile_sub_msg ("STOP");

        return 0;
      }
    }

    const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

    if (generic_ctx->keyspace == GENERIC_KEYSPACE_UNKNOWN)
    {
      status_ctx->words_cnt = GENERIC_KEYSPACE_UNKNOWN;

      return 0;
    }

    // -a 9 pairs word N with salt N, so the two counts have to agree exactly. Per round, because with
    // more than one dictionary each one is its own attack over the same salts and each has to line up
    // on its own.

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      if (generic_association_in_sync (hashcat_ctx, generic_ctx) == -1) return -1;
    }

    u64 amplifier = 1;

    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      amplifier = straight_ctx->kernel_rules_cnt;
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      amplifier = combinator_ctx->combs_cnt;
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_PCFG)
    {
      amplifier = generic_ctx->dev_avg;
    }

    // As above: the feed's keyspace is the base and is what the run is addressed by, so a product
    // that does not fit saturates rather than ending the run. A feed that generates its base words
    // is the only producer whose base is large enough to reach that.

    status_ctx->words_base_given = generic_ctx->keyspace;

    // Where the feed knows exactly how many candidates it produces, that is the total. The amplifier
    // it would otherwise be multiplied by is a mean rounded down to an integer, so the product is
    // always a little short and the run never quite reaches the total it is measured against.

    if (generic_ctx->global_ctx.dev_total > 0)
    {
      status_ctx->words_cnt = generic_ctx->global_ctx.dev_total;
    }
    else
    {
      status_ctx->words_cnt = (overflow_check_u64_mul (generic_ctx->keyspace, amplifier) == true) ? UINT64_MAX : (generic_ctx->keyspace * amplifier);
    }

    return 0;
  }

  // What is left below is the attacks whose base word is not a feed. -a 1 under --slow-candidates
  // still reads its base with the wordlist reader, and -a 7 under the pure kernel takes its base
  // words from the mask, as does -a 12 under the pure kernel when its mask ends in ?w.
  //
  // -a 0, -a 6, -a 8 and -a 9 have all returned above, and so has -a 7 under the optimized kernel.

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    logfile_sub_string (mask_ctx->mask);
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    straight_ctx->dict = straight_ctx->dicts[straight_ctx->dicts_pos];

    logfile_sub_string (straight_ctx->dict);
    logfile_sub_string (mask_ctx->mask);

    // The pure kernel amplifies with the dictionary and takes its base words from the mask, so the
    // keyspace is the mask size times the dictionary, and the dictionary was counted once by the
    // amplifier instance.
    //
    // The base is the mask and the amplifier is the dictionary, in that order. Stating them the other
    // way round makes the run walk one base word per dictionary word over a mask that has a different
    // number of values in it, and the product is right while both of its factors are wrong:
    //
    //   500 words, ?d?d   50000 candidates, 250000 walked, every one of them five times over
    //   500 words, ?d?d?d 500000 candidates, 250000 walked, and half of them never tried at all
    //
    // The second is the one that matters. A run that quietly covers half its own keyspace reports
    // Exhausted having never guessed the password, and nothing in the status screen says so.

    const u64 words_cnt = hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP].keyspace;

    if (straight_ctx_words_apply (hashcat_ctx, mask_ctx->bfs_cnt, words_cnt, straight_ctx->dict) == -1) return -1;

    if (status_ctx->words_cnt == 0)
    {
      logfile_sub_msg ("STOP");

      return 0;
    }
  }

  return 0;
}

// Where a wordlist attack reaches the candidate --lookup asked about.
//
// -a 0 has no arithmetic to invert. Its base words are the lines of a file, in the order they are in
// the file, so the answer is the line the word is on and the only work is finding it. That makes the
// answer exact and the refusal a proof, on one condition: that no rule is in play. A rule turns one
// base word into many candidates and nothing here inverts a rule, so a run with -r is answered about
// the base word only, and the report says so rather than letting a miss read as a proof.
//
// Read once through the feed rather than through the file, because the file is not necessarily one
// file: a folder or several dictionaries are laid end to end into one keyspace and only the feed
// knows the order. The index that comes back is already in --skip units.

void straight_ctx_lookup_report (hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->lookup == NULL) return;

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT) return;

  const u8 *arg     = (const u8 *) user_options->lookup;
  const u32 arg_len = (u32) strlen (user_options->lookup);

  u8 cand[PW_MAX];

  u32 cand_len = 0;

  // A wordlist can hold a line no shell can pass. $HEX[...] is how the potfile and --show write one,
  // so it is how --lookup takes one.

  if (is_hexify (arg, arg_len) == true)
  {
    cand_len = (u32) exec_unhexify (arg, arg_len, cand, sizeof (cand));
  }
  else
  {
    if (arg_len > sizeof (cand)) return;

    memcpy (cand, arg, arg_len);

    cand_len = arg_len;
  }

  event_log_info (hashcat_ctx, "lookup: '%s'", user_options->lookup);

  const u64 rules = straight_ctx->kernel_rules_cnt;

  // Whether a rule is in play at all, which is not the same as more than one being in play. A rule
  // file with a single line gives kernel_rules_cnt == 1, exactly as no rule file does, and testing
  // the count would then claim "without rules the wordlist is the whole attack" while a rule is
  // running. This is the test straight_ctx_init () already uses to decide whether to load any.

  const bool ruled = ((user_options->rp_files_cnt > 0) || (user_options->rp_gen > 0));

  // Two ways of naming the same rule set, because the two sentences below mean different things by
  // it: a miss is about any one of them having made the candidate, and a hit runs all of them.

  char rules_any[64];
  char rules_all[64];

  snprintf (rules_any, sizeof (rules_any), (rules == 1) ? "the one rule"  : "one of the %" PRIu64 " rules", rules);
  snprintf (rules_all, sizeof (rules_all), (rules == 1) ? "the one rule"  : "all %" PRIu64 " rules",         rules);

  u64 index = 0;
  u64 more  = 0;
  u64 words = 0;

  const int rc = generic_ctx_word_index (hashcat_ctx, GENERIC_ROLE_BASE, cand, cand_len, &index, &more, &words);

  if (rc == -1)
  {
    event_log_info (hashcat_ctx, "lookup: this wordlist could not be read through");

    return;
  }

  if (rc == 0)
  {
    // The wall this mode runs into, and the reason the wording differs from every other one. Without
    // rules the wordlist is the whole attack and this is a proof. With rules it is not: the candidate
    // could still be what some rule makes of some other word, and nothing here has looked.

    if (ruled == false)
    {
      event_log_info (hashcat_ctx, "lookup: nothing in this run produces it. the wordlist does not hold it, and without rules the wordlist is the whole attack");

      return;
    }

    event_log_info (hashcat_ctx, "lookup: this wordlist does not hold it as a word, in any of its %" PRIu64 " lines", words);

    event_log_info (hashcat_ctx, "lookup: whether %s makes it out of some other word was NOT checked, and is not something this can answer", rules_any);

    event_log_info (hashcat_ctx, "lookup: so this is not a proof that the run misses it, only that the word itself is not there");

    return;
  }

  const char *segment = generic_ctx_segment_of (hashcat_ctx, GENERIC_ROLE_BASE, index);

  if (segment != NULL)
  {
    event_log_info (hashcat_ctx, "lookup: word %" PRIu64 " of %" PRIu64 ", in %s", index, words, segment);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: word %" PRIu64 " of %" PRIu64 "", index, words);
  }

  if (more > 0)
  {
    event_log_info (hashcat_ctx, "lookup: it is in this wordlist %" PRIu64 " more times, and the run reaches the first of them", more);
  }

  const double pct = (status_ctx->words_walk_base > 0) ? ((double) index * 100.0 / (double) status_ctx->words_walk_base) : 0.0;

  event_log_info (hashcat_ctx, "lookup: %.4f%% into the run", pct);

  event_log_info (hashcat_ctx, "lookup: this run reaches it at -s %" PRIu64 ", because -a 0 counts -s in words", index);

  if (ruled == false)
  {
    event_log_info (hashcat_ctx, "lookup: -s %" PRIu64 " -l 1 runs the one word", index);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: -s %" PRIu64 " -l 1 runs that word with %s applied to it", index, rules_all);

    event_log_info (hashcat_ctx, "lookup: an earlier -s may reach it too, through a rule on another word. that was not checked");
  }

  if ((user_options->skip != 0) || (user_options->limit != 0))
  {
    const u64 from = user_options->skip;
    const u64 upto = (user_options->limit > 0) ? user_options->limit : status_ctx->words_walk_base;

    if ((index >= from) && (index < upto))
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here covers it", from, upto - from);
    }
    else
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here does not cover it", from, upto - from);
    }
  }
}

int straight_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  straight_ctx->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;

  if (user_options->attack_mode  == ATTACK_MODE_BF)      return 0;

  straight_ctx->enabled = true;

  /**
   * generate NOP rules
   */

  if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
  {
    straight_ctx->kernel_rules_buf = (kernel_rule_t *) hcmalloc (sizeof (kernel_rule_t));

    straight_ctx->kernel_rules_buf[0].cmds[0] = RULE_OP_MANGLE_NOOP;

    straight_ctx->kernel_rules_cnt = 1;
  }
  else
  {
    if (user_options->rp_files_cnt)
    {
      EVENT (EVENT_RULESFILES_PARSE_PRE);

      if (kernel_rules_load (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt) == -1) return -1;

      EVENT (EVENT_RULESFILES_PARSE_POST);
    }
    else if (user_options->rp_gen)
    {
      if (kernel_rules_generate (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt, user_options->rp_gen_func_sel) == -1) return -1;
    }
  }

  /**
   * wordlist based work
   */

  // A feed handed every source at once lays them end to end into one keyspace, so there is no
  // dictionary list to build here and no dictionary loop for inner1_loop to run. A feed scoped to one
  // round still needs the list, because that loop is what says which dictionary each round reads. The
  // rules above are this context's either way, because the feed amplifies with them and does not own
  // them.

  if (user_options_extra->base_source == BASE_SOURCE_FEED)
  {
    if (user_options_extra->base_scope == BASE_SCOPE_ALL_SOURCES) return 0;
  }

  // -a 9 splitting its own hash file has no dictionaries. Its rounds are the words one account name
  // becomes, so the list is a round per word and the widest name in the file says how many. Every round
  // hands out one word per hash, and an account with fewer words repeats its last one, because the
  // kernel reads the salt index off the word's position in the batch and no account can sit a round out.

  if (user_options_extra->association_autosplit == true)
  {
    if (straight_ctx_add_association_rounds (hashcat_ctx) == -1) return -1;
  }
  else if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
  {
    // Reading candidates from stdin is the one case with no dictionaries to list. Testing for that
    // rather than for the wordlist reader is what lets a feed scoped to one round have the list too.

    if (user_options_extra->wordlist_mode != WL_MODE_STDIN)
    {
      if (straight_ctx_add_workv (hashcat_ctx, 0, user_options_extra->hc_workc) == -1) return -1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // the mask is first and the wordlists follow it. A ?q wordlist is not in this list: it amplifies,
    // and only the base word source is listed here.

    const int to = user_options_extra->hc_workc - ((user_options_extra->hybrid_q == true) ? 1 : 0);

    if (straight_ctx_add_workv (hashcat_ctx, 1, to) == -1) return -1;
  }
  return 0;
}

void straight_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  if (straight_ctx->enabled == false) return;

  for (u32 dict_pos = 0; dict_pos < straight_ctx->dicts_cnt; dict_pos++)
  {
    hcfree (straight_ctx->dicts[dict_pos]);
  }

  hcfree (straight_ctx->dicts);
  hcfree (straight_ctx->kernel_rules_buf);

  memset (straight_ctx, 0, sizeof (straight_ctx_t));
}
