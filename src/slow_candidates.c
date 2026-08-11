/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "rp.h"
#include "rp_cpu.h"
#include "emu_inc_rp.h"
#include "emu_inc_rp_optimized.h"
#include "wordlist.h"
#include "convert.h"
#include "mpsp.h"
#include "slow_candidates.h"
#include "shared.h"
#include "generic.h"

// Pull one base word from the base word instance and apply the base rule to it. Shared by seek () and
// next () so that the two can never disagree about what a base index holds, and shared by the straight
// and the combinator readers so that the two can never disagree about what a base word is.

static void slow_candidates_base_next (hashcat_ctx_t *hashcat_ctx, const int device_id, const pw_transform_t *transform, u8 *base_buf, u32 *base_len_out, bool *reject)
{
  reject[0] = false;

  const int base_len = generic_thread_next (hashcat_ctx, GENERIC_ROLE_BASE, device_id, base_buf, PW_MAX);

  if (base_len < 0)
  {
    base_len_out[0] = 0;

    reject[0] = true;

    return;
  }

  // A feed reports the true length of the candidate even when it only had room to write the first
  // PW_MAX bytes, so a longer one has to be thrown away here rather than believed. A transform below
  // can shorten a line, but only one that was short enough to be written in the first place: there is
  // no second read here to recover a line that never fitted, which is the one thing the fast producer
  // can do and this cannot.
  //
  // It is rejected in place rather than replaced, so the offset it occupies stays occupied. That is
  // what keeps --skip, --restore and the brain agreeing with a run over the same feed.

  if (base_len > PW_MAX)
  {
    base_len_out[0] = 0;

    reject[0] = true;

    return;
  }

  const int work_len = pw_transform_apply (transform, base_buf, base_len, PW_MAX);

  if (work_len < 0)
  {
    base_len_out[0] = 0;

    reject[0] = true;

    return;
  }

  base_len_out[0] = (u32) work_len;
}

// One amplifier line of a -a 1, with -k applied. The amplifier is counted the same way the base is,
// so this consumes exactly one line per call and says whether that line can be used, rather than
// reading on until it finds one that can.

static bool slow_candidates_combs_next (hashcat_ctx_t *hashcat_ctx, const int device_id, const pw_transform_t *transform, char **out_buf, u32 *out_len)
{
  char *line_buf = out_buf[0];

  out_len[0] = 0;

  const int line_len_raw = generic_thread_next (hashcat_ctx, GENERIC_ROLE_AMP, device_id, (u8 *) line_buf, HCBUFSIZ_LARGE);

  // Out of words, or the feed failed, or the word is longer than the buffer it was asked to write
  // into. All three mean this amplifier slot produces no candidate, and the caller rejects it in
  // place so the slot stays occupied.

  if (line_len_raw < 0) return false;

  if (line_len_raw > HCBUFSIZ_LARGE) return false;

  const int line_len = pw_transform_apply (transform, (u8 *) line_buf, line_len_raw, HCBUFSIZ_LARGE);

  if (line_len < 0) return false;

  if (line_len > PW_MAX) return false;

  out_len[0] = (u32) line_len;

  return true;
}

// Put both sources where offset end says they are.
//
// Neither branch has to replay. One base word is one block of offsets, so the base index is the
// quotient and where inside that block the offset sits is the remainder. What the remainder addresses
// is the only thing the two branches disagree about: a rules position is an index into a buffer that
// is already in memory, and an amplifier position is a second feed that has to be seeked as well.
//
// A remainder of zero needs no fetch at all. next () sees the start of a base word and fetches it
// itself, and doing it here as well would consume two.
//
// cur is unused now that neither branch replays, and it stays in the signature because it is what a
// producer knows without having to work anything out.

void slow_candidates_seek (hashcat_ctx_t *hashcat_ctx, void *extra_info, MAYBE_UNUSED const u64 cur, const u64 end)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  const u32 attack_mode = user_options->attack_mode;
  const u32 base_source = user_options_extra->base_source;

  // -a 1 is asked about first because both of its sources are feeds, so it answers to the feed test
  // as well and the feed branch has no amplifier to place.

  if (attack_mode == ATTACK_MODE_HYBRID)
  {
    extra_info_combi_t *extra_info_combi = (extra_info_combi_t *) extra_info;

    const u64 combs_cnt = combinator_ctx->combs_cnt;

    const u64 base_idx = end / combs_cnt;
    const u64 comb_idx = end % combs_cnt;

    // Landing past the end of the feed means there is nothing here to generate. Saying so with the
    // reject flag stops the caller counting a candidate that does not exist.

    if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_BASE, extra_info_combi->device_id, base_idx) != 0)
    {
      extra_info_combi->base_len = 0;

      extra_info_combi->base_reject = true;
    }
    else if (comb_idx > 0)
    {
      slow_candidates_base_next (hashcat_ctx, extra_info_combi->device_id, &extra_info_combi->transform_base, extra_info_combi->base_buf, &extra_info_combi->base_len, &extra_info_combi->base_reject);

      // An amplifier position covers a mask value and, when the mask has a ?q, a word from the second
      // wordlist as well, with the word running fastest. Only the word has a feed to seek.

      if (mask_ctx->has_q == true)
      {
        const u64 words_cnt = hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP].keyspace;

        if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_AMP, extra_info_combi->device_id, comb_idx % words_cnt) != 0)
        {
          extra_info_combi->base_reject = true;
        }
      }
    }

    extra_info_combi->comb_pos_prev = comb_idx;

    extra_info_combi->comb_pos = comb_idx;
  }
  else if (base_source == BASE_SOURCE_FEED)
  {
    extra_info_generic_t *extra_info_generic = (extra_info_generic_t *) extra_info;

    const u64 rules_cnt = straight_ctx->kernel_rules_cnt;

    const u64 base_idx = end / rules_cnt;
    const u64 rule_idx = end % rules_cnt;

    if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_BASE, extra_info_generic->device_id, base_idx) != 0)
    {
      extra_info_generic->base_len = 0;

      extra_info_generic->reject = true;
    }
    else if (rule_idx > 0)
    {
      slow_candidates_base_next (hashcat_ctx, extra_info_generic->device_id, &extra_info_generic->transform, extra_info_generic->base_buf, &extra_info_generic->base_len, &extra_info_generic->reject);
    }

    extra_info_generic->rule_pos_prev = rule_idx;

    extra_info_generic->rule_pos = rule_idx;
  }
  else if (attack_mode == ATTACK_MODE_BF)
  {
    // nothing to do
  }
}

void slow_candidates_next (hashcat_ctx_t *hashcat_ctx, void *extra_info)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  const u32 attack_mode = user_options->attack_mode;
  const u32 base_source = user_options_extra->base_source;

  // -a 1 is asked about first for the same reason as in seek (): both of its sources are feeds, so it
  // answers to the feed test as well and the feed branch would build a candidate with no amplifier on
  // it.

  if (attack_mode == ATTACK_MODE_HYBRID)
  {
    extra_info_combi_t *extra_info_combi = (extra_info_combi_t *) extra_info;

    if ((extra_info_combi->pos % combinator_ctx->combs_cnt) == 0)
    {
      slow_candidates_base_next (hashcat_ctx, extra_info_combi->device_id, &extra_info_combi->transform_base, extra_info_combi->base_buf, &extra_info_combi->base_len, &extra_info_combi->base_reject);

      if (mask_ctx->has_q == true)
      {
        if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_AMP, extra_info_combi->device_id, 0) != 0)
        {
          extra_info_combi->base_reject = true;
        }
      }
    }

    // The mask value this amplifier position stands for, produced whole and then cut at the markers,
    // which is what hybrid_assemble () does with it.

    char mask_buf[256];

    hybrid_amp_mask (hashcat_ctx, extra_info_combi->comb_pos, mask_buf);

    char *line_buf = extra_info_combi->scratch_buf;
    u32   line_len = 0;

    bool amp_usable = true;

    // The second word, when the mask names one. The line is consumed whatever happens to it, because
    // the amplifier is counted in lines too: a line -k throws away rejects the candidate it would
    // have made rather than handing the slot to the line after it.

    if (mask_ctx->has_q == true)
    {
      amp_usable = slow_candidates_combs_next (hashcat_ctx, extra_info_combi->device_id, &extra_info_combi->transform_amp, &line_buf, &line_len);

      // the word index wraps back to the start of the second wordlist as the mask value steps on

      const u64 words_cnt = hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP].keyspace;

      if (((extra_info_combi->comb_pos + 1) % words_cnt) == 0)
      {
        if (generic_thread_seek (hashcat_ctx, GENERIC_ROLE_AMP, extra_info_combi->device_id, 0) != 0)
        {
          amp_usable = false;
        }
      }
    }

    extra_info_combi->out_len = hybrid_assemble (hashcat_ctx, extra_info_combi->out_buf, mask_buf, extra_info_combi->base_buf, extra_info_combi->base_len, (const u8 *) line_buf, line_len);

    memset (extra_info_combi->out_buf + extra_info_combi->out_len, 0, sizeof (extra_info_combi->out_buf) - extra_info_combi->out_len);

    extra_info_combi->reject = (extra_info_combi->base_reject == true) || (amp_usable == false);

    if (extra_info_combi->reject == true) extra_info_combi->out_len = 0;

    extra_info_combi->comb_pos_prev = extra_info_combi->comb_pos;

    extra_info_combi->comb_pos++;

    if (extra_info_combi->comb_pos == combinator_ctx->combs_cnt)
    {
      extra_info_combi->comb_pos = 0;
    }
  }
  else if (base_source == BASE_SOURCE_FEED)
  {
    extra_info_generic_t *extra_info_generic = (extra_info_generic_t *) extra_info;

    if ((extra_info_generic->pos % straight_ctx->kernel_rules_cnt) == 0)
    {
      slow_candidates_base_next (hashcat_ctx, extra_info_generic->device_id, &extra_info_generic->transform, extra_info_generic->base_buf, &extra_info_generic->base_len, &extra_info_generic->reject);
    }

    // A base word the -j rule threw away is still a base word. Every candidate it would have made is
    // rejected, and the offset it occupies stays occupied, which is what keeps --skip and the brain
    // agreeing with a run that does not use -j.

    if (extra_info_generic->reject == true)
    {
      extra_info_generic->out_len = 0;
    }
    else
    {
      memcpy (extra_info_generic->out_buf, extra_info_generic->base_buf, extra_info_generic->base_len);

      extra_info_generic->out_len = extra_info_generic->base_len;

      memset (extra_info_generic->out_buf + extra_info_generic->base_len, 0, sizeof (extra_info_generic->out_buf) - extra_info_generic->out_len);

      u32 *out_ptr = (u32 *) extra_info_generic->out_buf;

      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        extra_info_generic->out_len = MIN (extra_info_generic->out_len, 31); // max length supported by apply_rules_optimized()

        extra_info_generic->out_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[extra_info_generic->rule_pos].cmds, &out_ptr[0], &out_ptr[4], extra_info_generic->out_len);
      }
      else
      {
        extra_info_generic->out_len = MIN (extra_info_generic->out_len, 256); // max length supported by apply_rules()

        extra_info_generic->out_len = apply_rules (straight_ctx->kernel_rules_buf[extra_info_generic->rule_pos].cmds, out_ptr, extra_info_generic->out_len);
      }
    }

    extra_info_generic->rule_pos_prev = extra_info_generic->rule_pos;

    extra_info_generic->rule_pos++;

    if (extra_info_generic->rule_pos == straight_ctx->kernel_rules_cnt)
    {
      extra_info_generic->rule_pos = 0;
    }
  }
  else if (attack_mode == ATTACK_MODE_BF)
  {
    extra_info_mask_t *extra_info_mask = (extra_info_mask_t *) extra_info;

    sp_exec (extra_info_mask->pos, (char *) extra_info_mask->out_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);
  }
}
