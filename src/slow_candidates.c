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
#include "mpsp.h"
#include "filehandling.h"
#include "slow_candidates.h"
#include "shared.h"
#include "generic.h"

// Pull one base word from the feed and apply -j to it. Shared by seek () and next () so that the
// two can never disagree about what a base index holds.

static void slow_candidates_generic_base (hashcat_ctx_t *hashcat_ctx, extra_info_generic_t *extra_info_generic)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  extra_info_generic->reject = false;

  const int base_len = generic_thread_next (hashcat_ctx, extra_info_generic->device_id, extra_info_generic->base_buf, PW_MAX);

  if (base_len < 0)
  {
    extra_info_generic->base_len = 0;

    extra_info_generic->reject = true;

    return;
  }

  extra_info_generic->base_len = (u32) base_len;

  if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l) == 0) return;

  if (extra_info_generic->base_len >= RP_PASSWORD_SIZE)
  {
    extra_info_generic->reject = true;

    return;
  }

  char rule_buf_out[RP_PASSWORD_SIZE];

  memset (rule_buf_out, 0, sizeof (rule_buf_out));

  const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, (char *) extra_info_generic->base_buf, (int) extra_info_generic->base_len, rule_buf_out);

  if (rule_len_out < 0)
  {
    extra_info_generic->reject = true;

    return;
  }

  memcpy (extra_info_generic->base_buf, rule_buf_out, rule_len_out);

  extra_info_generic->base_len = (u32) rule_len_out;
}

void slow_candidates_seek (hashcat_ctx_t *hashcat_ctx, void *extra_info, const u64 cur, const u64 end)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  const u32 attack_mode = user_options->attack_mode;

  if (attack_mode == ATTACK_MODE_STRAIGHT)
  {
    extra_info_straight_t *extra_info_straight = (extra_info_straight_t *) extra_info;

    for (u64 i = cur; i < end; i++)
    {
      if ((i % straight_ctx->kernel_rules_cnt) == 0)
      {
        char *line_buf = NULL;
        u32   line_len = 0;

        // Declared here, not inside the loop: line_buf may point at it after the break.
        char rule_buf_out[RP_PASSWORD_SIZE];

        while (true)
        {
          HCFILE *fp = &extra_info_straight->fp;

          get_next_word (hashcat_ctx, fp, &line_buf, &line_len);

          // post-process rule engine

          if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l))
          {
            if (line_len >= RP_PASSWORD_SIZE) continue;

            memset (rule_buf_out, 0, sizeof (rule_buf_out));

            const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, line_buf, (int) line_len, rule_buf_out);

            if (rule_len_out < 0) continue;

            line_buf = rule_buf_out;
            line_len = (u32) rule_len_out;
          }

          break;
        }

        memcpy (extra_info_straight->base_buf, line_buf, line_len);

        extra_info_straight->base_len = line_len;
      }
    }

    extra_info_straight->rule_pos_prev = end % straight_ctx->kernel_rules_cnt;

    extra_info_straight->rule_pos = extra_info_straight->rule_pos_prev;
  }
  else if (attack_mode == ATTACK_MODE_COMBI)
  {
    extra_info_combi_t *extra_info_combi = (extra_info_combi_t *) extra_info;

    HCFILE *base_fp = &extra_info_combi->base_fp;
    HCFILE *combs_fp = &extra_info_combi->combs_fp;

    for (u64 i = cur; i < end; i++)
    {
      if ((i % combinator_ctx->combs_cnt) == 0)
      {
        char *line_buf = NULL;
        u32   line_len = 0;

        // Declared here, not inside the loop: line_buf may point at it after the break.
        char rule_buf_out[RP_PASSWORD_SIZE];

        while (true)
        {
          get_next_word (hashcat_ctx, base_fp, &line_buf, &line_len);

          // post-process rule engine

          if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l))
          {
            if (line_len >= RP_PASSWORD_SIZE) continue;

            memset (rule_buf_out, 0, sizeof (rule_buf_out));

            const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, line_buf, (int) line_len, rule_buf_out);

            if (rule_len_out < 0) continue;

            line_buf = rule_buf_out;
            line_len = (u32) rule_len_out;
          }

          break;
        }

        memcpy (extra_info_combi->base_buf, line_buf, line_len);

        extra_info_combi->base_len = line_len;

        hc_rewind (combs_fp);
      }

      char *line_buf = extra_info_combi->scratch_buf;
      u32   line_len = 0;

      while (true)
      {
        line_len = (u32) fgetl (combs_fp, line_buf, HCBUFSIZ_LARGE);

        line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

        // post-process rule engine

        if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l))
        {
          if (line_len >= RP_PASSWORD_SIZE) continue;

          char rule_buf_out[RP_PASSWORD_SIZE];

          memset (rule_buf_out, 0, sizeof (rule_buf_out));

          const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, line_buf, (int) line_len, rule_buf_out);

          if (rule_len_out < 0) continue;
        }

        break;
      }
    }

    extra_info_combi->comb_pos_prev = end % combinator_ctx->combs_cnt;

    extra_info_combi->comb_pos = extra_info_combi->comb_pos_prev;
  }
  else if (attack_mode == ATTACK_MODE_BF)
  {
    // nothing to do
  }
  else if (attack_mode == ATTACK_MODE_GENERIC)
  {
    extra_info_generic_t *extra_info_generic = (extra_info_generic_t *) extra_info;

    // Unlike the wordlist reader this does not have to replay. One base word is one offset, so the
    // feed can be told the base index directly and the rules position falls out of the remainder.

    const u64 rules_cnt = straight_ctx->kernel_rules_cnt;

    const u64 base_idx = end / rules_cnt;
    const u64 rule_idx = end % rules_cnt;

    // Landing past the end of the feed means there is nothing here to generate. Saying so with the
    // reject flag stops the caller counting a candidate that does not exist, which otherwise runs
    // the progress counter away past the keyspace and never terminates.

    if (generic_thread_seek (hashcat_ctx, extra_info_generic->device_id, base_idx) != 0)
    {
      extra_info_generic->base_len = 0;

      extra_info_generic->reject = true;
    }
    else if (rule_idx > 0)
    {
      // Landing part way through a base word means next () will not fetch one, so it has to be here.
      // Landing exactly on a boundary means next () fetches it itself and nothing is needed.

      slow_candidates_generic_base (hashcat_ctx, extra_info_generic);
    }

    extra_info_generic->rule_pos_prev = rule_idx;

    extra_info_generic->rule_pos = rule_idx;
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

  if (attack_mode == ATTACK_MODE_STRAIGHT)
  {
    extra_info_straight_t *extra_info_straight = (extra_info_straight_t *) extra_info;

    if ((extra_info_straight->pos % straight_ctx->kernel_rules_cnt) == 0)
    {
      char *line_buf = NULL;
      u32   line_len = 0;

      // Declared here, not inside the loop: line_buf may point at it after the break.
      char rule_buf_out[RP_PASSWORD_SIZE];

      while (true)
      {
        HCFILE *fp = &extra_info_straight->fp;

        get_next_word (hashcat_ctx, fp, &line_buf, &line_len);

        // post-process rule engine

        if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l))
        {
          if (line_len >= RP_PASSWORD_SIZE) continue;

          memset (rule_buf_out, 0, sizeof (rule_buf_out));

          const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, line_buf, (int) line_len, rule_buf_out);

          if (rule_len_out < 0) continue;

          line_buf = rule_buf_out;
          line_len = (u32) rule_len_out;
        }

        break;
      }

      memcpy (extra_info_straight->base_buf, line_buf, line_len);

      extra_info_straight->base_len = line_len;
    }

    memcpy (extra_info_straight->out_buf, extra_info_straight->base_buf, extra_info_straight->base_len);

    extra_info_straight->out_len = extra_info_straight->base_len;

    memset (extra_info_straight->out_buf + extra_info_straight->base_len, 0, sizeof (extra_info_straight->out_buf) - extra_info_straight->out_len);

    u32 *out_ptr = (u32 *) extra_info_straight->out_buf;

    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      extra_info_straight->out_len = MIN (extra_info_straight->out_len, 31); // max length supported by apply_rules_optimized()

      extra_info_straight->out_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[extra_info_straight->rule_pos].cmds, &out_ptr[0], &out_ptr[4], extra_info_straight->out_len);
    }
    else
    {
      extra_info_straight->out_len = MIN (extra_info_straight->out_len, 256); // max length supported by apply_rules()

      extra_info_straight->out_len = apply_rules (straight_ctx->kernel_rules_buf[extra_info_straight->rule_pos].cmds, out_ptr, extra_info_straight->out_len);
    }

    extra_info_straight->rule_pos_prev = extra_info_straight->rule_pos;

    extra_info_straight->rule_pos++;

    if (extra_info_straight->rule_pos == straight_ctx->kernel_rules_cnt)
    {
      extra_info_straight->rule_pos = 0;
    }
  }
  else if (attack_mode == ATTACK_MODE_COMBI)
  {
    extra_info_combi_t *extra_info_combi = (extra_info_combi_t *) extra_info;

    HCFILE *base_fp = &extra_info_combi->base_fp;
    HCFILE *combs_fp = &extra_info_combi->combs_fp;

    if ((extra_info_combi->pos % combinator_ctx->combs_cnt) == 0)
    {
      char *line_buf = NULL;
      u32   line_len = 0;

      // Declared here, not inside the loop: line_buf may point at it after the break.
      char rule_buf_out[RP_PASSWORD_SIZE];

      while (true)
      {
        get_next_word (hashcat_ctx, base_fp, &line_buf, &line_len);

        // post-process rule engine

        if (run_rule_engine ((int) user_options_extra->rule_len_l, user_options->rule_buf_l))
        {
          if (line_len >= RP_PASSWORD_SIZE) continue;

          memset (rule_buf_out, 0, sizeof (rule_buf_out));

          const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, (int) user_options_extra->rule_len_l, line_buf, (int) line_len, rule_buf_out);

          if (rule_len_out < 0) continue;

          line_buf = rule_buf_out;
          line_len = (u32) rule_len_out;
        }

        break;
      }

      memcpy (extra_info_combi->base_buf, line_buf, line_len);

      extra_info_combi->base_len = line_len;

      hc_rewind (combs_fp);
    }

    memcpy (extra_info_combi->out_buf, extra_info_combi->base_buf, extra_info_combi->base_len);

    extra_info_combi->out_len = extra_info_combi->base_len;

    char *line_buf = extra_info_combi->scratch_buf;
    u32   line_len = 0;

    // Declared here, not inside the loop: line_buf may point at it after the break.
    char rule_buf_out[RP_PASSWORD_SIZE];

    while (true)
    {
      line_len = (u32) fgetl (combs_fp, line_buf, HCBUFSIZ_LARGE);

      line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

      // post-process rule engine

      if (run_rule_engine ((int) user_options_extra->rule_len_r, user_options->rule_buf_r))
      {
        if (line_len >= RP_PASSWORD_SIZE) continue;

        memset (rule_buf_out, 0, sizeof (rule_buf_out));

        const int rule_len_out = _old_apply_rule (user_options->rule_buf_r, (int) user_options_extra->rule_len_r, line_buf, (int) line_len, rule_buf_out);

        if (rule_len_out < 0) continue;

        line_buf = rule_buf_out;
        line_len = (u32) rule_len_out;
      }

      break;
    }

    // this can overflow so we move it up

    if ((extra_info_combi->out_len + line_len) <= sizeof (extra_info_combi->out_buf))
    {
      memcpy (extra_info_combi->out_buf + extra_info_combi->out_len, line_buf, line_len);

      extra_info_combi->out_len += line_len;

      memset (extra_info_combi->out_buf + extra_info_combi->out_len, 0, sizeof (extra_info_combi->out_buf) - extra_info_combi->out_len);
    }
    else
    {
      extra_info_combi->out_len += line_len;
    }

    extra_info_combi->comb_pos_prev = extra_info_combi->comb_pos;

    extra_info_combi->comb_pos++;

    if (extra_info_combi->comb_pos == combinator_ctx->combs_cnt)
    {
      extra_info_combi->comb_pos = 0;
    }
  }
  else if (attack_mode == ATTACK_MODE_BF)
  {
    extra_info_mask_t *extra_info_mask = (extra_info_mask_t *) extra_info;

    sp_exec (extra_info_mask->pos, (char *) extra_info_mask->out_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);
  }
  else if (attack_mode == ATTACK_MODE_GENERIC)
  {
    extra_info_generic_t *extra_info_generic = (extra_info_generic_t *) extra_info;

    if ((extra_info_generic->pos % straight_ctx->kernel_rules_cnt) == 0)
    {
      slow_candidates_generic_base (hashcat_ctx, extra_info_generic);
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
}
