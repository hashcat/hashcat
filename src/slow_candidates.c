/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "rp.h"
#include "rp_cpu.h"
#include "emu_inc_rp.h"
#include "emu_inc_rp_optimized.h"
#include "wordlist.h"
#include "mpsp.h"
#include "filehandling.h"
#include "slow_candidates.h"
#include "shared.h"
#include "wordlist_index.h"

void slow_candidates_free_index (void *extra_info)
{
  if (extra_info == NULL) return;

  extra_info_straight_t *extra_info_straight = (extra_info_straight_t *) extra_info;

  if (extra_info_straight->idx != NULL)
  {
    hcidx_free ((hcidx_t *) extra_info_straight->idx);
    hcfree (extra_info_straight->idx);
    extra_info_straight->idx = NULL;
  }
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

    u64 eff_cur = cur;

    // --- wordlist seek index acceleration ---------------------------------
    // Only when walking forward from a known position whose file offset we can
    // trust: cur must sit on a base-word boundary, and the wordlist must be a
    // plain (uncompressed) file so byte offsets are meaningful. The common hot
    // case is a fresh chunk where cur == 0 and end is a large --skip.
    {
      HCFILE *fp = &extra_info_straight->fp;

      const bool plain = (fp->pfp != NULL) && (fp->gfp == NULL) && (fp->ufp == NULL) && (fp->xfp == NULL);

      const u64 krc = straight_ctx->kernel_rules_cnt;

      if (plain && krc > 0 && (cur % krc) == 0)
      {
        const u64 cur_word = cur / krc;
        const u64 end_word = end / krc;

        // Lazy one-shot load of the index for this fp.
        if (extra_info_straight->idx_tried == false)
        {
          extra_info_straight->idx_tried = true;

          hcidx_t *idx = (hcidx_t *) hcmalloc (sizeof (hcidx_t));

          if (hcidx_load (idx, straight_ctx->dict, user_options->wordlist_index_cache) == 0 && idx->loaded)
          {
            extra_info_straight->idx = idx;
          }
          else
          {
            hcidx_free (idx);
            hcfree (idx);
            extra_info_straight->idx = NULL;
          }

          extra_info_straight->idx_pos = 0; // fp is at start of file here
        }

        hcidx_t *idx = (hcidx_t *) extra_info_straight->idx;

        if (idx != NULL)
        {
          u64 ckpt_off  = 0;
          u64 ckpt_word = 0;

          // Only jump forward, and only if it skips past where fp already is.
          if (hcidx_lookup (idx, end_word, &ckpt_off, &ckpt_word) == true && ckpt_word > cur_word)
          {
            if (hc_fseek (fp, (off_t) ckpt_off, SEEK_SET) == 0)
            {
              // Invalidate the segment buffer so the next get_next_word reloads
              // from the new file offset.
              wl_data_t *wl_data = hashcat_ctx->wl_data;
              wl_data->pos = 0;
              wl_data->cnt = 0;

              // We are now positioned at the start of base word ckpt_word.
              eff_cur = ckpt_word * krc;
              extra_info_straight->idx_pos = ckpt_word;
            }
          }
        }
      }
    }

    for (u64 i = eff_cur; i < end; i++)
    {
      if ((i % straight_ctx->kernel_rules_cnt) == 0)
      {
        char *line_buf = NULL;
        u32   line_len = 0;

        while (true)
        {
          HCFILE *fp = &extra_info_straight->fp;

          get_next_word (hashcat_ctx, fp, &line_buf, &line_len);

          // post-process rule engine

          char rule_buf_out[RP_PASSWORD_SIZE];

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

        while (true)
        {
          get_next_word (hashcat_ctx, base_fp, &line_buf, &line_len);

          // post-process rule engine

          char rule_buf_out[RP_PASSWORD_SIZE];

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

      while (true)
      {
        HCFILE *fp = &extra_info_straight->fp;

        get_next_word (hashcat_ctx, fp, &line_buf, &line_len);

        // post-process rule engine

        char rule_buf_out[RP_PASSWORD_SIZE];

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

      while (true)
      {
        get_next_word (hashcat_ctx, base_fp, &line_buf, &line_len);

        // post-process rule engine

        char rule_buf_out[RP_PASSWORD_SIZE];

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

    while (true)
    {
      line_len = (u32) fgetl (combs_fp, line_buf, HCBUFSIZ_LARGE);

      line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

      // post-process rule engine

      if (run_rule_engine ((int) user_options_extra->rule_len_r, user_options->rule_buf_r))
      {
        if (line_len >= RP_PASSWORD_SIZE) continue;

        char rule_buf_out[RP_PASSWORD_SIZE];

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
}
