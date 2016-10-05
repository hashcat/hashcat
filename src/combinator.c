/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "combinator.h"
#include "wordlist.h"

int combinator_ctx_init (combinator_ctx_t *combinator_ctx, user_options_t *user_options, user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, dictstat_ctx_t *dictstat_ctx, wl_data_t *wl_data)
{
  combinator_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if ((user_options->attack_mode != ATTACK_MODE_COMBI)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID2)) return 0;

  combinator_ctx->enabled = true;

  combinator_ctx->scratch_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    // nothing to do
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    // display

    char *dictfile1 = user_options_extra->hc_workv[0];
    char *dictfile2 = user_options_extra->hc_workv[1];

    // find the bigger dictionary and use as base

    FILE *fp1 = NULL;
    FILE *fp2 = NULL;

    struct stat tmp_stat;

    if ((fp1 = fopen (dictfile1, "rb")) == NULL)
    {
      log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

      return -1;
    }

    if (stat (dictfile1, &tmp_stat) == -1)
    {
      log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

      fclose (fp1);

      return -1;
    }

    if (S_ISDIR (tmp_stat.st_mode))
    {
      log_error ("ERROR: %s must be a regular file", dictfile1, strerror (errno));

      fclose (fp1);

      return -1;
    }

    if ((fp2 = fopen (dictfile2, "rb")) == NULL)
    {
      log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

      fclose (fp1);

      return -1;
    }

    if (stat (dictfile2, &tmp_stat) == -1)
    {
      log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

      fclose (fp1);
      fclose (fp2);

      return -1;
    }

    if (S_ISDIR (tmp_stat.st_mode))
    {
      log_error ("ERROR: %s must be a regular file", dictfile2, strerror (errno));

      fclose (fp1);
      fclose (fp2);

      return -1;
    }

    combinator_ctx->combs_cnt = 1;

    const u64 words1_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fp1, dictfile1, dictstat_ctx);

    if (words1_cnt == 0)
    {
      log_error ("ERROR: %s: empty file", dictfile1);

      fclose (fp1);
      fclose (fp2);

      return -1;
    }

    combinator_ctx->combs_cnt = 1;

    const u64 words2_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fp2, dictfile2, dictstat_ctx);

    if (words2_cnt == 0)
    {
      log_error ("ERROR: %s: empty file", dictfile2);

      fclose (fp1);
      fclose (fp2);

      return -1;
    }

    fclose (fp1);
    fclose (fp2);

    combinator_ctx->dict1 = dictfile1;
    combinator_ctx->dict2 = dictfile2;

    if (words1_cnt >= words2_cnt)
    {
      combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
      combinator_ctx->combs_cnt  = words2_cnt;
    }
    else
    {
      combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;
      combinator_ctx->combs_cnt  = words1_cnt;

      // we also have to switch wordlist related rules!

      char *tmpc = user_options->rule_buf_l;

      user_options->rule_buf_l = user_options->rule_buf_r;
      user_options->rule_buf_r = tmpc;

      u32 tmpi = user_options_extra->rule_len_l;

      user_options_extra->rule_len_l = user_options_extra->rule_len_r;
      user_options_extra->rule_len_r = tmpi;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    // nothing to do
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;
  }

  return 0;
}

void combinator_ctx_destroy (combinator_ctx_t *combinator_ctx)
{
  if (combinator_ctx->enabled == false) return;

  myfree (combinator_ctx->scratch_buf);

  memset (combinator_ctx, 0, sizeof (combinator_ctx_t));
}
