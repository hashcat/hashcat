/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "shared.h"
#include "wordlist.h"
#include "combinator.h"

int combinator_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx      = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  combinator_ctx->enabled = false;

  if (user_options->hash_info    == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->usage        == true) return 0;
  if (user_options->version      == true) return 0;
  if (user_options->backend_info  > 0)    return 0;

  if ((user_options->attack_mode != ATTACK_MODE_COMBI)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID2)) return 0;

  combinator_ctx->enabled = true;

  if (user_options->slow_candidates == true)
  {
    // this is always need to be COMBINATOR_MODE_BASE_LEFT

    if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      // display

      char *dictfile1 = user_options_extra->hc_workv[0];
      char *dictfile2 = user_options_extra->hc_workv[1];

      // at this point we know the file actually exist
      // find the bigger dictionary and use as base

      if (hc_path_is_file (dictfile1) == false)
      {
        event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile1);

        return -1;
      }

      if (hc_path_is_file (dictfile2) == false)
      {
        event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile2);

        return -1;
      }

      HCFILE fp1;
      HCFILE fp2;

      if (hc_fopen (&fp1, dictfile1, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile1, strerror (errno));

        return -1;
      }

      if (hc_fopen (&fp2, dictfile2, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

        hc_fclose (&fp1);

        return -1;
      }

      combinator_ctx->combs_cnt = 1;

      u64 words1_cnt = 0;

      const int rc1 = count_words (hashcat_ctx, &fp1, dictfile1, &words1_cnt);

      if (rc1 == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile1);

        hc_fclose (&fp1);
        hc_fclose (&fp2);

        return -1;
      }

      if (words1_cnt == 0)
      {
        event_log_error (hashcat_ctx, "%s: empty file.", dictfile1);

        hc_fclose (&fp1);
        hc_fclose (&fp2);

        return -1;
      }

      combinator_ctx->combs_cnt = 1;

      u64 words2_cnt = 0;

      const int rc2 = count_words (hashcat_ctx, &fp2, dictfile2, &words2_cnt);

      hc_fclose (&fp1);
      hc_fclose (&fp2);

      if (rc2 == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile2);

        return -1;
      }

      if (words2_cnt == 0)
      {
        event_log_error (hashcat_ctx, "%s: empty file.", dictfile2);

        return -1;
      }

      combinator_ctx->dict1 = dictfile1;
      combinator_ctx->dict2 = dictfile2;

      combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
      combinator_ctx->combs_cnt  = words2_cnt;
    }
  }
  else
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      if (user_options->attack_mode == ATTACK_MODE_COMBI)
      {
        // display

        char *dictfile1 = user_options_extra->hc_workv[0];
        char *dictfile2 = user_options_extra->hc_workv[1];

        // at this point we know the file actually exist
        // find the bigger dictionary and use as base

        if (hc_path_is_file (dictfile1) == false)
        {
          event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile1);

          return -1;
        }

        if (hc_path_is_file (dictfile2) == false)
        {
          event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile2);

          return -1;
        }

        HCFILE fp1;
        HCFILE fp2;

        if (hc_fopen (&fp1, dictfile1, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile1, strerror (errno));

          return -1;
        }

        if (hc_fopen (&fp2, dictfile2, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

          hc_fclose (&fp1);

          return -1;
        }

        combinator_ctx->combs_cnt = 1;

        u64 words1_cnt = 0;

        const int rc1 = count_words (hashcat_ctx, &fp1, dictfile1, &words1_cnt);

        if (rc1 == -1)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile1);

          hc_fclose (&fp1);
          hc_fclose (&fp2);

          return -1;
        }

        if (words1_cnt == 0)
        {
          event_log_error (hashcat_ctx, "%s: empty file.", dictfile1);

          hc_fclose (&fp1);
          hc_fclose (&fp2);

          return -1;
        }

        combinator_ctx->combs_cnt = 1;

        u64 words2_cnt = 0;

        const int rc2 = count_words (hashcat_ctx, &fp2, dictfile2, &words2_cnt);

        hc_fclose (&fp1);
        hc_fclose (&fp2);

        if (rc2 == -1)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile2);

          return -1;
        }

        if (words2_cnt == 0)
        {
          event_log_error (hashcat_ctx, "%s: empty file.", dictfile2);

          return -1;
        }

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

          const char *tmpc = user_options->rule_buf_l;

          user_options->rule_buf_l = user_options->rule_buf_r;
          user_options->rule_buf_r = tmpc;

          u32 tmpi = user_options_extra->rule_len_l;

          user_options_extra->rule_len_l = user_options_extra->rule_len_r;
          user_options_extra->rule_len_r = tmpi;
        }
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
      {
        combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
      {
        combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;
      }
    }
    else
    {
      // this is always need to be COMBINATOR_MODE_BASE_LEFT

      if (user_options->attack_mode == ATTACK_MODE_COMBI)
      {
        // display

        char *dictfile1 = user_options_extra->hc_workv[0];
        char *dictfile2 = user_options_extra->hc_workv[1];

        // at this point we know the file actually exist
        // find the bigger dictionary and use as base

        if (hc_path_is_file (dictfile1) == false)
        {
          event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile1);

          return -1;
        }

        if (hc_path_is_file (dictfile2) == false)
        {
          event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile2);

          return -1;
        }

        HCFILE fp1;
        HCFILE fp2;

        if (hc_fopen (&fp1, dictfile1, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile1, strerror (errno));

          return -1;
        }

        if (hc_fopen (&fp2, dictfile2, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile2, strerror (errno));

          hc_fclose (&fp1);

          return -1;
        }

        combinator_ctx->combs_cnt = 1;

        u64 words1_cnt = 0;

        const int rc1 = count_words (hashcat_ctx, &fp1, dictfile1, &words1_cnt);

        if (rc1 == -1)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile1);

          hc_fclose (&fp1);
          hc_fclose (&fp2);

          return -1;
        }

        if (words1_cnt == 0)
        {
          event_log_error (hashcat_ctx, "%s: empty file.", dictfile1);

          hc_fclose (&fp1);
          hc_fclose (&fp2);

          return -1;
        }

        combinator_ctx->combs_cnt = 1;

        u64 words2_cnt = 0;

        const int rc2 = count_words (hashcat_ctx, &fp2, dictfile2, &words2_cnt);

        hc_fclose (&fp1);
        hc_fclose (&fp2);

        if (rc2 == -1)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile2);

          return -1;
        }

        if (words2_cnt == 0)
        {
          event_log_error (hashcat_ctx, "%s: empty file.", dictfile2);

          return -1;
        }

        combinator_ctx->dict1 = dictfile1;
        combinator_ctx->dict2 = dictfile2;

        combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
        combinator_ctx->combs_cnt  = words2_cnt;
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
      {
        combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
      {
        mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

        char *dictfile = user_options_extra->hc_workv[1];

        // at this point we know the file actually exist

        if (hc_path_is_file (dictfile) == false)
        {
          event_log_error (hashcat_ctx, "%s: Not a regular file.", dictfile);

          return -1;
        }

        HCFILE fp;

        if (hc_fopen (&fp, dictfile, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

          return -1;
        }

        mask_ctx->bfs_cnt = 1;

        u64 words_cnt = 0;

        const int rc = count_words (hashcat_ctx, &fp, dictfile, &words_cnt);

        hc_fclose (&fp);

        if (rc == -1)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", dictfile);

          return -1;
        }

        combinator_ctx->combs_cnt  = words_cnt;
        combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
      }
    }
  }

  return 0;
}

void combinator_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

  if (combinator_ctx->enabled == false) return;

  memset (combinator_ctx, 0, sizeof (combinator_ctx_t));
}
