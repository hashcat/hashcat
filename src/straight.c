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
#include "filehandling.h"
#include "folder.h"
#include "rp.h"
#include "rp_cpu.h"
#include "straight.h"
#include "wordlist.h"

static int straight_ctx_add_wl (hashcat_ctx_t *hashcat_ctx, const char *dict)
{
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

int straight_ctx_update_loop (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  induct_ctx_t         *induct_ctx         = hashcat_ctx->induct_ctx;
  logfile_ctx_t        *logfile_ctx        = hashcat_ctx->logfile_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
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

      FILE *fd = fopen (straight_ctx->dict, "rb");

      if (fd == NULL)
      {
        event_log_error (hashcat_ctx, "%s: %s", straight_ctx->dict, strerror (errno));

        return -1;
      }

      const int rc = count_words (hashcat_ctx, fd, straight_ctx->dict, &status_ctx->words_cnt);

      if (rc == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", straight_ctx->dict);

        return -1;
      }

      fclose (fd);

      if (status_ctx->words_cnt == 0)
      {
        logfile_sub_msg ("STOP");

        return 0;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    logfile_sub_string (combinator_ctx->dict1);
    logfile_sub_string (combinator_ctx->dict2);

    if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      FILE *fd = fopen (combinator_ctx->dict1, "rb");

      if (fd == NULL)
      {
        event_log_error (hashcat_ctx, "%s: %s", combinator_ctx->dict1, strerror (errno));

        return -1;
      }

      const int rc = count_words (hashcat_ctx, fd, combinator_ctx->dict1, &status_ctx->words_cnt);

      if (rc == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", combinator_ctx->dict1);

        return -1;
      }

      fclose (fd);
    }
    else if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_RIGHT)
    {
      FILE *fd = fopen (combinator_ctx->dict2, "rb");

      if (fd == NULL)
      {
        event_log_error (hashcat_ctx, "%s: %s", combinator_ctx->dict2, strerror (errno));

        return -1;
      }

      const int rc = count_words (hashcat_ctx, fd, combinator_ctx->dict2, &status_ctx->words_cnt);

      if (rc == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", combinator_ctx->dict2);

        return -1;
      }

      fclose (fd);
    }

    if (status_ctx->words_cnt == 0)
    {
      logfile_sub_msg ("STOP");

      return 0;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    logfile_sub_string (mask_ctx->mask);
  }
  else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
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
    logfile_sub_string (mask_ctx->mask);

    FILE *fd = fopen (straight_ctx->dict, "rb");

    if (fd == NULL)
    {
      event_log_error (hashcat_ctx, "%s: %s", straight_ctx->dict, strerror (errno));

      return -1;
    }

    const int rc = count_words (hashcat_ctx, fd, straight_ctx->dict, &status_ctx->words_cnt);

    if (rc == -1)
    {
      event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of wordlist: %s", straight_ctx->dict);

      return -1;
    }

    fclose (fd);

    if (status_ctx->words_cnt == 0)
    {
      logfile_sub_msg ("STOP");

      return 0;
    }
  }

  return 0;
}

int straight_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  straight_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if (user_options->attack_mode == ATTACK_MODE_BF) return 0;

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
      const int rc_kernel_load = kernel_rules_load (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt);

      if (rc_kernel_load == -1) return -1;
    }
    else if (user_options->rp_gen)
    {
      const int rc_kernel_generate = kernel_rules_generate (hashcat_ctx, &straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt);

      if (rc_kernel_generate == -1) return -1;
    }
  }

  // If we have a NOOP rule then we can process words from wordlists > length 32 for slow hashes

  u32 pw_min = hashconfig->pw_min;
  u32 pw_max = hashconfig->pw_max;

  const bool has_noop = kernel_rules_has_noop (straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt);

  if (has_noop == false)
  {
    switch (user_options_extra->attack_kern)
    {
      case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX;
                                  break;
      case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX;
                                  break;
    }
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      switch (user_options_extra->attack_kern)
      {
        case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX;
                                    break;
        case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX;
                                    break;
      }
    }
    else
    {
      // in this case we can process > 32
    }
  }

  hashconfig->pw_min = pw_min;
  hashconfig->pw_max = pw_max;

  /**
   * wordlist based work
   */

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
    {
      for (int i = 0; i < user_options_extra->hc_workc; i++)
      {
        char *l0_filename = user_options_extra->hc_workv[i];

        // at this point we already verified the path actually exist and is readable

        if (hc_path_is_directory (l0_filename) == true)
        {
          char **dictionary_files;

          dictionary_files = scan_directory (l0_filename);

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
                const int rc = straight_ctx_add_wl (hashcat_ctx, l1_filename);

                if (rc == -1)
                {
                  hcfree (dictionary_files);

                  return -1;
                }
              }
            }
          }

          hcfree (dictionary_files);
        }
        else
        {
          const int rc = straight_ctx_add_wl (hashcat_ctx, l0_filename);

          if (rc == -1) return -1;
        }
      }

      if (straight_ctx->dicts_cnt == 0)
      {
        event_log_error (hashcat_ctx, "No usable dictionary file found.");

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {

  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {

  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    for (int i = 0; i < user_options_extra->hc_workc - 1; i++)
    {
      char *l0_filename = user_options_extra->hc_workv[i];

      // at this point we already verified the path actually exist and is readable

      if (hc_path_is_directory (l0_filename) == true)
      {
        char **dictionary_files;

        dictionary_files = scan_directory (l0_filename);

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
              const int rc = straight_ctx_add_wl (hashcat_ctx, l1_filename);

              if (rc == -1)
              {
                hcfree (dictionary_files);

                return -1;
              }
            }
          }
        }

        hcfree (dictionary_files);
      }
      else
      {
        const int rc = straight_ctx_add_wl (hashcat_ctx, l0_filename);

        if (rc == -1) return -1;
      }
    }

    if (straight_ctx->dicts_cnt == 0)
    {
      event_log_error (hashcat_ctx, "No usable dictionary file found.");

      return -1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    for (int i = 1; i < user_options_extra->hc_workc; i++)
    {
      char *l0_filename = user_options_extra->hc_workv[i];

      // at this point we already verified the path actually exist and is readable

      if (hc_path_is_directory (l0_filename) == true)
      {
        char **dictionary_files;

        dictionary_files = scan_directory (l0_filename);

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
              const int rc = straight_ctx_add_wl (hashcat_ctx, l1_filename);

              if (rc == -1)
              {
                hcfree (dictionary_files);

                return -1;
              }
            }
          }
        }

        hcfree (dictionary_files);
      }
      else
      {
        const int rc = straight_ctx_add_wl (hashcat_ctx, l0_filename);

        if (rc == -1) return -1;
      }
    }

    if (straight_ctx->dicts_cnt == 0)
    {
      event_log_error (hashcat_ctx, "No usable dictionary file found.");

      return -1;
    }
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
