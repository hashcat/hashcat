/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif // __APPLE__

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>
#include <inttypes.h>
#include <signal.h>

#if defined (_POSIX)
#include <pthread.h>
#include <pwd.h>
#endif // _POSIX

#include "types.h"
#include "affinity.h"
#include "attack_mode.h"
#include "autotune.h"
#include "benchmark.h"
#include "bitmap.h"
#include "bitops.h"
#include "convert.h"
#include "cpu_aes.h"
#include "cpu_crc32.h"
#include "cpu_des.h"
#include "cpu_md5.h"
#include "cpu_sha1.h"
#include "cpu_sha256.h"
#include "data.h"
#include "debugfile.h"
#include "dictstat.h"
#include "dispatch.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_OpenCL.h"
#include "ext_xnvctrl.h"
#include "filehandling.h"
#include "folder.h"
#include "hash_management.h"
#include "hlfmt.h"
#include "hwmon.h"
#include "inc_hash_constants.h"
#include "induct.h"
#include "interface.h"
#include "locking.h"
#include "logfile.h"
#include "logging.h"
#include "loopback.h"
#include "memory.h"
#include "monitor.h"
#include "mpsp.h"
#include "opencl.h"
#include "outfile_check.h"
#include "outfile.h"
#include "potfile.h"
#include "powertune.h"
#include "remove.h"
#include "restore.h"
#include "rp_cpu.h"
#include "rp.h"
#include "rp_kernel_on_cpu.h"
#include "runtime.h"
#include "session.h"
#include "shared.h"
#include "status.h"
#include "stdout.h"
#include "terminal.h"
#include "thread.h"
#include "timer.h"
#include "tuningdb.h"
#include "usage.h"
#include "user_options.h"
#include "version.h"
#include "weak_hash.h"
#include "wordlist.h"
#include "straight.h"
#include "combinator.h"

extern hc_global_data_t data;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_hwmon;
extern hc_thread_mutex_t mux_display;

extern const int DEFAULT_BENCHMARK_ALGORITHMS_CNT;
extern const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[];

const int comptime = COMPTIME;

static void setup_environment_variables ()
{
  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    static char display[100];

    snprintf (display, sizeof (display) - 1, "DISPLAY=%s", compute);

    putenv (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  if (getenv ("GPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("CPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("GPU_USE_SYNC_OBJECTS") == NULL)
    putenv ((char *) "GPU_USE_SYNC_OBJECTS=1");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");
}

static void setup_umask ()
{
  umask (077);
}

static int setup_console ()
{
  #if defined (_WIN)
  SetConsoleWindowSize (132);

  if (_setmode (_fileno (stdin), _O_BINARY) == -1)
  {
    log_error ("ERROR: %s: %s", "stdin", strerror (errno));

    return -1;
  }

  if (_setmode (_fileno (stdout), _O_BINARY) == -1)
  {
    log_error ("ERROR: %s: %s", "stdout", strerror (errno));

    return -1;
  }

  if (_setmode (_fileno (stderr), _O_BINARY) == -1)
  {
    log_error ("ERROR: %s: %s", "stderr", strerror (errno));

    return -1;
  }
  #endif

  return 0;
}

static void setup_seeding (const user_options_t *user_options, const time_t *proc_start)
{
  if (user_options->rp_gen_seed_chgd == true)
  {
    srand (user_options->rp_gen_seed);
  }
  else
  {
    srand (*proc_start);
  }
}

static void welcome_screen (const user_options_t *user_options, const time_t *proc_start)
{
  if (user_options->quiet       == true) return;
  if (user_options->keyspace    == true) return;
  if (user_options->stdout_flag == true) return;
  if (user_options->show        == true) return;
  if (user_options->left        == true) return;

  if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      log_info ("%s (%s) starting in benchmark-mode...", PROGNAME, VERSION_TAG);
      log_info ("");
    }
    else
    {
      log_info ("# %s (%s) %s", PROGNAME, VERSION_TAG, ctime (proc_start));
    }
  }
  else if (user_options->restore == true)
  {
    log_info ("%s (%s) starting in restore-mode...", PROGNAME, VERSION_TAG);
    log_info ("");
  }
  else
  {
    log_info ("%s (%s) starting...", PROGNAME, VERSION_TAG);
    log_info ("");
  }
}

static void goodbye_screen (const user_options_t *user_options, const time_t *proc_start, const time_t *proc_stop)
{
  if (user_options->quiet       == true) return;
  if (user_options->keyspace    == true) return;
  if (user_options->stdout_flag == true) return;
  if (user_options->show        == true) return;
  if (user_options->left        == true) return;

  log_info_nn ("Started: %s", ctime (proc_start));
  log_info_nn ("Stopped: %s", ctime (proc_stop));
}

static int inner1_loop (user_options_t *user_options, user_options_extra_t *user_options_extra, restore_ctx_t *restore_ctx, logfile_ctx_t *logfile_ctx, induct_ctx_t *induct_ctx, dictstat_ctx_t *dictstat_ctx, loopback_ctx_t *loopback_ctx, opencl_ctx_t *opencl_ctx, hwmon_ctx_t *hwmon_ctx, hashconfig_t *hashconfig, hashes_t *hashes, wl_data_t *wl_data, straight_ctx_t *straight_ctx, combinator_ctx_t *combinator_ctx, mask_ctx_t *mask_ctx)
{
  //opencl_ctx->run_main_level1   = true;
  //opencl_ctx->run_main_level2   = true;
  opencl_ctx->run_main_level3   = true;
  opencl_ctx->run_thread_level1 = true;
  opencl_ctx->run_thread_level2 = true;

  /**
   * word len
   */

  uint pw_min = hashconfig_general_pw_min (hashconfig);
  uint pw_max = hashconfig_general_pw_max (hashconfig);

  /**
   * If we have a NOOP rule then we can process words from wordlists > length 32 for slow hashes
   */

  const bool has_noop = kernel_rules_has_noop (straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt);

  if (has_noop == false)
  {
    switch (user_options_extra->attack_kern)
    {
      case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                  break;
      case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                  break;
    }
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      switch (user_options_extra->attack_kern)
      {
        case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
        case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
      }
    }
    else
    {
      // in this case we can process > 32
    }
  }

  /**
   * Update attack-mode specific stuff
   */

  if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
  {
    if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      // nothing yet
    }
    else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
    {
      mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

      const int rc_mask_file = mask_ctx_parse_maskfile (mask_ctx, user_options, hashconfig);

      if (rc_mask_file == -1) return -1;

      mask_ctx->css_buf = mp_gen_css (mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, &mask_ctx->css_cnt, hashconfig, user_options);

      uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

      mp_css_to_uniq_tbl (mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      combinator_ctx->combs_cnt = sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf);

      const int rc_update_mp = opencl_session_update_mp (opencl_ctx, mask_ctx);

      if (rc_update_mp == -1) return -1;
    }

    //const int rc_update_combinator = opencl_session_update_combinator (opencl_ctx, hashconfig, combinator_ctx);

    //if (rc_update_combinator == -1) return -1;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

    const int rc_mask_file = mask_ctx_parse_maskfile (mask_ctx, user_options, hashconfig);

    if (rc_mask_file == -1) return -1;

    if (user_options->attack_mode == ATTACK_MODE_BF) // always true
    {
      mask_ctx->css_buf = mp_gen_css (mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, &mask_ctx->css_cnt, hashconfig, user_options);

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        u32 css_cnt_unicode = mask_ctx->css_cnt * 2;

        cs_t *css_buf_unicode = (cs_t *) mycalloc (css_cnt_unicode, sizeof (cs_t));

        for (uint i = 0, j = 0; i < mask_ctx->css_cnt; i += 1, j += 2)
        {
          memcpy (&css_buf_unicode[j + 0], &mask_ctx->css_buf[i], sizeof (cs_t));

          css_buf_unicode[j + 1].cs_buf[0] = 0;
          css_buf_unicode[j + 1].cs_len    = 1;
        }

        myfree (mask_ctx->css_buf);

        mask_ctx->css_buf = css_buf_unicode;
        mask_ctx->css_cnt = css_cnt_unicode;
      }

      // check if mask is not too large or too small for pw_min/pw_max  (*2 if unicode)

      uint mask_min = pw_min;
      uint mask_max = pw_max;

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        mask_min *= 2;
        mask_max *= 2;
      }

      if ((mask_ctx->css_cnt < mask_min) || (mask_ctx->css_cnt > mask_max))
      {
        if (mask_ctx->css_cnt < mask_min)
        {
          log_info ("WARNING: Skipping mask '%s' because it is smaller than the minimum password length", mask_ctx->mask);
        }

        if (mask_ctx->css_cnt > mask_max)
        {
          log_info ("WARNING: Skipping mask '%s' because it is larger than the maximum password length", mask_ctx->mask);
        }

        // skip to next mask

        logfile_sub_msg ("STOP");

        return 0;
      }

      u32 css_cnt_orig = mask_ctx->css_cnt;

      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          uint  salt_len = (uint)   hashes->salts_buf[0].salt_len;
          char *salt_buf = (char *) hashes->salts_buf[0].salt_buf;

          uint css_cnt_salt = mask_ctx->css_cnt + salt_len;

          cs_t *css_buf_salt = (cs_t *) mycalloc (css_cnt_salt, sizeof (cs_t));

          memcpy (css_buf_salt, mask_ctx->css_buf, mask_ctx->css_cnt * sizeof (cs_t));

          for (uint i = 0, j = mask_ctx->css_cnt; i < salt_len; i++, j++)
          {
            css_buf_salt[j].cs_buf[0] = salt_buf[i];
            css_buf_salt[j].cs_len    = 1;
          }

          myfree (mask_ctx->css_buf);

          mask_ctx->css_buf = css_buf_salt;
          mask_ctx->css_cnt = css_cnt_salt;
        }
      }

      uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

      mp_css_to_uniq_tbl (mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      data.words_cnt = sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf);

      // copy + args

      uint css_cnt_l = mask_ctx->css_cnt;
      uint css_cnt_r;

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (css_cnt_orig < 6)
        {
          css_cnt_r = 1;
        }
        else if (css_cnt_orig == 6)
        {
          css_cnt_r = 2;
        }
        else
        {
          if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
          {
            if (css_cnt_orig == 8 || css_cnt_orig == 10)
            {
              css_cnt_r = 2;
            }
            else
            {
              css_cnt_r = 4;
            }
          }
          else
          {
            if ((mask_ctx->css_buf[0].cs_len * mask_ctx->css_buf[1].cs_len * mask_ctx->css_buf[2].cs_len) > 256)
            {
              css_cnt_r = 3;
            }
            else
            {
              css_cnt_r = 4;
            }
          }
        }
      }
      else
      {
        css_cnt_r = 1;

        /* unfinished code?
        int sum = css_buf[css_cnt_r - 1].cs_len;

        for (uint i = 1; i < 4 && i < css_cnt; i++)
        {
          if (sum > 1) break; // we really don't need alot of amplifier them for slow hashes

          css_cnt_r++;

          sum *= css_buf[css_cnt_r - 1].cs_len;
        }
        */
      }

      css_cnt_l -= css_cnt_r;

      mask_ctx->bfs_cnt = sp_get_sum (0, css_cnt_r, mask_ctx->root_css_buf);

      const int rc_update_mp_rl = opencl_session_update_mp_rl (opencl_ctx, mask_ctx, css_cnt_l, css_cnt_r);

      if (rc_update_mp_rl == -1) return -1;
    }
  }

  /**
   * update induction directory scan
   */

  induct_ctx_scan (induct_ctx);

  /**
   * dictstat read
   */

  dictstat_read (dictstat_ctx);

  /**
   * dictionary pad
   */

  uint   dictcnt   = 0;
  char **dictfiles = NULL;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
    {
      int wls_left = restore_ctx->argc - (user_options_extra->optind + 1);

      for (int i = 0; i < wls_left; i++)
      {
        char *l0_filename = restore_ctx->argv[user_options_extra->optind + 1 + i];

        struct stat l0_stat;

        if (stat (l0_filename, &l0_stat) == -1)
        {
          log_error ("ERROR: %s: %s", l0_filename, strerror (errno));

          return -1;
        }

        uint is_dir = S_ISDIR (l0_stat.st_mode);

        if (is_dir == 0)
        {
          dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

          dictcnt++;

          dictfiles[dictcnt - 1] = l0_filename;
        }
        else
        {
          // do not allow --keyspace w/ a directory

          if (user_options->keyspace == true)
          {
            log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

            return -1;
          }

          char **dictionary_files = NULL;

          dictionary_files = scan_directory (l0_filename);

          if (dictionary_files != NULL)
          {
            qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

            for (int d = 0; dictionary_files[d] != NULL; d++)
            {
              char *l1_filename = dictionary_files[d];

              struct stat l1_stat;

              if (stat (l1_filename, &l1_stat) == -1)
              {
                log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                return -1;
              }

              if (S_ISREG (l1_stat.st_mode))
              {
                dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                dictcnt++;

                dictfiles[dictcnt - 1] = mystrdup (l1_filename);
              }
            }
          }

          myfree (dictionary_files);
        }
      }

      if (dictcnt < 1)
      {
        log_error ("ERROR: No usable dictionary file found.");

        return -1;
      }
    }
    else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      dictcnt = 1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    // display

    char *dictfile1 = restore_ctx->argv[user_options_extra->optind + 1 + 0];
    char *dictfile2 = restore_ctx->argv[user_options_extra->optind + 1 + 1];

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

    data.dictfile  = dictfile1;
    data.dictfile2 = dictfile2;

    if (words1_cnt >= words2_cnt)
    {
      combinator_ctx->combs_cnt  = words2_cnt;
      combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;

      dictfiles = &data.dictfile;

      dictcnt = 1;
    }
    else
    {
      combinator_ctx->combs_cnt  = words1_cnt;
      combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;

      dictfiles = &data.dictfile2;

      dictcnt = 1;

      // we also have to switch wordlist related rules!

      char *tmpc = user_options->rule_buf_l;

      user_options->rule_buf_l = user_options->rule_buf_r;
      user_options->rule_buf_r = tmpc;

      int   tmpi = user_options_extra->rule_len_l;

      user_options_extra->rule_len_l = user_options_extra->rule_len_r;
      user_options_extra->rule_len_r = tmpi;
    }

    const int rc_update_combinator = opencl_session_update_combinator (opencl_ctx, hashconfig, combinator_ctx);

    if (rc_update_combinator == -1) return -1;
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->benchmark == true)
    {
      pw_min = mp_get_length (mask_ctx->mask);
      pw_max = pw_min;
    }

    /* i think we can do this better
    if (user_options->increment == true)
    {
      if (user_options->increment_min > pw_min) pw_min = user_options->increment_min;
      if (user_options->increment_max < pw_max) pw_max = user_options->increment_max;
    }
    */

    dictfiles = (char **) mycalloc (1, sizeof (char *));
    dictfiles[0] = "DUMMY";

    dictcnt = 1;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;

    // mod -- moved to mpsp.c

    // base

    int wls_left = restore_ctx->argc - (user_options_extra->optind + 2);

    for (int i = 0; i < wls_left; i++)
    {
      char *filename = restore_ctx->argv[user_options_extra->optind + 1 + i];

      struct stat file_stat;

      if (stat (filename, &file_stat) == -1)
      {
        log_error ("ERROR: %s: %s", filename, strerror (errno));

        return -1;
      }

      uint is_dir = S_ISDIR (file_stat.st_mode);

      if (is_dir == 0)
      {
        dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

        dictcnt++;

        dictfiles[dictcnt - 1] = filename;
      }
      else
      {
        // do not allow --keyspace w/ a directory

        if (user_options->keyspace == true)
        {
          log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

          return -1;
        }

        char **dictionary_files = NULL;

        dictionary_files = scan_directory (filename);

        if (dictionary_files != NULL)
        {
          qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

          for (int d = 0; dictionary_files[d] != NULL; d++)
          {
            char *l1_filename = dictionary_files[d];

            struct stat l1_stat;

            if (stat (l1_filename, &l1_stat) == -1)
            {
              log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

              return -1;
            }

            if (S_ISREG (l1_stat.st_mode))
            {
              dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

              dictcnt++;

              dictfiles[dictcnt - 1] = mystrdup (l1_filename);
            }
          }
        }

        myfree (dictionary_files);
      }
    }

    if (dictcnt < 1)
    {
      log_error ("ERROR: No usable dictionary file found.");

      return -1;
    }

    const int rc_update_combinator = opencl_session_update_combinator (opencl_ctx, hashconfig, combinator_ctx);

    if (rc_update_combinator == -1) return -1;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;

    // mod -- moved to mpsp.c

    // base

    int wls_left = restore_ctx->argc - (user_options_extra->optind + 2);

    for (int i = 0; i < wls_left; i++)
    {
      char *filename = restore_ctx->argv[user_options_extra->optind + 2 + i];

      struct stat file_stat;

      if (stat (filename, &file_stat) == -1)
      {
        log_error ("ERROR: %s: %s", filename, strerror (errno));

        return -1;
      }

      uint is_dir = S_ISDIR (file_stat.st_mode);

      if (is_dir == 0)
      {
        dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

        dictcnt++;

        dictfiles[dictcnt - 1] = filename;
      }
      else
      {
        // do not allow --keyspace w/ a directory

        if (user_options->keyspace == true)
        {
          log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

          return -1;
        }

        char **dictionary_files = NULL;

        dictionary_files = scan_directory (filename);

        if (dictionary_files != NULL)
        {
          qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

          for (int d = 0; dictionary_files[d] != NULL; d++)
          {
            char *l1_filename = dictionary_files[d];

            struct stat l1_stat;

            if (stat (l1_filename, &l1_stat) == -1)
            {
              log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

              return -1;
            }

            if (S_ISREG (l1_stat.st_mode))
            {
              dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

              dictcnt++;

              dictfiles[dictcnt - 1] = mystrdup (l1_filename);
            }
          }
        }

        myfree (dictionary_files);
      }
    }

    if (dictcnt < 1)
    {
      log_error ("ERROR: No usable dictionary file found.");

      return -1;
    }

    const int rc_update_combinator = opencl_session_update_combinator (opencl_ctx, hashconfig, combinator_ctx);

    if (rc_update_combinator == -1) return -1;
  }

  hashconfig->pw_min = pw_min;
  hashconfig->pw_max = pw_max;

  /**
   * prevent the user from using --skip/--limit together w/ maskfile and or dictfile
   */

  if (user_options->skip != 0 || user_options->limit != 0)
  {
    if ((mask_ctx->masks_cnt > 1) || (dictcnt > 1))
    {
      log_error ("ERROR: --skip/--limit are not supported with --increment or mask files");

      return -1;
    }
  }

  /**
   * prevent the user from using --keyspace together w/ maskfile and or dictfile
   */

  if (user_options->keyspace == true)
  {
    if ((mask_ctx->masks_cnt > 1) || (dictcnt > 1))
    {
      log_error ("ERROR: --keyspace is not supported with --increment or mask files");

      return -1;
    }
  }

  /**
   * main inner loop
   */

  restore_data_t *rd = restore_ctx->rd;

  for (uint dictpos = rd->dictpos; dictpos < dictcnt; dictpos++)
  {
    if (opencl_ctx->run_main_level3 == false) break;

    //opencl_ctx->run_main_level1   = true;
    //opencl_ctx->run_main_level2   = true;
    //opencl_ctx->run_main_level3   = true;
    opencl_ctx->run_thread_level1 = true;
    opencl_ctx->run_thread_level2 = true;

    rd->dictpos = dictpos;

    logfile_generate_subid (logfile_ctx);

    logfile_sub_msg ("START");

    memset (data.words_progress_done,     0, hashes->salts_cnt * sizeof (u64));
    memset (data.words_progress_rejected, 0, hashes->salts_cnt * sizeof (u64));
    memset (data.words_progress_restored, 0, hashes->salts_cnt * sizeof (u64));

    memset (data.cpt_buf, 0, CPT_BUF * sizeof (cpt_t));

    data.cpt_pos = 0;

    data.cpt_start = time (NULL);

    data.cpt_total = 0;

    data.words_cur = 0;

    if (rd->words_cur)
    {
      data.words_cur = rd->words_cur;

      user_options->skip = 0;
    }

    if (user_options->skip)
    {
      data.words_cur = user_options->skip;

      user_options->skip = 0;
    }

    data.ms_paused = 0;

    opencl_session_reset (opencl_ctx);

    // figure out some workload

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (user_options_extra->wordlist_mode == WL_MODE_FILE)
      {
        char *dictfile = NULL;

        if (induct_ctx->induction_dictionaries_cnt)
        {
          dictfile = induct_ctx->induction_dictionaries[0];
        }
        else
        {
          dictfile = dictfiles[dictpos];
        }

        data.dictfile = dictfile;

        logfile_sub_string (dictfile);

        for (uint i = 0; i < user_options->rp_files_cnt; i++)
        {
          logfile_sub_var_string ("rulefile", user_options->rp_files[i]);
        }

        FILE *fd2 = fopen (dictfile, "rb");

        if (fd2 == NULL)
        {
          log_error ("ERROR: %s: %s", dictfile, strerror (errno));

          return -1;
        }

        data.words_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fd2, dictfile, dictstat_ctx);

        fclose (fd2);

        if (data.words_cnt == 0)
        {
          logfile_sub_msg ("STOP");

          continue;
        }
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {
      char *dictfile  = data.dictfile;
      char *dictfile2 = data.dictfile2;

      logfile_sub_string (dictfile);
      logfile_sub_string (dictfile2);

      if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
      {
        FILE *fd2 = fopen (dictfile, "rb");

        if (fd2 == NULL)
        {
          log_error ("ERROR: %s: %s", dictfile, strerror (errno));

          return -1;
        }

        data.words_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fd2, dictfile, dictstat_ctx);

        fclose (fd2);
      }
      else if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        FILE *fd2 = fopen (dictfile2, "rb");

        if (fd2 == NULL)
        {
          log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

          return -1;
        }

        data.words_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fd2, dictfile2, dictstat_ctx);

        fclose (fd2);
      }

      if (data.words_cnt == 0)
      {
        logfile_sub_msg ("STOP");

        continue;
      }
    }
    else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
    {
      char *dictfile = NULL;

      if (induct_ctx->induction_dictionaries_cnt)
      {
        dictfile = induct_ctx->induction_dictionaries[0];
      }
      else
      {
        dictfile = dictfiles[dictpos];
      }

      data.dictfile = dictfile;

      logfile_sub_string (dictfile);
      logfile_sub_string (mask_ctx->mask);

      FILE *fd2 = fopen (dictfile, "rb");

      if (fd2 == NULL)
      {
        log_error ("ERROR: %s: %s", dictfile, strerror (errno));

        return -1;
      }

      data.words_cnt = count_words (wl_data, user_options, user_options_extra, straight_ctx, combinator_ctx, fd2, dictfile, dictstat_ctx);

      fclose (fd2);

      if (data.words_cnt == 0)
      {
        logfile_sub_msg ("STOP");

        continue;
      }
    }
    else if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      logfile_sub_string (mask_ctx->mask);
    }

    u64 words_base = data.words_cnt;

    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if (straight_ctx->kernel_rules_cnt)
      {
        words_base /= straight_ctx->kernel_rules_cnt;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      if (combinator_ctx->combs_cnt)
      {
        words_base /= combinator_ctx->combs_cnt;
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      if (mask_ctx->bfs_cnt)
      {
        words_base /= mask_ctx->bfs_cnt;
      }
    }

    data.words_base = words_base;

    if (user_options->keyspace == true)
    {
      log_info ("%" PRIu64 "", words_base);

      return 0;
    }

    if (data.words_cur > data.words_base)
    {
      log_error ("ERROR: Restore value greater keyspace");

      return -1;
    }

    if (data.words_cur)
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        for (uint i = 0; i < hashes->salts_cnt; i++)
        {
          data.words_progress_restored[i] = data.words_cur * straight_ctx->kernel_rules_cnt;
        }
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        for (uint i = 0; i < hashes->salts_cnt; i++)
        {
          data.words_progress_restored[i] = data.words_cur * combinator_ctx->combs_cnt;
        }
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        for (uint i = 0; i < hashes->salts_cnt; i++)
        {
          data.words_progress_restored[i] = data.words_cur * mask_ctx->bfs_cnt;
        }
      }
    }

    /*
     * Update dictionary statistic
     */

    dictstat_write (dictstat_ctx);

    /**
     * Update loopback file
     */

    if (user_options->loopback == true)
    {
      loopback_write_open (loopback_ctx, induct_ctx->root_directory);
    }

    /**
     * some algorithms have a maximum kernel-loops count
     */

    for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if (device_param->kernel_loops_min < device_param->kernel_loops_max)
      {
        u32 innerloop_cnt = 0;

        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = straight_ctx->kernel_rules_cnt;
          else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = combinator_ctx->combs_cnt;
          else if (user_options_extra->attack_kern == ATTACK_KERN_BF)        innerloop_cnt = mask_ctx->bfs_cnt;
        }
        else
        {
          innerloop_cnt = hashes->salts_buf[0].salt_iter;
        }

        if ((innerloop_cnt >= device_param->kernel_loops_min) &&
            (innerloop_cnt <= device_param->kernel_loops_max))
        {
          device_param->kernel_loops_max = innerloop_cnt;
        }
      }
    }

    /**
     * create autotune threads
     */

    hc_thread_t *c_threads = (hc_thread_t *) mycalloc (opencl_ctx->devices_cnt, sizeof (hc_thread_t));

    opencl_ctx->devices_status = STATUS_AUTOTUNE;

    for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      hc_thread_create (c_threads[device_id], thread_autotune, device_param);
    }

    hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

    // autotune modified kernel_accel, which modifies opencl_ctx->kernel_power_all

    opencl_ctx_devices_update_power (opencl_ctx, user_options, user_options_extra);

    /**
     * create cracker threads
     */

    opencl_ctx->devices_status = STATUS_RUNNING;

    hc_timer_set (&data.timer_running);

    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      if ((user_options->quiet == false) && (user_options->status == false) && (user_options->benchmark == false))
      {
        if (user_options->quiet == false) send_prompt ();
      }
    }
    else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      if (user_options->quiet == false) log_info ("Starting attack in stdin mode...");
      if (user_options->quiet == false) log_info ("");
    }

    time_t runtime_start;

    time (&runtime_start);

    data.runtime_start = runtime_start;

    data.prepare_time = runtime_start - data.prepare_start;

    for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
      {
        hc_thread_create (c_threads[device_id], thread_calc_stdin, device_param);
      }
      else
      {
        hc_thread_create (c_threads[device_id], thread_calc, device_param);
      }
    }

    hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

    myfree (c_threads);

    if ((opencl_ctx->devices_status != STATUS_CRACKED)
     && (opencl_ctx->devices_status != STATUS_ABORTED)
     && (opencl_ctx->devices_status != STATUS_QUIT)
     && (opencl_ctx->devices_status != STATUS_BYPASS))
    {
      opencl_ctx->devices_status = STATUS_EXHAUSTED;
    }

    if (opencl_ctx->devices_status == STATUS_EXHAUSTED)
    {
      rd->words_cur = 0;
    }

    logfile_sub_var_uint ("status-after-work", opencl_ctx->devices_status);

    if (induct_ctx->induction_dictionaries_cnt)
    {
      unlink (induct_ctx->induction_dictionaries[0]);
    }

    myfree (induct_ctx->induction_dictionaries);

    induct_ctx_scan (induct_ctx);

    if (user_options->benchmark == true)
    {
      status_benchmark (opencl_ctx, hashconfig, user_options);

      log_info ("");
    }
    else
    {
      if (user_options->quiet == false)
      {
        clear_prompt ();

        if (hashes->digests_saved != hashes->digests_done) log_info ("");

        status_display (opencl_ctx, hwmon_ctx, hashconfig, hashes, restore_ctx, user_options, user_options_extra, straight_ctx, combinator_ctx, mask_ctx);

        log_info ("");
      }
      else
      {
        if (user_options->status == true)
        {
          status_display (opencl_ctx, hwmon_ctx, hashconfig, hashes, restore_ctx, user_options, user_options_extra, straight_ctx, combinator_ctx, mask_ctx);

          log_info ("");
        }
      }
    }

    if (induct_ctx->induction_dictionaries_cnt)
    {
      // yeah, this next statement is a little hack to make sure that --loopback runs correctly (because with it we guarantee that the loop iterates one more time)

      dictpos--;
    }

    /**
     * Update loopback file
     */

    if (user_options->loopback == true)
    {
      loopback_write_close (loopback_ctx);
    }

    time_t runtime_stop;

    time (&runtime_stop);

    data.runtime_stop = runtime_stop;

    logfile_sub_uint (runtime_start);
    logfile_sub_uint (runtime_stop);

    time (&data.prepare_start);

    logfile_sub_msg ("STOP");

    // finalize task

    if (opencl_ctx->run_main_level3 == false) break;
  }

  // free memory


  return 0;
}

static int outer_loop (user_options_t *user_options, user_options_extra_t *user_options_extra, restore_ctx_t *restore_ctx, folder_config_t *folder_config, logfile_ctx_t *logfile_ctx, tuning_db_t *tuning_db, induct_ctx_t *induct_ctx, outcheck_ctx_t *outcheck_ctx, outfile_ctx_t *outfile_ctx, potfile_ctx_t *potfile_ctx, dictstat_ctx_t *dictstat_ctx, loopback_ctx_t *loopback_ctx, opencl_ctx_t *opencl_ctx, hwmon_ctx_t *hwmon_ctx)
{
  opencl_ctx->devices_status = STATUS_INIT;

  //opencl_ctx->run_main_level1   = true;
  opencl_ctx->run_main_level2   = true;
  opencl_ctx->run_main_level3   = true;
  opencl_ctx->run_thread_level1 = true;
  opencl_ctx->run_thread_level2 = true;

  /*
   * We need to reset 'rd' in benchmark mode otherwise when the user hits 'bypass'
   * the following algos are skipped entirely
   * still needed? there's no more bypass in benchmark mode
   * also there's no signs of special benchmark handling in the branch
   */

  /*
  if (algorithm_pos > 0)
  {
    myfree (rd);

    rd = init_restore (argc, argv, user_options);

    data.rd = rd;
  }
  */

  /**
   * setup prepare timer
   */

  time (&data.prepare_start);

  /**
   * setup variables and buffers depending on hash_mode
   */

  hashconfig_t *hashconfig = (hashconfig_t *) mymalloc (sizeof (hashconfig_t));

  data.hashconfig = hashconfig;

  const int rc_hashconfig = hashconfig_init (hashconfig, user_options);

  if (rc_hashconfig == -1) return -1;

  /**
   * potfile show/left depends on hash_mode, so it's called here first time
   */

  if (user_options->show == true || user_options->left == true)
  {
    outfile_write_open (outfile_ctx);

    SUPPRESS_OUTPUT = 1;

    potfile_read_open  (potfile_ctx);

    potfile_read_parse (potfile_ctx, hashconfig);

    potfile_read_close (potfile_ctx);

    SUPPRESS_OUTPUT = 0;
  }

  /**
   * load hashes, stage 1
   */

  hashes_t *hashes = (hashes_t *) mymalloc (sizeof (hashes_t));

  data.hashes = hashes;

  const int rc_hashes_init_stage1 = hashes_init_stage1 (hashes, hashconfig, potfile_ctx, outfile_ctx, user_options, restore_ctx->argv[user_options_extra->optind]);

  if (rc_hashes_init_stage1 == -1) return -1;

  if ((user_options->keyspace == false) && (user_options->stdout_flag == false) && (user_options->opencl_info == false))
  {
    if (hashes->hashes_cnt == 0)
    {
      log_error ("ERROR: No hashes loaded");

      return -1;
    }
  }

  /**
   * potfile show/left final
   */

  if (user_options->show == true || user_options->left == true)
  {
    outfile_write_close (outfile_ctx);

    potfile_hash_free (potfile_ctx, hashconfig);

    //if (user_options->quiet == false) log_info_nn ("");

    return 0;
  }

  /**
   * Potfile removes
   */

  int potfile_remove_cracks = 0;

  if (user_options->potfile_disable == 0)
  {
    if (user_options->quiet == false) log_info_nn ("Comparing hashes with potfile entries...");

    potfile_remove_cracks = potfile_remove_parse (potfile_ctx, hashconfig, hashes);
  }

  /**
   * load hashes, stage 2, remove duplicates, build base structure
   */

  const u32 hashes_cnt_orig = hashes->hashes_cnt;

  const int rc_hashes_init_stage2 = hashes_init_stage2 (hashes, hashconfig, opencl_ctx, user_options);

  if (rc_hashes_init_stage2 == -1) return -1;

  /**
   * load hashes, stage 3, automatic Optimizers
   */

  const int rc_hashes_init_stage3 = hashes_init_stage3 (hashes, hashconfig, user_options);

  if (rc_hashes_init_stage3 == -1) return -1;

  hashes_logger (hashes, logfile_ctx);

  /**
   * bitmaps
   */

  bitmap_ctx_t *bitmap_ctx = (bitmap_ctx_t *) mymalloc (sizeof (bitmap_ctx_t));

  data.bitmap_ctx = bitmap_ctx;

  bitmap_ctx_init (bitmap_ctx, user_options, hashconfig, hashes);

  /**
   * Wordlist allocate buffer
   */

  wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

  wl_data_init (wl_data, user_options, hashconfig);

  /**
   * straight mode init
   */

  straight_ctx_t *straight_ctx = (straight_ctx_t *) mymalloc (sizeof (straight_ctx_t));

  data.straight_ctx = straight_ctx;

  const int rc_straight_init = straight_ctx_init (straight_ctx, user_options);

  if (rc_straight_init == -1) return -1;

  /**
   * straight mode init
   */

  combinator_ctx_t *combinator_ctx = (combinator_ctx_t *) mymalloc (sizeof (combinator_ctx_t));

  data.combinator_ctx = combinator_ctx;

  const int rc_combinator_init = combinator_ctx_init (combinator_ctx, user_options);

  if (rc_combinator_init == -1) return -1;

  /**
   * charsets : keep them together for more easy maintainnce
   */

  mask_ctx_t *mask_ctx = (mask_ctx_t *) mymalloc (sizeof (mask_ctx_t));

  data.mask_ctx = mask_ctx;

  const int rc_mask_init = mask_ctx_init (mask_ctx, user_options, user_options_extra, folder_config, restore_ctx, hashconfig);

  if (rc_mask_init == -1) return -1;

  /**
   * enable custom signal handler(s)
   */

  if (user_options->benchmark == false)
  {
    hc_signal (sigHandler_default);
  }
  else
  {
    hc_signal (sigHandler_benchmark);
  }

  /**
   * inform the user
   */

  if (user_options->quiet == false)
  {
    log_info ("Hashes: %u digests; %u unique digests, %u unique salts", hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);

    log_info ("Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_ctx->bitmap_bits, bitmap_ctx->bitmap_nums, bitmap_ctx->bitmap_mask, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_shift1, bitmap_ctx->bitmap_shift2);

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      log_info ("Rules: %u", straight_ctx->kernel_rules_cnt);
    }

    if (user_options->quiet == false) log_info ("");

    if (hashconfig->opti_type)
    {
      log_info ("Applicable Optimizers:");

      for (uint i = 0; i < 32; i++)
      {
        const uint opti_bit = 1u << i;

        if (hashconfig->opti_type & opti_bit) log_info ("* %s", stroptitype (opti_bit));
      }
    }

    if (user_options->quiet == false) log_info ("");

    /**
     * Watchdog and Temperature balance
     */

    if (hwmon_ctx->enabled == false && user_options->gpu_temp_disable == false)
    {
      log_info ("Watchdog: Hardware Monitoring Interface not found on your system");
    }

    if (hwmon_ctx->enabled == true && user_options->gpu_temp_abort > 0)
    {
      log_info ("Watchdog: Temperature abort trigger set to %uc", user_options->gpu_temp_abort);
    }
    else
    {
      log_info ("Watchdog: Temperature abort trigger disabled");
    }

    if (hwmon_ctx->enabled == true && user_options->gpu_temp_retain > 0)
    {
      log_info ("Watchdog: Temperature retain trigger set to %uc", user_options->gpu_temp_retain);
    }
    else
    {
      log_info ("Watchdog: Temperature retain trigger disabled");
    }

    if (user_options->quiet == false) log_info ("");
  }

  #if defined (DEBUG)
  if (user_options->benchmark == true) log_info ("Hashmode: %d", hashconfig->hash_mode);
  #endif

  if (user_options->quiet == false) log_info_nn ("Initializing device kernels and memory...");

  u64 *words_progress_done     = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
  u64 *words_progress_rejected = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
  u64 *words_progress_restored = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));

  data.words_progress_done     = words_progress_done;
  data.words_progress_rejected = words_progress_rejected;
  data.words_progress_restored = words_progress_restored;

  /*
  session_ctx_t *session_ctx = (session_ctx_t *) mymalloc (sizeof (session_ctx_t));

  data.session_ctx = session_ctx;

  session_ctx_init (session_ctx);
  */

  opencl_session_begin (opencl_ctx, hashconfig, hashes, straight_ctx, user_options, user_options_extra, folder_config, bitmap_ctx, tuning_db);

  if (user_options->quiet == false) log_info_nn ("");

  /**
   * In benchmark-mode, inform user which algorithm is checked
   */

  if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      char *hash_type = strhashtype (hashconfig->hash_mode); // not a bug

      log_info ("Hashtype: %s", hash_type);
      log_info ("");
    }
  }

  /**
   * weak hash check is the first to write to potfile, so open it for writing from here
   */

  potfile_write_open (potfile_ctx);

  /**
   * weak hash check
   */

  if (user_options->weak_hash_threshold >= hashes->salts_cnt)
  {
    hc_device_param_t *device_param = NULL;

    for (uint device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      break;
    }

    if (user_options->quiet == false) log_info_nn ("Checking for weak hashes...");

    for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
    {
      weak_hash_check (opencl_ctx, device_param, user_options, user_options_extra, straight_ctx, combinator_ctx, hashconfig, hashes, salt_pos);
    }
  }

  /**
   * status and monitor threads
   */

  uint inner_threads_cnt = 0;

  hc_thread_t *inner_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  data.shutdown_inner = false;

  /**
    * Outfile remove
    */

  if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
  {
    hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, NULL);

    inner_threads_cnt++;

    if (outcheck_ctx->enabled == true)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_outfile_remove, NULL);

      inner_threads_cnt++;
    }
  }

  /**
   * main loop
   */

  if (user_options->quiet == false)
  {
    if (potfile_remove_cracks > 0)
    {
      if (potfile_remove_cracks == 1)
      {
        log_info ("INFO: Removed 1 hash found in potfile");
        log_info ("");
      }
      else
      {
        log_info ("INFO: Removed %d hashes found in potfile", potfile_remove_cracks);
        log_info ("");
      }
    }
  }

  // still needed?
  // mask_ctx->masks_cnt = maskcnt;

  restore_data_t *rd = restore_ctx->rd;

  if (mask_ctx->masks_cnt)
  {
    for (uint masks_pos = rd->masks_pos; masks_pos < mask_ctx->masks_cnt; masks_pos++)
    {
      if (masks_pos > rd->masks_pos)
      {
        rd->dictpos = 0;
      }

      rd->masks_pos = masks_pos;

      mask_ctx->masks_pos = masks_pos;

      const int rc_inner1_loop = inner1_loop (user_options, user_options_extra, restore_ctx, logfile_ctx, induct_ctx, dictstat_ctx, loopback_ctx, opencl_ctx, hwmon_ctx, hashconfig, hashes, wl_data, straight_ctx, combinator_ctx, mask_ctx);

      if (rc_inner1_loop == -1) return -1;

      if (opencl_ctx->run_main_level2 == false) break;
    }
  }
  else
  {
    const int rc_inner1_loop = inner1_loop (user_options, user_options_extra, restore_ctx, logfile_ctx, induct_ctx, dictstat_ctx, loopback_ctx, opencl_ctx, hwmon_ctx, hashconfig, hashes, wl_data, straight_ctx, combinator_ctx, mask_ctx);

    if (rc_inner1_loop == -1) return -1;
  }

  /* ???????? TODO
  // problems could occur if already at startup everything was cracked (because of .pot file reading etc), we must set some variables here to avoid NULL pointers
  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
    {
      if (data.dictfile == NULL)
      {
        if (dictfiles != NULL)
        {
          data.dictfile = dictfiles[0];

          hc_timer_set (&data.timer_running);
        }
      }
    }
  }
  // NOTE: combi is okay because it is already set beforehand
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1 || user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (data.dictfile == NULL)
    {
      if (dictfiles != NULL)
      {
        hc_timer_set (&data.timer_running);

        data.dictfile = dictfiles[0];
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (mask_ctx->mask == NULL)
    {
      hc_timer_set (&data.timer_running);

      mask_ctx->mask = mask_ctx->masks[0];
    }
  }
  */

  // if cracked / aborted remove last induction dictionary
  induct_ctx_cleanup (induct_ctx);

  // wait for inner threads

  data.shutdown_inner = true;

  for (uint thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &inner_threads[thread_idx]);
  }

  myfree (inner_threads);

  // we dont need restore file anymore
  if (restore_ctx->enabled == true)
  {
    if ((opencl_ctx->devices_status == STATUS_EXHAUSTED) || (opencl_ctx->devices_status == STATUS_CRACKED))
    {
      if (opencl_ctx->run_thread_level1 == true) // this is to check for [c]heckpoint
      {
        unlink (restore_ctx->eff_restore_file);
        unlink (restore_ctx->new_restore_file);
      }
      else
      {
        cycle_restore (restore_ctx, opencl_ctx);
      }
    }
    else
    {
      cycle_restore (restore_ctx, opencl_ctx);
    }
  }

  // finally save left hashes
  if ((hashes->hashlist_mode == HL_MODE_FILE) && (user_options->remove == true) && (hashes->digests_saved != hashes->digests_done))
  {
    save_hash (user_options, hashconfig, hashes);
  }

  /**
   * Clean up
   */

  myfree (words_progress_done);
  myfree (words_progress_rejected);
  myfree (words_progress_restored);

  opencl_session_destroy (opencl_ctx);

  potfile_write_close (potfile_ctx);

  bitmap_ctx_destroy (bitmap_ctx);

  mask_ctx_destroy (mask_ctx);

  combinator_ctx_destroy (combinator_ctx);

  straight_ctx_destroy (straight_ctx);

  hashes_destroy (hashes);

  hashconfig_destroy (hashconfig);

  wl_data_destroy (wl_data);

  return 0;
}

int main (int argc, char **argv)
{
  /**
   * To help users a bit
   */

  const int rc_console = setup_console ();

  if (rc_console == -1) return -1;

  setup_environment_variables ();

  setup_umask ();

  /**
   * Real init
   */

  memset (&data, 0, sizeof (hc_global_data_t));

  time_t proc_start;

  time (&proc_start);

  data.proc_start = proc_start;

  hc_thread_mutex_init (mux_display);
  hc_thread_mutex_init (mux_hwmon);

  /**
   * folder
   */

  char *install_folder = NULL;
  char *shared_folder  = NULL;

  #if defined (INSTALL_FOLDER)
  install_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  shared_folder = SHARED_FOLDER;
  #endif

  folder_config_t *folder_config = (folder_config_t *) mymalloc (sizeof (folder_config_t));

  folder_config_init (folder_config, install_folder, shared_folder);

  /**
   * commandline parameters
   */

  user_options_t *user_options = (user_options_t *) mymalloc (sizeof (user_options_t));

  data.user_options = user_options;

  user_options_init (user_options);

  const int rc_user_options_parse = user_options_parse (user_options, argc, argv);

  if (rc_user_options_parse == -1) return -1;

  /**
   * some early exits
   */

  if (user_options->version == true)
  {
    log_info ("%s", VERSION_TAG);

    return 0;
  }

  if (user_options->usage == true)
  {
    usage_big_print (PROGNAME);

    return 0;
  }

  /**
   * restore
   */

  restore_ctx_t *restore_ctx = (restore_ctx_t *) mymalloc (sizeof (restore_ctx_t));

  data.restore_ctx = restore_ctx;

  const int rc_restore_init = restore_ctx_init (restore_ctx, user_options, folder_config, argc, argv);

  if (rc_restore_init == -1) return -1;

  /**
   * process user input
   */

  user_options_extra_t *user_options_extra = (user_options_extra_t *) mymalloc (sizeof (user_options_extra_t));

  data.user_options_extra = user_options_extra;

  const int rc_user_options_extra_init = user_options_extra_init (user_options, restore_ctx, user_options_extra);

  if (rc_user_options_extra_init == -1) return -1;

  const int rc_user_options_sanity = user_options_sanity (user_options, restore_ctx, user_options_extra);

  if (rc_user_options_sanity == -1) return -1;

  /**
   * prepare seeding for random number generator, required by logfile and rules generator
   */

  setup_seeding (user_options, &proc_start);

  /**
   * Inform user things getting started,
   * - this is giving us a visual header before preparations start, so we do not need to clear them afterwards
   */

  welcome_screen (user_options, &proc_start);

  /**
   * logfile init
   */

  logfile_ctx_t *logfile_ctx = (logfile_ctx_t *) mymalloc (sizeof (logfile_ctx_t));

  data.logfile_ctx = logfile_ctx;

  logfile_init (logfile_ctx, user_options, folder_config);

  logfile_generate_topid (logfile_ctx);

  logfile_top_msg ("START");

  user_options_logger (user_options, logfile_ctx);

  /**
   * tuning db
   */

  char tuning_db_file[256] = { 0 };

  snprintf (tuning_db_file, sizeof (tuning_db_file) - 1, "%s/%s", folder_config->shared_dir, TUNING_DB_FILE);

  tuning_db_t *tuning_db = tuning_db_init (tuning_db_file);

  /**
   * induction directory
   */

  induct_ctx_t *induct_ctx = (induct_ctx_t *) mymalloc (sizeof (induct_ctx_t));

  data.induct_ctx = induct_ctx;

  const int rc_induct_ctx_init = induct_ctx_init (induct_ctx, user_options, folder_config, proc_start);

  if (rc_induct_ctx_init == -1) return -1;

  /**
   * outfile-check directory
   */

  outcheck_ctx_t *outcheck_ctx = (outcheck_ctx_t *) mymalloc (sizeof (outcheck_ctx_t));

  data.outcheck_ctx = outcheck_ctx;

  const int rc_outcheck_ctx_init = outcheck_ctx_init (outcheck_ctx, user_options, folder_config);

  if (rc_outcheck_ctx_init == -1) return -1;

  /**
   * outfile itself
   */

  outfile_ctx_t *outfile_ctx = mymalloc (sizeof (outfile_ctx_t));

  data.outfile_ctx = outfile_ctx;

  outfile_init (outfile_ctx, user_options);

  /**
   * Sanity check for hashfile vs outfile (should not point to the same physical file)
   */

  const int rc_outfile_and_hashfile = outfile_and_hashfile (outfile_ctx, restore_ctx->argv[user_options_extra->optind]);

  if (rc_outfile_and_hashfile == -1) return -1;

  /**
   * potfile init
   * this is only setting path because potfile can be used in read and write mode depending on user options
   * plus it depends on hash_mode, so we continue using it in outer_loop
   */

  potfile_ctx_t *potfile_ctx = mymalloc (sizeof (potfile_ctx_t));

  data.potfile_ctx = potfile_ctx;

  potfile_init (potfile_ctx, folder_config->profile_dir, user_options->potfile_path, user_options->potfile_disable);

  /**
   * dictstat init
   */

  dictstat_ctx_t *dictstat_ctx = mymalloc (sizeof (dictstat_ctx_t));

  dictstat_init (dictstat_ctx, user_options, folder_config);

  /**
   * loopback init
   */

  loopback_ctx_t *loopback_ctx = mymalloc (sizeof (loopback_ctx_t));

  data.loopback_ctx = loopback_ctx;

  loopback_init (loopback_ctx);

  /**
   * debugfile init
   */

  debugfile_ctx_t *debugfile_ctx = mymalloc (sizeof (debugfile_ctx_t));

  data.debugfile_ctx = debugfile_ctx;

  debugfile_init (debugfile_ctx, user_options->debug_mode, user_options->debug_file);

  /**
   * cpu affinity
   */

  if (user_options->cpu_affinity)
  {
    set_cpu_affinity (user_options->cpu_affinity);
  }

  /**
   * Init OpenCL library loader
   */

  opencl_ctx_t *opencl_ctx = (opencl_ctx_t *) mymalloc (sizeof (opencl_ctx_t));

  data.opencl_ctx = opencl_ctx;

  const int rc_opencl_init = opencl_ctx_init (opencl_ctx, user_options);

  if (rc_opencl_init == -1)
  {
    log_error ("ERROR: opencl_ctx_init() failed");

    return -1;
  }

  /**
   * Init OpenCL devices
   */

  const int rc_devices_init = opencl_ctx_devices_init (opencl_ctx, user_options);

  if (rc_devices_init == -1)
  {
    log_error ("ERROR: opencl_ctx_devices_init() failed");

    return -1;
  }

  /**
   * HM devices: init
   */

  hwmon_ctx_t *hwmon_ctx = (hwmon_ctx_t *) mymalloc (sizeof (hwmon_ctx_t));

  data.hwmon_ctx = hwmon_ctx;

  const int rc_hwmon_init = hwmon_ctx_init (hwmon_ctx, user_options, opencl_ctx);

  if (rc_hwmon_init == -1)
  {
    log_error ("ERROR: hwmon_ctx_init() failed");

    return -1;
  }

  /**
   * keypress thread
   */

  uint outer_threads_cnt = 0;

  hc_thread_t *outer_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  data.shutdown_outer = false;

  if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      hc_thread_create (outer_threads[outer_threads_cnt], thread_keypress, NULL);

      outer_threads_cnt++;
    }
  }

  /**
   * outer loop
   */

  if (user_options->benchmark == true)
  {
    user_options->quiet = true;

    if (user_options->hash_mode_chgd == true)
    {
      const int rc = outer_loop (user_options, user_options_extra, restore_ctx, folder_config, logfile_ctx, tuning_db, induct_ctx, outcheck_ctx, outfile_ctx, potfile_ctx, dictstat_ctx, loopback_ctx, opencl_ctx, hwmon_ctx);

      if (rc == -1) return -1;
    }
    else
    {
      for (int algorithm_pos = 0; algorithm_pos < DEFAULT_BENCHMARK_ALGORITHMS_CNT; algorithm_pos++)
      {
        user_options->hash_mode = DEFAULT_BENCHMARK_ALGORITHMS_BUF[algorithm_pos];

        const int rc = outer_loop (user_options, user_options_extra, restore_ctx, folder_config, logfile_ctx, tuning_db, induct_ctx, outcheck_ctx, outfile_ctx, potfile_ctx, dictstat_ctx, loopback_ctx, opencl_ctx, hwmon_ctx);

        if (rc == -1) return -1;

        if (opencl_ctx->run_main_level1 == false) break;
      }
    }
  }
  else
  {
    const int rc = outer_loop (user_options, user_options_extra, restore_ctx, folder_config, logfile_ctx, tuning_db, induct_ctx, outcheck_ctx, outfile_ctx, potfile_ctx, dictstat_ctx, loopback_ctx, opencl_ctx, hwmon_ctx);

    if (rc == -1) return -1;
  }

  // wait for outer threads

  data.shutdown_outer = true;

  for (uint thread_idx = 0; thread_idx < outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &outer_threads[thread_idx]);
  }

  myfree (outer_threads);

  if (user_options->benchmark == true)
  {
    user_options->quiet = false;
  }

  // destroy others mutex

  hc_thread_mutex_delete (mux_display);
  hc_thread_mutex_delete (mux_hwmon);

  // free memory

  debugfile_destroy (debugfile_ctx);

  tuning_db_destroy (tuning_db);

  loopback_destroy (loopback_ctx);

  dictstat_destroy (dictstat_ctx);

  potfile_destroy (potfile_ctx);

  induct_ctx_destroy (induct_ctx);

  outfile_destroy (outfile_ctx);

  outcheck_ctx_destroy (outcheck_ctx);

  folder_config_destroy (folder_config);

  user_options_extra_destroy (user_options_extra);

  hwmon_ctx_destroy (hwmon_ctx, user_options, opencl_ctx);

  opencl_ctx_devices_destroy (opencl_ctx);

  restore_ctx_destroy (restore_ctx);

  time_t proc_stop;

  time (&proc_stop);

  logfile_top_uint (proc_start);
  logfile_top_uint (proc_stop);

  logfile_top_msg ("STOP");

  logfile_destroy (logfile_ctx);

  goodbye_screen (user_options, &proc_start, &proc_stop);

  user_options_destroy (user_options);

  u32 rc_final = -1;

  if (opencl_ctx->devices_status == STATUS_ABORTED)   rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_QUIT)      rc_final = 2;
  if (opencl_ctx->devices_status == STATUS_EXHAUSTED) rc_final = 1;
  if (opencl_ctx->devices_status == STATUS_CRACKED)   rc_final = 0;

  opencl_ctx_destroy (opencl_ctx);

  return rc_final;
}
