/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "interface.h"
#include "timer.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "rp_cpu.h"
#include "terminal.h"
#include "mpsp.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "status.h"
#include "dictstat.h"
#include "wordlist.h"
#include "data.h"
#include "status.h"
#include "shared.h"
#include "dispatch.h"

extern hc_global_data_t data;

static void set_kernel_power_final (const user_options_t *user_options, const u64 kernel_power_final)
{
  if (user_options->quiet == false)
  {
    clear_prompt ();

    //log_info ("");

    log_info ("INFO: approaching final keyspace, workload adjusted");
    log_info ("");

    send_prompt ();
  }

  data.kernel_power_final = kernel_power_final;
}

static u32 get_power (hc_device_param_t *device_param)
{
  const u64 kernel_power_final = data.kernel_power_final;

  if (kernel_power_final)
  {
    const double device_factor = (double) device_param->hardware_power / data.hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, device_param->hardware_power);

    return work;
  }

  return device_param->kernel_power;
}

static uint get_work (opencl_ctx_t *opencl_ctx, const user_options_t *user_options, hc_device_param_t *device_param, const u64 max)
{
  hc_thread_mutex_lock (opencl_ctx->mux_dispatcher);

  const u64 words_cur  = data.words_cur;
  const u64 words_base = (user_options->limit == 0) ? data.words_base : MIN (user_options->limit, data.words_base);

  device_param->words_off = words_cur;

  const u64 kernel_power_all = data.kernel_power_all;

  const u64 words_left = words_base - words_cur;

  if (words_left < kernel_power_all)
  {
    if (data.kernel_power_final == 0)
    {
      set_kernel_power_final (user_options, words_left);
    }
  }

  const u32 kernel_power = get_power (device_param);

  uint work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  data.words_cur += work;

  hc_thread_mutex_unlock (opencl_ctx->mux_dispatcher);

  return work;
}

void *thread_calc_stdin (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  user_options_t       *user_options       = data.user_options;
  user_options_extra_t *user_options_extra = data.user_options_extra;
  hashconfig_t         *hashconfig         = data.hashconfig;
  hashes_t             *hashes             = data.hashes;
  rules_ctx_t          *rules_ctx          = data.rules_ctx;
  opencl_ctx_t         *opencl_ctx         = data.opencl_ctx;
  mask_ctx_t           *mask_ctx           = data.mask_ctx;

  char *buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  const uint attack_kern = user_options_extra->attack_kern;

  while (opencl_ctx->run_thread_level1 == true)
  {
    hc_thread_mutex_lock (opencl_ctx->mux_dispatcher);

    if (feof (stdin) != 0)
    {
      hc_thread_mutex_unlock (opencl_ctx->mux_dispatcher);

      break;
    }

    uint words_cur = 0;

    while (words_cur < device_param->kernel_power)
    {
      char *line_buf = fgets (buf, HCBUFSIZ_LARGE - 1, stdin);

      if (line_buf == NULL) break;

      uint line_len = in_superchop (line_buf);

      line_len = convert_from_hex (line_buf, line_len, user_options);

      // post-process rule engine

      if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
      {
        char rule_buf_out[BLOCK_SIZE] = { 0 };

        int rule_len_out = -1;

        if (line_len < BLOCK_SIZE)
        {
          rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, line_buf, line_len, rule_buf_out);
        }

        if (rule_len_out < 0) continue;

        line_buf = rule_buf_out;
        line_len = rule_len_out;
      }

      if (line_len > PW_MAX)
      {
        continue;
      }

      // hmm that's always the case, or?

      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if ((line_len < data.pw_min) || (line_len > data.pw_max))
        {
          hc_thread_mutex_lock (opencl_ctx->mux_counter);

          for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
          {
            data.words_progress_rejected[salt_pos] += rules_ctx->kernel_rules_cnt;
          }

          hc_thread_mutex_unlock (opencl_ctx->mux_counter);

          continue;
        }
      }

      pw_add (device_param, (u8 *) line_buf, line_len);

      words_cur++;

      while (opencl_ctx->run_thread_level1 == false) break;
    }

    hc_thread_mutex_unlock (opencl_ctx->mux_dispatcher);

    while (opencl_ctx->run_thread_level1 == false) break;

    // flush

    const uint pws_cnt = device_param->pws_cnt;

    if (pws_cnt)
    {
      run_copy (opencl_ctx, device_param, hashconfig, user_options, user_options_extra, pws_cnt);

      run_cracker (opencl_ctx, device_param, hashconfig, hashes, user_options, user_options_extra, rules_ctx, mask_ctx, pws_cnt);

      device_param->pws_cnt = 0;

      /*
      still required?
      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        run_kernel_bzero (opencl_ctx, device_param, device_param->d_rules_c, device_param->size_rules_c);
      }
      else if (attack_kern == ATTACK_KERN_COMBI)
      {
        run_kernel_bzero (opencl_ctx, device_param, device_param->d_combs_c, device_param->size_combs);
      }
      */
    }
  }

  device_param->kernel_accel = 0;
  device_param->kernel_loops = 0;

  myfree (buf);

  return NULL;
}

void *thread_calc (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  user_options_t       *user_options       = data.user_options;
  user_options_extra_t *user_options_extra = data.user_options_extra;
  hashconfig_t         *hashconfig         = data.hashconfig;
  hashes_t             *hashes             = data.hashes;
  opencl_ctx_t         *opencl_ctx         = data.opencl_ctx;
  rules_ctx_t          *rules_ctx          = data.rules_ctx;
  mask_ctx_t           *mask_ctx           = data.mask_ctx;

  const uint attack_mode = user_options->attack_mode;
  const uint attack_kern = user_options_extra->attack_kern;

  if (attack_mode == ATTACK_MODE_BF)
  {
    while (opencl_ctx->run_thread_level1 == true)
    {
      const uint work = get_work (opencl_ctx, user_options, device_param, -1u);

      if (work == 0) break;

      const u64 words_off = device_param->words_off;
      const u64 words_fin = words_off + work;

      const uint pws_cnt = work;

      device_param->pws_cnt = pws_cnt;

      if (pws_cnt)
      {
        run_copy (opencl_ctx, device_param, hashconfig, user_options, user_options_extra, pws_cnt);

        run_cracker (opencl_ctx, device_param, hashconfig, hashes, user_options, user_options_extra, rules_ctx, mask_ctx, pws_cnt);

        device_param->pws_cnt = 0;

        /*
        still required?
        run_kernel_bzero (device_param, device_param->d_bfs_c, device_param->size_bfs);
        */
      }

      if (opencl_ctx->run_thread_level1 == false) break;

      if (user_options->benchmark == true) break;

      device_param->words_done = words_fin;
    }
  }
  else
  {
    char *dictfile = data.dictfile;

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        dictfile = data.dictfile2;
      }
    }

    FILE *fd = fopen (dictfile, "rb");

    if (fd == NULL)
    {
      log_error ("ERROR: %s: %s", dictfile, strerror (errno));

      return NULL;
    }

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      const uint combs_mode = data.combs_mode;

      if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
      {
        const char *dictfilec = data.dictfile2;

        FILE *combs_fp = fopen (dictfilec, "rb");

        if (combs_fp == NULL)
        {
          log_error ("ERROR: %s: %s", dictfilec, strerror (errno));

          fclose (fd);

          return NULL;
        }

        device_param->combs_fp = combs_fp;
      }
      else if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        const char *dictfilec = data.dictfile;

        FILE *combs_fp = fopen (dictfilec, "rb");

        if (combs_fp == NULL)
        {
          log_error ("ERROR: %s: %s", dictfilec, strerror (errno));

          fclose (fd);

          return NULL;
        }

        device_param->combs_fp = combs_fp;
      }
    }

    wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

    wl_data_init (wl_data, user_options, hashconfig);

    u64 words_cur = 0;

    while (opencl_ctx->run_thread_level1 == true)
    {
      u64 words_off = 0;
      u64 words_fin = 0;

      u64 max = -1llu;

      while (max)
      {
        const uint work = get_work (opencl_ctx, user_options, device_param, max);

        if (work == 0) break;

        max = 0;

        words_off = device_param->words_off;
        words_fin = words_off + work;

        char *line_buf;
        uint  line_len;

        for ( ; words_cur < words_off; words_cur++) get_next_word (wl_data, user_options, user_options_extra, fd, &line_buf, &line_len);

        for ( ; words_cur < words_fin; words_cur++)
        {
          get_next_word (wl_data, user_options, user_options_extra, fd, &line_buf, &line_len);

          line_len = convert_from_hex (line_buf, line_len, user_options);

          // post-process rule engine

          if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
          {
            char rule_buf_out[BLOCK_SIZE] = { 0 };

            int rule_len_out = -1;

            if (line_len < BLOCK_SIZE)
            {
              rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, line_buf, line_len, rule_buf_out);
            }

            if (rule_len_out < 0) continue;

            line_buf = rule_buf_out;
            line_len = rule_len_out;
          }

          if (attack_kern == ATTACK_KERN_STRAIGHT)
          {
            if ((line_len < data.pw_min) || (line_len > data.pw_max))
            {
              max++;

              hc_thread_mutex_lock (opencl_ctx->mux_counter);

              for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += rules_ctx->kernel_rules_cnt;
              }

              hc_thread_mutex_unlock (opencl_ctx->mux_counter);

              continue;
            }
          }
          else if (attack_kern == ATTACK_KERN_COMBI)
          {
            // do not check if minimum restriction is satisfied (line_len >= data.pw_min) here
            // since we still need to combine the plains

            if (line_len > data.pw_max)
            {
              max++;

              hc_thread_mutex_lock (opencl_ctx->mux_counter);

              for (uint salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += data.combs_cnt;
              }

              hc_thread_mutex_unlock (opencl_ctx->mux_counter);

              continue;
            }
          }

          pw_add (device_param, (u8 *) line_buf, line_len);

          if (opencl_ctx->run_thread_level1 == false) break;
        }

        if (opencl_ctx->run_thread_level1 == false) break;
      }

      if (opencl_ctx->run_thread_level1 == false) break;

      //
      // flush
      //

      const uint pws_cnt = device_param->pws_cnt;

      if (pws_cnt)
      {
        run_copy (opencl_ctx, device_param, hashconfig, user_options, user_options_extra, pws_cnt);

        run_cracker (opencl_ctx, device_param, hashconfig, hashes, user_options, user_options_extra, rules_ctx, mask_ctx, pws_cnt);

        device_param->pws_cnt = 0;

        /*
        still required?
        if (attack_kern == ATTACK_KERN_STRAIGHT)
        {
          run_kernel_bzero (device_param, device_param->d_rules_c, device_param->size_rules_c);
        }
        else if (attack_kern == ATTACK_KERN_COMBI)
        {
          run_kernel_bzero (device_param, device_param->d_combs_c, device_param->size_combs);
        }
        */
      }

      if (opencl_ctx->run_thread_level1 == false) break;

      if (words_fin == 0) break;

      device_param->words_done = words_fin;
    }

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      fclose (device_param->combs_fp);
    }

    wl_data_destroy (wl_data);

    fclose (fd);
  }

  device_param->kernel_accel = 0;
  device_param->kernel_loops = 0;

  return NULL;
}
