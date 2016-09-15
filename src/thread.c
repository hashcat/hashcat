/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
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
#include "opencl.h"
#include "thread.h"
#include "rp_cpu.h"
#include "terminal.h"
#include "hwmon.h"
#include "mpsp.h"
#include "restore.h"
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

extern hc_global_data_t data;

extern hc_thread_mutex_t mux_counter;

hc_thread_mutex_t mux_dispatcher;

#if defined (_WIN)

BOOL WINAPI sigHandler_default (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      /*
       * special case see: https://stackoverflow.com/questions/3640633/c-setconsolectrlhandler-routine-issue/5610042#5610042
       * if the user interacts w/ the user-interface (GUI/cmd), we need to do the finalization job within this signal handler
       * function otherwise it is too late (e.g. after returning from this function)
       */

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

BOOL WINAPI sigHandler_benchmark (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit ();

      SetConsoleCtrlHandler (NULL, TRUE);

      return TRUE;
  }

  return FALSE;
}

void hc_signal (BOOL WINAPI (callback) (DWORD))
{
  if (callback == NULL)
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, FALSE);
  }
  else
  {
    SetConsoleCtrlHandler ((PHANDLER_ROUTINE) callback, TRUE);
  }
}

#else

void sigHandler_default (int sig)
{
  myabort ();

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit ();

  signal (sig, NULL);
}

void hc_signal (void (callback) (int))
{
  if (callback == NULL) callback = SIG_DFL;

  signal (SIGINT,  callback);
  signal (SIGTERM, callback);
  signal (SIGABRT, callback);
}

#endif

void myabort ()
{
  data.devices_status = STATUS_ABORTED;
}

void myquit ()
{
  data.devices_status = STATUS_QUIT;
}

void SuspendThreads ()
{
  if (data.devices_status != STATUS_RUNNING) return;

  hc_timer_set (&data.timer_paused);

  data.devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

void ResumeThreads ()
{
  if (data.devices_status != STATUS_PAUSED) return;

  double ms_paused;

  hc_timer_get (data.timer_paused, ms_paused);

  data.ms_paused += ms_paused;

  data.devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}

void bypass ()
{
  data.devices_status = STATUS_BYPASS;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

static void set_kernel_power_final (const u64 kernel_power_final)
{
  if (data.quiet == 0)
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

uint get_work (hc_device_param_t *device_param, const u64 max)
{
  hc_thread_mutex_lock (mux_dispatcher);

  const u64 words_cur  = data.words_cur;
  const u64 words_base = (data.limit == 0) ? data.words_base : MIN (data.limit, data.words_base);

  device_param->words_off = words_cur;

  const u64 kernel_power_all = data.kernel_power_all;

  const u64 words_left = words_base - words_cur;

  if (words_left < kernel_power_all)
  {
    if (data.kernel_power_final == 0)
    {
      set_kernel_power_final (words_left);
    }
  }

  const u32 kernel_power = get_power (device_param);

  uint work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  data.words_cur += work;

  hc_thread_mutex_unlock (mux_dispatcher);

  return work;
}

void *thread_calc_stdin (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  hashconfig_t *hashconfig = data.hashconfig;

  char *buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  const uint attack_kern = data.attack_kern;

  while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
  {
    hc_thread_mutex_lock (mux_dispatcher);

    if (feof (stdin) != 0)
    {
      hc_thread_mutex_unlock (mux_dispatcher);

      break;
    }

    uint words_cur = 0;

    while (words_cur < device_param->kernel_power)
    {
      char *line_buf = fgets (buf, HCBUFSIZ_LARGE - 1, stdin);

      if (line_buf == NULL) break;

      uint line_len = in_superchop (line_buf);

      line_len = convert_from_hex (line_buf, line_len);

      // post-process rule engine

      if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
      {
        char rule_buf_out[BLOCK_SIZE] = { 0 };

        int rule_len_out = -1;

        if (line_len < BLOCK_SIZE)
        {
          rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, line_buf, line_len, rule_buf_out);
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
          hc_thread_mutex_lock (mux_counter);

          for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
          {
            data.words_progress_rejected[salt_pos] += data.kernel_rules_cnt;
          }

          hc_thread_mutex_unlock (mux_counter);

          continue;
        }
      }

      pw_add (device_param, (u8 *) line_buf, line_len);

      words_cur++;

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;
    }

    hc_thread_mutex_unlock (mux_dispatcher);

    if (data.devices_status == STATUS_CRACKED) break;
    if (data.devices_status == STATUS_ABORTED) break;
    if (data.devices_status == STATUS_QUIT)    break;
    if (data.devices_status == STATUS_BYPASS)  break;

    // flush

    const uint pws_cnt = device_param->pws_cnt;

    if (pws_cnt)
    {
      run_copy (device_param, hashconfig, pws_cnt);

      run_cracker (device_param, hashconfig, pws_cnt);

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

  hashconfig_t *hashconfig = data.hashconfig;

  const uint attack_mode = data.attack_mode;
  const uint attack_kern = data.attack_kern;

  if (attack_mode == ATTACK_MODE_BF)
  {
    while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
    {
      const uint work = get_work (device_param, -1u);

      if (work == 0) break;

      const u64 words_off = device_param->words_off;
      const u64 words_fin = words_off + work;

      const uint pws_cnt = work;

      device_param->pws_cnt = pws_cnt;

      if (pws_cnt)
      {
        run_copy (device_param, hashconfig, pws_cnt);

        run_cracker (device_param, hashconfig, pws_cnt);

        device_param->pws_cnt = 0;

        /*
        still required?
        run_kernel_bzero (device_param, device_param->d_bfs_c, device_param->size_bfs);
        */
      }

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      if (data.benchmark == 1) break;

      device_param->words_done = words_fin;
    }
  }
  else
  {
    const uint segment_size = data.segment_size;

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

    wl_data->buf   = (char *) mymalloc (segment_size);
    wl_data->avail = segment_size;
    wl_data->incr  = segment_size;
    wl_data->cnt   = 0;
    wl_data->pos   = 0;

    u64 words_cur = 0;

    while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
    {
      u64 words_off = 0;
      u64 words_fin = 0;

      u64 max = -1llu;

      while (max)
      {
        const uint work = get_work (device_param, max);

        if (work == 0) break;

        max = 0;

        words_off = device_param->words_off;
        words_fin = words_off + work;

        char *line_buf;
        uint  line_len;

        for ( ; words_cur < words_off; words_cur++) get_next_word (wl_data, fd, &line_buf, &line_len);

        for ( ; words_cur < words_fin; words_cur++)
        {
          get_next_word (wl_data, fd, &line_buf, &line_len);

          line_len = convert_from_hex (line_buf, line_len);

          // post-process rule engine

          if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
          {
            char rule_buf_out[BLOCK_SIZE] = { 0 };

            int rule_len_out = -1;

            if (line_len < BLOCK_SIZE)
            {
              rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, line_buf, line_len, rule_buf_out);
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

              hc_thread_mutex_lock (mux_counter);

              for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += data.kernel_rules_cnt;
              }

              hc_thread_mutex_unlock (mux_counter);

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

              hc_thread_mutex_lock (mux_counter);

              for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += data.combs_cnt;
              }

              hc_thread_mutex_unlock (mux_counter);

              continue;
            }
          }

          pw_add (device_param, (u8 *) line_buf, line_len);

          if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

          if (data.devices_status == STATUS_CRACKED) break;
          if (data.devices_status == STATUS_ABORTED) break;
          if (data.devices_status == STATUS_QUIT)    break;
          if (data.devices_status == STATUS_BYPASS)  break;
        }

        if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

        if (data.devices_status == STATUS_CRACKED) break;
        if (data.devices_status == STATUS_ABORTED) break;
        if (data.devices_status == STATUS_QUIT)    break;
        if (data.devices_status == STATUS_BYPASS)  break;
      }

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      //
      // flush
      //

      const uint pws_cnt = device_param->pws_cnt;

      if (pws_cnt)
      {
        run_copy (device_param, hashconfig, pws_cnt);

        run_cracker (device_param, hashconfig, pws_cnt);

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

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      if (words_fin == 0) break;

      device_param->words_done = words_fin;
    }

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      fclose (device_param->combs_fp);
    }

    free (wl_data->buf);
    free (wl_data);

    fclose (fd);
  }

  device_param->kernel_accel = 0;
  device_param->kernel_loops = 0;

  return NULL;
}
