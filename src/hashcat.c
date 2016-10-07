/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif // __APPLE__

#include "common.h"

// basic tools

#include "types.h"
#include "folder.h"
#include "locking.h"
#include "logging.h"
#include "memory.h"
#include "shared.h"
#include "thread.h"
#include "timer.h"

// features

#include "affinity.h"
#include "autotune.h"
#include "bitmap.h"
#include "combinator.h"
#include "cpt.h"
#include "debugfile.h"
#include "dictstat.h"
#include "dispatch.h"
#include "hashes.h"
#include "hwmon.h"
#include "induct.h"
#include "interface.h"
#include "logfile.h"
#include "loopback.h"
#include "monitor.h"
#include "mpsp.h"
#include "opencl.h"
#include "outfile_check.h"
#include "outfile.h"
#include "potfile.h"
#include "restore.h"
#include "rp.h"
#include "status.h"
#include "straight.h"
#include "tuningdb.h"
#include "usage.h"
#include "user_options.h"
#include "weak_hash.h"
#include "wordlist.h"

extern const u32 DEFAULT_BENCHMARK_ALGORITHMS_CNT;
extern const u32 DEFAULT_BENCHMARK_ALGORITHMS_BUF[];

void hashcat_ctx_init (hashcat_ctx_t *hashcat_ctx, int (*event) (hashcat_ctx_t *, const u32))
{
  if (event == NULL)
  {
    fprintf (stderr, "Event callback function is mandatory\n");

    exit (-1);
  }

  hashcat_ctx->event = event;

  hashcat_ctx->bitmap_ctx         = (bitmap_ctx_t *)          mymalloc (sizeof (bitmap_ctx_t));
  hashcat_ctx->combinator_ctx     = (combinator_ctx_t *)      mymalloc (sizeof (combinator_ctx_t));
  hashcat_ctx->cpt_ctx            = (cpt_ctx_t *)             mymalloc (sizeof (cpt_ctx_t));
  hashcat_ctx->debugfile_ctx      = (debugfile_ctx_t *)       mymalloc (sizeof (debugfile_ctx_t));
  hashcat_ctx->dictstat_ctx       = (dictstat_ctx_t *)        mymalloc (sizeof (dictstat_ctx_t));
  hashcat_ctx->folder_config      = (folder_config_t *)       mymalloc (sizeof (folder_config_t));
  hashcat_ctx->hashcat_user       = (hashcat_user_t *)        mymalloc (sizeof (hashcat_user_t));
  hashcat_ctx->hashconfig         = (hashconfig_t *)          mymalloc (sizeof (hashconfig_t));
  hashcat_ctx->hashes             = (hashes_t *)              mymalloc (sizeof (hashes_t));
  hashcat_ctx->hwmon_ctx          = (hwmon_ctx_t *)           mymalloc (sizeof (hwmon_ctx_t));
  hashcat_ctx->induct_ctx         = (induct_ctx_t *)          mymalloc (sizeof (induct_ctx_t));
  hashcat_ctx->logfile_ctx        = (logfile_ctx_t *)         mymalloc (sizeof (logfile_ctx_t));
  hashcat_ctx->loopback_ctx       = (loopback_ctx_t *)        mymalloc (sizeof (loopback_ctx_t));
  hashcat_ctx->mask_ctx           = (mask_ctx_t *)            mymalloc (sizeof (mask_ctx_t));
  hashcat_ctx->opencl_ctx         = (opencl_ctx_t *)          mymalloc (sizeof (opencl_ctx_t));
  hashcat_ctx->outcheck_ctx       = (outcheck_ctx_t *)        mymalloc (sizeof (outcheck_ctx_t));
  hashcat_ctx->outfile_ctx        = (outfile_ctx_t *)         mymalloc (sizeof (outfile_ctx_t));
  hashcat_ctx->potfile_ctx        = (potfile_ctx_t *)         mymalloc (sizeof (potfile_ctx_t));
  hashcat_ctx->restore_ctx        = (restore_ctx_t *)         mymalloc (sizeof (restore_ctx_t));
  hashcat_ctx->status_ctx         = (status_ctx_t *)          mymalloc (sizeof (status_ctx_t));
  hashcat_ctx->straight_ctx       = (straight_ctx_t *)        mymalloc (sizeof (straight_ctx_t));
  hashcat_ctx->tuning_db          = (tuning_db_t *)           mymalloc (sizeof (tuning_db_t));
  hashcat_ctx->user_options_extra = (user_options_extra_t *)  mymalloc (sizeof (user_options_extra_t));
  hashcat_ctx->user_options       = (user_options_t *)        mymalloc (sizeof (user_options_t));
  hashcat_ctx->wl_data            = (wl_data_t *)             mymalloc (sizeof (wl_data_t));
}

void hashcat_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  myfree (hashcat_ctx->bitmap_ctx);
  myfree (hashcat_ctx->combinator_ctx);
  myfree (hashcat_ctx->cpt_ctx);
  myfree (hashcat_ctx->debugfile_ctx);
  myfree (hashcat_ctx->dictstat_ctx);
  myfree (hashcat_ctx->folder_config);
  myfree (hashcat_ctx->hashconfig);
  myfree (hashcat_ctx->hashes);
  myfree (hashcat_ctx->hwmon_ctx);
  myfree (hashcat_ctx->induct_ctx);
  myfree (hashcat_ctx->logfile_ctx);
  myfree (hashcat_ctx->loopback_ctx);
  myfree (hashcat_ctx->mask_ctx);
  myfree (hashcat_ctx->opencl_ctx);
  myfree (hashcat_ctx->outcheck_ctx);
  myfree (hashcat_ctx->outfile_ctx);
  myfree (hashcat_ctx->potfile_ctx);
  myfree (hashcat_ctx->restore_ctx);
  myfree (hashcat_ctx->status_ctx);
  myfree (hashcat_ctx->straight_ctx);
  myfree (hashcat_ctx->tuning_db);
  myfree (hashcat_ctx->user_options_extra);
  myfree (hashcat_ctx->user_options);
  myfree (hashcat_ctx->wl_data);

  memset (hashcat_ctx, 0, sizeof (hashcat_ctx_t));
}

// inner2_loop iterates through wordlists, then calls kernel execution

static int inner2_loop (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t             *hashes              = hashcat_ctx->hashes;
  induct_ctx_t         *induct_ctx          = hashcat_ctx->induct_ctx;
  logfile_ctx_t        *logfile_ctx         = hashcat_ctx->logfile_ctx;
  opencl_ctx_t         *opencl_ctx          = hashcat_ctx->opencl_ctx;
  restore_ctx_t        *restore_ctx         = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  //status_ctx->run_main_level1   = true;
  //status_ctx->run_main_level2   = true;
  //status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  status_ctx->devices_status = STATUS_INIT;

  EVENT_SEND (EVENT_LOGFILE_SUB_INITIALIZE);

  status_progress_reset (hashcat_ctx);

  status_ctx->words_cur = 0;

  restore_data_t *rd = restore_ctx->rd;

  if (rd->words_cur)
  {
    status_ctx->words_cur = rd->words_cur;

    user_options->skip = 0;
  }

  if (user_options->skip)
  {
    status_ctx->words_cur = user_options->skip;

    user_options->skip = 0;
  }

  status_ctx->ms_paused = 0;

  opencl_session_reset (hashcat_ctx);

  cpt_ctx_reset (hashcat_ctx);

  /**
   * Update attack-mode specific stuff based on mask
   */

  mask_ctx_update_loop (hashcat_ctx);

  /**
   * Update attack-mode specific stuff based on wordlist
   */

  straight_ctx_update_loop (hashcat_ctx);

  // words base

  status_ctx->words_base = status_ctx->words_cnt / user_options_extra_amplifier (hashcat_ctx);

  EVENT_SEND (EVENT_CALCULATED_WORDS_BASE);

  if (user_options->keyspace == true) return 0;

  // restore stuff

  if (status_ctx->words_cur > status_ctx->words_base)
  {
    log_error ("ERROR: Restore value greater keyspace");

    return -1;
  }

  if (status_ctx->words_cur)
  {
    const u64 progress_restored = status_ctx->words_cur * user_options_extra_amplifier (hashcat_ctx);

    for (u32 i = 0; i < hashes->salts_cnt; i++)
    {
      status_ctx->words_progress_restored[i] = progress_restored;
    }
  }

  /**
   * limit kernel loops by the amplification count we have from:
   * - straight_ctx, combinator_ctx or mask_ctx for fast hashes
   * - hash iteration count for slow hashes
   */

  opencl_ctx_devices_kernel_loops (hashcat_ctx);

  /**
   * create autotune threads
   */

  EVENT_SEND (EVENT_AUTOTUNE_STARTING);

  thread_param_t *threads_param = (thread_param_t *) mycalloc (opencl_ctx->devices_cnt, sizeof (thread_param_t));

  hc_thread_t *c_threads = (hc_thread_t *) mycalloc (opencl_ctx->devices_cnt, sizeof (hc_thread_t));

  status_ctx->devices_status = STATUS_AUTOTUNE;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    thread_param_t *thread_param = threads_param + device_id;

    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid         = device_id;

    hc_thread_create (c_threads[device_id], thread_autotune, thread_param);
  }

  hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

  EVENT_SEND (EVENT_AUTOTUNE_FINISHED);

  /**
   * autotune modified kernel_accel, which modifies opencl_ctx->kernel_power_all
   */

  opencl_ctx_devices_update_power (hashcat_ctx);

  /**
   * Begin loopback recording
   */

  if (user_options->loopback == true)
  {
    loopback_write_open (hashcat_ctx);
  }

  /**
   * Prepare cracking stats
   */

  hc_timer_set (&status_ctx->timer_running);

  time_t runtime_start;

  time (&runtime_start);

  status_ctx->runtime_start = runtime_start;

  status_ctx->prepare_time = runtime_start - status_ctx->prepare_start;

  /**
   * create cracker threads
   */

  EVENT_SEND (EVENT_CRACKER_STARTING);

  status_ctx->devices_status = STATUS_RUNNING;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    thread_param_t *thread_param = threads_param + device_id;

    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid         = device_id;

    if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      hc_thread_create (c_threads[device_id], thread_calc_stdin, thread_param);
    }
    else
    {
      hc_thread_create (c_threads[device_id], thread_calc, thread_param);
    }
  }

  hc_thread_wait (opencl_ctx->devices_cnt, c_threads);

  myfree (c_threads);

  myfree (threads_param);

  if ((status_ctx->devices_status != STATUS_CRACKED)
   && (status_ctx->devices_status != STATUS_ABORTED)
   && (status_ctx->devices_status != STATUS_QUIT)
   && (status_ctx->devices_status != STATUS_BYPASS))
  {
    status_ctx->devices_status = STATUS_EXHAUSTED;
  }

  EVENT_SEND (EVENT_CRACKER_FINISHED);

  // update some timer

  time_t runtime_stop;

  time (&runtime_stop);

  status_ctx->runtime_stop = runtime_stop;

  logfile_sub_uint (runtime_start);
  logfile_sub_uint (runtime_stop);

  time (&status_ctx->prepare_start);

  EVENT_SEND (EVENT_CRACKER_FINAL_STATS);

  // no more skip and restore from here

  if (status_ctx->devices_status == STATUS_EXHAUSTED)
  {
    rd->words_cur = 0;
  }

  // stop loopback recording

  if (user_options->loopback == true)
  {
    loopback_write_close (hashcat_ctx);
  }

  EVENT_SEND (EVENT_LOGFILE_SUB_FINALIZE);

  // New induction folder check

  if (induct_ctx->induction_dictionaries_cnt == 0)
  {
    induct_ctx_scan (hashcat_ctx);

    while (induct_ctx->induction_dictionaries_cnt)
    {
      for (induct_ctx->induction_dictionaries_pos = 0; induct_ctx->induction_dictionaries_pos < induct_ctx->induction_dictionaries_cnt; induct_ctx->induction_dictionaries_pos++)
      {
        const int rc_inner2_loop = inner2_loop (hashcat_ctx);

        if (rc_inner2_loop == -1) return -1;

        if (status_ctx->run_main_level3 == false) break;

        unlink (induct_ctx->induction_dictionaries[induct_ctx->induction_dictionaries_pos]);
      }

      myfree (induct_ctx->induction_dictionaries);

      induct_ctx_scan (hashcat_ctx);
    }
  }

  return 0;
}

// inner1_loop iterates through masks, then calls inner2_loop

static int inner1_loop (hashcat_ctx_t *hashcat_ctx)
{
  restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;
  straight_ctx_t *straight_ctx  = hashcat_ctx->straight_ctx;

  //status_ctx->run_main_level1   = true;
  //status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  /**
   * loop through wordlists
   */

  EVENT_SEND (EVENT_INNERLOOP2_STARTING);

  restore_data_t *rd = restore_ctx->rd;

  if (straight_ctx->dicts_cnt)
  {
    for (u32 dicts_pos = rd->dicts_pos; dicts_pos < straight_ctx->dicts_cnt; dicts_pos++)
    {
      rd->dicts_pos = dicts_pos;

      straight_ctx->dicts_pos = dicts_pos;

      const int rc_inner2_loop = inner2_loop (hashcat_ctx);

      if (rc_inner2_loop == -1) return -1;

      if (status_ctx->run_main_level3 == false) break;
    }
  }
  else
  {
    const int rc_inner2_loop = inner2_loop (hashcat_ctx);

    if (rc_inner2_loop == -1) return -1;
  }

  EVENT_SEND (EVENT_INNERLOOP2_FINISHED);

  return 0;
}

// outer_loop iterates through hash_modes (in benchmark mode)
// also initializes stuff that depend on hash mode

static int outer_loop (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t             *hashes              = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  opencl_ctx_t         *opencl_ctx          = hashcat_ctx->opencl_ctx;
  outcheck_ctx_t       *outcheck_ctx        = hashcat_ctx->outcheck_ctx;
  restore_ctx_t        *restore_ctx         = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  status_ctx->devices_status = STATUS_INIT;

  //status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  /**
   * setup prepare timer
   */

  time (&status_ctx->prepare_start);

  /**
   * setup variables and buffers depending on hash_mode
   */

  const int rc_hashconfig = hashconfig_init (hashcat_ctx);

  if (rc_hashconfig == -1) return -1;

  /**
   * potfile show/left depends on hash_mode, so it's called here first time
   */

  if (user_options->show == true || user_options->left == true)
  {
    outfile_write_open (hashcat_ctx);

    potfile_read_open  (hashcat_ctx);
    potfile_read_parse (hashcat_ctx);
    potfile_read_close (hashcat_ctx);
  }

  /**
   * load hashes, stage 1
   */

  const int rc_hashes_init_stage1 = hashes_init_stage1 (hashcat_ctx);

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
    outfile_write_close (hashcat_ctx);

    potfile_hash_free (hashcat_ctx);

    return 0;
  }

  /**
   * potfile removes
   */

  if (user_options->potfile_disable == 0)
  {
    EVENT_SEND (EVENT_POTFILE_REMOVE_PARSE);

    potfile_remove_parse (hashcat_ctx);
  }

  /**
   * load hashes, stage 2, remove duplicates, build base structure
   */

  hashes->hashes_cnt_orig = hashes->hashes_cnt;

  const int rc_hashes_init_stage2 = hashes_init_stage2 (hashcat_ctx);

  if (rc_hashes_init_stage2 == -1) return -1;

  /**
   * load hashes, stage 2: at this point we can check for all hashes cracked (by potfile)
   */

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    EVENT_SEND (EVENT_POTFILE_ALL_CRACKED);

    hashes_destroy (hashcat_ctx);

    hashconfig_destroy (hashcat_ctx);

    potfile_destroy (hashcat_ctx);

    return 0;
  }

  /**
   * load hashes, stage 3, automatic Optimizers
   */

  const int rc_hashes_init_stage3 = hashes_init_stage3 (hashcat_ctx);

  if (rc_hashes_init_stage3 == -1) return -1;

  hashes_logger (hashcat_ctx);

  /**
   * bitmaps
   */

  EVENT_SEND (EVENT_BITMAP_INIT_PRE);

  bitmap_ctx_init (hashcat_ctx);

  EVENT_SEND (EVENT_BITMAP_INIT_POST);

  /**
   * cracks-per-time allocate buffer
   */

  cpt_ctx_init (hashcat_ctx);

  /**
   * Wordlist allocate buffer
   */

  wl_data_init (hashcat_ctx);

  /**
   * straight mode init
   */

  const int rc_straight_init = straight_ctx_init (hashcat_ctx);

  if (rc_straight_init == -1) return -1;

  /**
   * straight mode init
   */

  const int rc_combinator_init = combinator_ctx_init (hashcat_ctx);

  if (rc_combinator_init == -1) return -1;

  /**
   * charsets : keep them together for more easy maintainnce
   */

  const int rc_mask_init = mask_ctx_init (hashcat_ctx);

  if (rc_mask_init == -1) return -1;

  /**
   * prevent the user from using --skip/--limit together w/ maskfile and or dictfile
   */

  if (user_options->skip != 0 || user_options->limit != 0)
  {
    if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
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
    if ((mask_ctx->masks_cnt > 1) || (straight_ctx->dicts_cnt > 1))
    {
      log_error ("ERROR: --keyspace is not supported with --increment or mask files");

      return -1;
    }
  }

  /**
   * status progress init; needs hashes that's why we have to do it here and separate from status_ctx_init
   */

  const int rc_status_init = status_progress_init (hashcat_ctx);

  if (rc_status_init == -1) return -1;

  /**
   * main screen
   */

  EVENT_SEND (EVENT_OUTERLOOP_MAINSCREEN);

  /**
   * inform the user
   */

  EVENT_SEND (EVENT_OPENCL_SESSION_PRE);

  opencl_session_begin (hashcat_ctx);

  EVENT_SEND (EVENT_OPENCL_SESSION_POST);

  /**
   * weak hash check is the first to write to potfile, so open it for writing from here
   */

  const int rc_potfile_write = potfile_write_open (hashcat_ctx);

  if (rc_potfile_write == -1) return -1;

  /**
   * weak hash check
   */

  if (user_options->weak_hash_threshold >= hashes->salts_cnt)
  {
    hc_device_param_t *device_param = NULL;

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      break;
    }

    EVENT_SEND (EVENT_WEAK_HASH_PRE);

    for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
    {
      weak_hash_check (hashcat_ctx, device_param, salt_pos);
    }

    EVENT_SEND (EVENT_WEAK_HASH_POST);
  }

  /**
   * status and monitor threads
   */

  int inner_threads_cnt = 0;

  hc_thread_t *inner_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  status_ctx->shutdown_inner = false;

  /**
    * Outfile remove
    */

  if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
  {
    hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, hashcat_ctx);

    inner_threads_cnt++;

    if (outcheck_ctx->enabled == true)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_outfile_remove, hashcat_ctx);

      inner_threads_cnt++;
    }
  }

  /**
   * Tell user about cracked hashes by potfile
   */

  EVENT_SEND (EVENT_POTFILE_NUM_CRACKED);

  // main call

  EVENT_SEND (EVENT_INNERLOOP1_STARTING);

  if (mask_ctx->masks_cnt)
  {
    restore_data_t *rd = restore_ctx->rd;

    for (u32 masks_pos = rd->masks_pos; masks_pos < mask_ctx->masks_cnt; masks_pos++)
    {
      if (masks_pos > rd->masks_pos)
      {
        rd->dicts_pos = 0;
      }

      rd->masks_pos = masks_pos;

      mask_ctx->masks_pos = masks_pos;

      const int rc_inner1_loop = inner1_loop (hashcat_ctx);

      if (rc_inner1_loop == -1) return -1;

      if (status_ctx->run_main_level2 == false) break;
    }
  }
  else
  {
    const int rc_inner1_loop = inner1_loop (hashcat_ctx);

    if (rc_inner1_loop == -1) return -1;
  }

  // wait for inner threads

  status_ctx->shutdown_inner = true;

  for (int thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &inner_threads[thread_idx]);
  }

  myfree (inner_threads);

  EVENT_SEND (EVENT_INNERLOOP1_FINISHED);

  // finalize potfile

  potfile_write_close (hashcat_ctx);

  // finalize opencl session

  opencl_session_destroy (hashcat_ctx);

  // clean up

  status_progress_destroy (hashcat_ctx);

  bitmap_ctx_destroy (hashcat_ctx);

  mask_ctx_destroy (hashcat_ctx);

  combinator_ctx_destroy (hashcat_ctx);

  straight_ctx_destroy (hashcat_ctx);

  hashes_destroy (hashcat_ctx);

  hashconfig_destroy (hashcat_ctx);

  wl_data_destroy (hashcat_ctx);

  cpt_ctx_destroy (hashcat_ctx);

  return 0;
}

int hashcat (hashcat_ctx_t *hashcat_ctx, char *install_folder, char *shared_folder, int argc, char **argv, const int comptime)
{
  logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  /**
   * status init
   */

  const int rc_status_init = status_ctx_init (hashcat_ctx);

  if (rc_status_init == -1) return -1;

  EVENT_SEND (EVENT_WELCOME_SCREEN);

  /**
   * folder
   */

  const int rc_folder_config_init = folder_config_init (hashcat_ctx, install_folder, shared_folder);

  if (rc_folder_config_init == -1) return -1;

  /**
   * restore
   */

  const int rc_restore_init = restore_ctx_init (hashcat_ctx, argc, argv);

  if (rc_restore_init == -1) return -1;

  /**
   * process user input
   */

  user_options_preprocess (hashcat_ctx);

  user_options_extra_init (hashcat_ctx);

  // from here all user configuration is pre-processed so we can start logging

  EVENT_SEND (EVENT_LOGFILE_TOP_INITIALIZE);

  /**
   * To help users a bit
   */

  setup_environment_variables ();

  setup_umask ();

  /**
   * prepare seeding for random number generator, required by logfile and rules generator
   */

  setup_seeding (user_options->rp_gen_seed_chgd, user_options->rp_gen_seed);

  /**
   * tuning db
   */

  const int rc_tuning_db = tuning_db_init (hashcat_ctx);

  if (rc_tuning_db == -1) return -1;

  /**
   * induction directory
   */

  const int rc_induct_ctx_init = induct_ctx_init (hashcat_ctx);

  if (rc_induct_ctx_init == -1) return -1;

  /**
   * outfile-check directory
   */

  const int rc_outcheck_ctx_init = outcheck_ctx_init (hashcat_ctx);

  if (rc_outcheck_ctx_init == -1) return -1;

  /**
   * outfile itself
   */

  const int rc_outfile_init = outfile_init (hashcat_ctx);

  if (rc_outfile_init == -1) return -1;

  /**
   * Sanity check for hashfile vs outfile (should not point to the same physical file)
   */

  const int rc_outfile_and_hashfile = outfile_and_hashfile (hashcat_ctx);

  if (rc_outfile_and_hashfile == -1) return -1;

  /**
   * potfile init
   * this is only setting path because potfile can be used in read and write mode depending on user options
   * plus it depends on hash_mode, so we continue using it in outer_loop
   */

  const int rc_potfile_init = potfile_init (hashcat_ctx);

  if (rc_potfile_init == -1) return -1;
  /**
   * dictstat init
   */

  const int rc_dictstat_init = dictstat_init (hashcat_ctx);

  if (rc_dictstat_init == -1) return -1;

  dictstat_read (hashcat_ctx);

  /**
   * loopback init
   */

  const int rc_loopback_init = loopback_init (hashcat_ctx);

  if (rc_loopback_init == -1) return -1;

  /**
   * debugfile init
   */

  const int rc_debugfile_init = debugfile_init (hashcat_ctx);

  if (rc_debugfile_init == -1) return -1;

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

  const int rc_opencl_init = opencl_ctx_init (hashcat_ctx);

  if (rc_opencl_init == -1) return -1;

  /**
   * Init OpenCL devices
   */

  const int rc_devices_init = opencl_ctx_devices_init (hashcat_ctx, comptime);

  if (rc_devices_init == -1) return -1;

  /**
   * HM devices: init
   */

  const int rc_hwmon_init = hwmon_ctx_init (hashcat_ctx);

  if (rc_hwmon_init == -1) return -1;

  /**
   * outer loop
   */

  EVENT_SEND (EVENT_OUTERLOOP_STARTING);

  if (user_options->benchmark == true)
  {
    user_options->quiet = true;

    if (user_options->hash_mode_chgd == true)
    {
      const int rc = outer_loop (hashcat_ctx);

      if (rc == -1) return -1;
    }
    else
    {
      for (u32 algorithm_pos = 0; algorithm_pos < DEFAULT_BENCHMARK_ALGORITHMS_CNT; algorithm_pos++)
      {
        user_options->hash_mode = DEFAULT_BENCHMARK_ALGORITHMS_BUF[algorithm_pos];

        const int rc = outer_loop (hashcat_ctx);

        if (rc == -1) return -1;

        if (status_ctx->run_main_level1 == false) break;
      }
    }
  }
  else
  {
    const int rc = outer_loop (hashcat_ctx);

    if (rc == -1) return -1;
  }

  EVENT_SEND (EVENT_OUTERLOOP_FINISHED);

  if (user_options->benchmark == true)
  {
    user_options->quiet = false;
  }

  // if exhausted or cracked, unlink the restore file

  unlink_restore (hashcat_ctx);

  // final update dictionary cache

  dictstat_write (hashcat_ctx);

  // free memory

  debugfile_destroy (hashcat_ctx);

  tuning_db_destroy (hashcat_ctx);

  loopback_destroy (hashcat_ctx);

  dictstat_destroy (hashcat_ctx);

  potfile_destroy (hashcat_ctx);

  induct_ctx_destroy (hashcat_ctx);

  outfile_destroy (hashcat_ctx);

  outcheck_ctx_destroy (hashcat_ctx);

  folder_config_destroy (hashcat_ctx);

  hwmon_ctx_destroy (hashcat_ctx);

  opencl_ctx_devices_destroy (hashcat_ctx);

  opencl_ctx_destroy (hashcat_ctx);

  restore_ctx_destroy (hashcat_ctx);

  time (&status_ctx->proc_stop);

  logfile_top_uint (status_ctx->proc_start);
  logfile_top_uint (status_ctx->proc_stop);

  EVENT_SEND (EVENT_LOGFILE_TOP_FINALIZE);

  user_options_extra_destroy (hashcat_ctx);

  user_options_destroy (hashcat_ctx);

  int rc_final = -1;

  if (status_ctx->devices_status == STATUS_ABORTED)   rc_final = 2;
  if (status_ctx->devices_status == STATUS_QUIT)      rc_final = 2;
  if (status_ctx->devices_status == STATUS_EXHAUSTED) rc_final = 1;
  if (status_ctx->devices_status == STATUS_CRACKED)   rc_final = 0;

  EVENT_SEND (EVENT_GOODBYE_SCREEN);

  status_ctx_destroy (hashcat_ctx);

  // done

  return rc_final;
}
