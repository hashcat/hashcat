/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"

// basic tools

#include "types.h"
#include "folder.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"
#include "system.h"
#include "path.h"
#include "thread.h"
#include "timer.h"

// features

#include "affinity.h"
#include "autotune.h"
#include "benchmark.h"
#include "bitmap.h"
#include "bridges.h"
#include "combinator.h"
#include "cpt.h"
#include "debugfile.h"
#include "dispatch.h"
#include "dynamicx.h"
#include "event.h"
#include "hashes.h"
#include "hwmon.h"
#include "hlfmt.h"
#include "induct.h"
#include "interface.h"
#include "logfile.h"
#include "loopback.h"
#include "monitor.h"
#include "mpsp.h"
#include "backend.h"
#include "outfile_check.h"
#include "outfile.h"
#include "pidfile.h"
#include "potfile.h"
#include "pubkey.h"
#include "restore.h"
#include "selftest.h"
#include "status.h"
#include "feed_ctx.h"
#include "straight.h"
#include "tuningdb.h"
#include "user_options.h"
#include "wordlist.h"
#include "hashcat.h"
#include "ext_zlib.h"
#include "ext_lzma.h"
#include "ext_zstd.h"
#include "ext_iconv.h"
#include "usage.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

// Measure how every device should be launched for this round.
//
// Returns 0 when the round can go ahead, and -10 when every enabled device failed to tune and there is
// nothing left to run on. A device that failed on its own is skipped here and the run continues on the
// rest, which is why the caller cannot decide this from a return code alone.

static int inner2_autotune (hashcat_ctx_t *hashcat_ctx, thread_param_t *threads_param, hc_thread_t *c_threads)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  EVENT (EVENT_AUTOTUNE_STARTING);

  status_ctx->devices_status = STATUS_AUTOTUNE;

  // Which devices are interchangeable, decided before anything is measured, because it decides what
  // has to be measured at all.

  backend_ctx_devices_group (hashcat_ctx);

  // AUTOTUNE ONE DEVICE PER GROUP, not one per device.
  //
  // Every trial is a real launch, and on an accelerator a real launch is the algorithm running at the
  // user's own cost factor. Sixty four identical devices measured the same answer sixty four times
  // over and then had it overwritten by backend_ctx_devices_sync_tuning below, which has always
  // copied one group member's tuning onto the rest. The measurement was the part that was redundant,
  // not the copy.
  //
  // A device that is not the leader of its group is left at its minimum here and takes the leader's
  // answer from sync_tuning, clamped to what its own buffers can hold.

  int autotune_cnt = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    if (backend_ctx_device_is_group_leader (hashcat_ctx, backend_devices_idx) == false) continue;

    thread_param_t *thread_param = threads_param + backend_devices_idx;

    thread_param->hashcat_ctx = hashcat_ctx;
    thread_param->tid         = backend_devices_idx;

    // autotune is bounded work, so a device whose thread will not start is tuned on this thread
    // rather than left untuned. Only a real thread goes into the wait below.

    if (hc_thread_create_ok (c_threads[autotune_cnt], thread_autotune, thread_param) == true)
    {
      autotune_cnt++;
    }
    else
    {
      thread_autotune (thread_param);
    }
  }

  hc_thread_wait (autotune_cnt, c_threads);

  // check for any autotune failures
  // by default, skipping device on error
  // using --force, accel/loops/threads min values are used instead of skipping

  int at_err = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    if (backend_ctx->enabled == false) continue;

    hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

    if (device_param->skipped == true) continue;

    if (device_param->skipped_warning == true) continue;

    if (device_param->at_status == AT_STATUS_FAILED)
    {
      at_err++;

      if (user_options->force == false)
      {
        event_log_warning (hashcat_ctx, "* Device #%u: skipped, due to kernel autotune failure (%d).", device_param->device_id + 1, device_param->at_rc);

        device_param->skipped = true;

        // update counters

        if (device_param->is_hip == true)    backend_ctx->hip_devices_active--;
        if (device_param->is_cuda == true)   backend_ctx->cuda_devices_active--;
        if (device_param->is_opencl == true) backend_ctx->opencl_devices_active--;

        backend_ctx->backend_devices_active--;
      }
      else
      {
        event_log_warning (hashcat_ctx, "* Device #%u: detected kernel autotune failure (%d), min values will be used", device_param->device_id + 1, device_param->at_rc);
      }
    }
  }

  if (at_err > 0)
  {
    event_log_warning (hashcat_ctx, NULL);

    if (user_options->force == false)
    {
      // if all enabled devices fail, abort session
      if (backend_ctx->backend_devices_active <= 0)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel autotune failures, for all active devices.");

        event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        return -10;
      }
    }
  }

  EVENT (EVENT_AUTOTUNE_FINISHED);

  return 0;
}

// inner2_loop iterates through wordlists, then calls kernel execution

static int inner2_loop (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t             *hashes              = hashcat_ctx->hashes;
  induct_ctx_t         *induct_ctx          = hashcat_ctx->induct_ctx;
  logfile_ctx_t        *logfile_ctx         = hashcat_ctx->logfile_ctx;
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  restore_ctx_t        *restore_ctx         = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  //status_ctx->run_main_level1   = true;
  //status_ctx->run_main_level2   = true;
  //status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  status_ctx->devices_status = STATUS_INIT;

  logfile_generate_subid (hashcat_ctx);

  logfile_sub_msg ("START");

  // ONE ATTACK, NOT A QUEUE OF THEM.
  //
  // -a 9 splitting its own hash file makes its own rounds, one per word position in an account name,
  // and the user never asked for them. Reporting them as separate attacks resets the progress, the
  // elapsed time and the estimate several times over a run, which is what a user watching the status
  // screen complains about: the run keeps starting again.
  //
  // words_walk_base is what says a round already ran in this process. It is only ever advanced by a
  // round that got far enough to be sized, and outer_loop starts it at zero, so it is true for the
  // second and later rounds and false for a session restored into the middle of a queue.

  const bool round_continues = ((user_options_extra->association_autosplit == true) && (status_ctx->words_walk_base > 0));

  // msec_paused is subtracted from the elapsed time, so it belongs to whatever timer_running is
  // measuring. A continuation round leaves that timer alone, so it must leave this alone too.

  if (round_continues == false)
  {
    status_progress_reset (hashcat_ctx);

    status_ctx->msec_paused = 0;
  }

  status_ctx->words_off = 0;
  status_ctx->words_cur = 0;

  status_ctx->seek_pending = false;
  status_ctx->seek_target  = 0;
  status_ctx->seek_step    = 0;
  status_ctx->seek_dir     = 0;

  // Where the round starts is only settled below, once its own keyspace is known, because --skip is a
  // position in the whole queue of rounds and not in this one. A restored session is the exception:
  // its position came out of the restore file and is already this round's, so it is taken here and
  // --restore overrides --skip exactly as it always did.

  bool restored = false;

  if (restore_ctx->restore_execute == true)
  {
    restore_ctx->restore_execute = false;

    restore_data_t *rd = restore_ctx->rd;

    status_ctx->words_off = rd->words_cur;
    status_ctx->words_cur = status_ctx->words_off;

    restored = true;
  }

  backend_session_reset (hashcat_ctx);

  cpt_ctx_reset (hashcat_ctx);

  /**
   * Update attack-mode specific stuff based on mask
   */

  // Cleared per round, because a producer states it per round and the value from the round before it
  // must not be read as this round's.

  status_ctx->words_base_given = 0;

  if (mask_ctx_update_loop (hashcat_ctx) == -1) return 0;

  /**
   * Update attack-mode specific stuff based on wordlist
   */

  if (straight_ctx_update_loop (hashcat_ctx) == -1) return 0;

  // words base

  const u64 amplifier_cnt = user_options_extra_amplifier (hashcat_ctx);

  // The division is exact only while words_cnt is, so a producer that knows its base is believed over
  // it. A mask states nothing and is recovered by division exactly as before.
  //
  // A producer states its base in base words, and a base word is what the run is addressed by only
  // while the amplifier runs on the device. --slow-candidates builds every candidate on the host, so
  // there the unit is the candidate and words_cnt already counts them. Its amplifier is 1, which
  // leaves the division exact, so the division is the answer and the stated base is not.

  const bool base_given = ((status_ctx->words_base_given > 0) && (user_options->slow_candidates == false));

  status_ctx->words_base = (base_given == true) ? status_ctx->words_base_given : (status_ctx->words_cnt / amplifier_cnt);

  // Where this round sits in the queue, and how much longer the queue is now. A mask that was skipped
  // for being too short or too long returned above and adds nothing, which is right: it is not part
  // of the keyspace and --keyspace must not count it.

  const u64 walk_first = status_ctx->words_walk_base;

  // --lookup answered in this round's own numbering, because that is the only numbering the round's
  // tables know. --skip addresses the queue, so the answer is moved into the queue's here, where how
  // far into it this round begins is finally known. Once moved it stays put: the round that found it
  // is the first that reaches it and no later round can be nearer.

  if ((mask_ctx->lookup.hit == true) && (mask_ctx->lookup.placed == false))
  {
    mask_ctx->lookup.placed = true;
    mask_ctx->lookup.word  += walk_first;
  }

  if ((mask_ctx->lookup_combi.hit == true) && (mask_ctx->lookup_combi.placed == false))
  {
    mask_ctx->lookup_combi.placed = true;
    mask_ctx->lookup_combi.word  += walk_first;
  }

  status_ctx->words_walk_base += status_ctx->words_base;
  status_ctx->words_walk_cnt  += status_ctx->words_cnt;

  // --keyspace answers for the whole queue, so every round is sized and none of them is run. The
  // total is reported once the queue has been walked, by outer_loop.

  if (user_options->keyspace == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    return 0;
  }

  // This round's share of the window --skip and --limit describe. Both are positions in the queue, so
  // they are moved to the front of this round, and a round the window does not reach is not run at
  // all rather than run with no work in it.

  status_ctx->words_skip  = 0;
  status_ctx->words_limit = 0;

  const bool one_round = ((mask_ctx->masks_cnt <= 1) && (straight_ctx->dicts_cnt <= 1));

  if (user_options->skip > walk_first)
  {
    status_ctx->words_skip = user_options->skip - walk_first;

    // A queue of rounds passes over one the window does not reach. A single round has nothing to pass
    // over to, so a --skip past its end is the command line mistake it always was and the keyspace
    // check further down is what says so.

    if ((status_ctx->words_skip >= status_ctx->words_base) && (one_round == false))
    {
      // The round has finished the nothing the window asked of it. Saying so is what keeps a run
      // whose window covers no round at all from ending in the state it started in, which reports a
      // failure for a chunk that was simply empty. A chunk at the end of the queue is one somebody
      // in a distributed setup has been handed.

      status_ctx->devices_status = STATUS_EXHAUSTED;

      logfile_sub_msg ("STOP");

      return 0;
    }
  }

  if (user_options->limit > 0)
  {
    if (user_options->limit <= walk_first)
    {
      status_ctx->devices_status = STATUS_EXHAUSTED;

      logfile_sub_msg ("STOP");

      return 0;
    }

    status_ctx->words_limit = user_options->limit - walk_first;
  }

  // A restored session is already where it belongs, and --restore overrides --skip.

  if (restored == false)
  {
    status_ctx->words_off = status_ctx->words_skip;
    status_ctx->words_cur = status_ctx->words_off;
  }

  // restore stuff

  if (status_ctx->words_off > status_ctx->words_base)
  {
    event_log_error (hashcat_ctx, "Restore value is greater than keyspace.");

    return -1;
  }

  // A source that cannot be seeked only reaches a position by consuming everything before it, so the
  // words --skip or --restore passes over are read and thrown away here. This is a pipe, and it is
  // done before the device threads exist because the offsets they ask for are one per device and none
  // of them is where the run starts.
  //
  // Those words were read, so they are booked as rejected rather than as restored: the two counters
  // are added together to make the progress line, and booking them in both would count them twice.

  if ((user_options_extra->wordlist_mode == WL_MODE_STDIN) && (status_ctx->words_off > 0))
  {
    // Any device's thread context will do, because the plugin holds one stream behind one mutex and
    // nothing else is reading it yet. It has to be one that exists, though: only devices that were
    // not skipped were given a thread context.

    int device_id = -1;

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;
      if (device_param->skipped_warning == true) continue;

      device_id = device_param->device_id;

      break;
    }

    if (device_id == -1) return -1;

    if (generic_ctx_base_discard (hashcat_ctx, device_id, status_ctx->words_off) == -1) return -1;
  }
  else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    const u64 progress_restored = 1 * amplifier_cnt;

    for (u32 i = 0; i < status_ctx->words_off; i++)
    {
      status_ctx->words_progress_restored[i] = progress_restored;
    }
  }
  else
  {
    const u64 progress_restored = status_ctx->words_off * amplifier_cnt;

    for (u32 i = 0; i < hashes->salts_cnt; i++)
    {
      status_ctx->words_progress_restored[i] = progress_restored;
    }
  }

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    user_options->brain_attack = brain_compute_attack (hashcat_ctx);
  }
  #endif

  /**
   * limit kernel loops by the amplification count we have from:
   * - straight_ctx, combinator_ctx or mask_ctx for fast hashes
   * - hash iteration count for slow hashes
   * this is required for autotune
   */

  backend_ctx_devices_kernel_loops (hashcat_ctx);

  /**
   * prepare thread buffers
   */

  thread_param_t *threads_param = (thread_param_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (thread_param_t));

  hc_thread_t *c_threads = (hc_thread_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (hc_thread_t));

  int calc_threads_live = 0;

  /**
   * create autotune threads
   */

  // The rounds of -a 9 splitting its own hash file are one attack, not a queue of different ones. A
  // round is "try the Nth word of every account name", so every round launches the same kernel over
  // the same digests with the same keyspace, and measuring each of them separately arrives at the same
  // answer as many times as there are rounds. On a slow hash that is seconds of real launches per
  // round, spent to learn nothing.
  //
  // The one thing a round boundary destroys is the tuning itself, because run_cracker zeroes it on its
  // way out. So the previous round's answer is taken back from where run_cracker saved it, and a round
  // that has no previous answer to take falls through and measures as usual.

  bool tuning_reused = false;

  if (user_options_extra->association_autosplit == true)
  {
    tuning_reused = backend_ctx_devices_tuning_restore (hashcat_ctx);
  }

  if (tuning_reused == false)
  {
    const int rc_autotune = inner2_autotune (hashcat_ctx, threads_param, c_threads);

    if (rc_autotune != 0) return rc_autotune;
  }

  /**
   * find same backend devices and equal results
   */

  backend_ctx_devices_sync_tuning (hashcat_ctx);

  /**
   * autotune modified kernel_accel, which modifies backend_ctx->kernel_power_all
   */

  backend_ctx_devices_update_power (hashcat_ctx);

  /**
   * Begin loopback recording
   */

  if (user_options->loopback == true)
  {
    loopback_write_open (hashcat_ctx);
  }

  /**
   * Set time for --bypass-delay and start point for --bypass-threshold
   */

  if (user_options->bypass_delay_chgd == true)
  {
    time (&status_ctx->timer_bypass_start);
    status_ctx->bypass_digests_done_new = hashcat_ctx->hashes->digests_done_new;
  }

  /**
   * Prepare cracking stats
   */

  // A continuation round keeps the clock the queue started on. Restarting it is what makes the elapsed
  // time and the estimate jump backwards every time a round ends, and the speed is an average over
  // this same window, so it takes the reading with it.

  if (round_continues == false)
  {
    hc_timer_set (&status_ctx->timer_running);

    time (&status_ctx->runtime_start);
  }

  const time_t runtime_start = status_ctx->runtime_start;

  /**
   * create cracker threads
   */

  if (round_continues == false) EVENT (EVENT_CRACKER_STARTING);

  status_ctx->devices_status = STATUS_RUNNING;

  status_ctx->accessible = true;

  // A seek stops every device and starts it again from the position it moved to. Everything set up
  // above survives that, the autotune and the backend session the devices are holding included, so
  // what repeats is the threads and the counters seek_apply () writes from the new position.

  for (;;)
  {
    calc_threads_live = 0;

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      thread_param_t *thread_param = threads_param + backend_devices_idx;

      thread_param->hashcat_ctx = hashcat_ctx;
      thread_param->tid         = backend_devices_idx;

      // A cracking thread cannot be run inline, it is the whole attack for that device. Keep the
      // handles that started packed at the front so the wait has no unset handle to join, and tell
      // the user, because a device that never starts means keyspace this run does not cover.

      if (hc_thread_create_ok (c_threads[calc_threads_live], thread_calc, thread_param) == true)
      {
        calc_threads_live++;
      }
      else
      {
        event_log_error (hashcat_ctx, "Could not start the cracking thread for device #%d.", backend_devices_idx + 1);

        backend_ctx->devices_param[backend_devices_idx].skipped = true;
      }
    }

    hc_thread_wait (calc_threads_live, c_threads);

    if (status_ctx->seek_pending == false) break;

    // A seek resumes a paused run before it arms anything, but the user can still pause again while
    // the devices are winding down. Waiting for the resume here, rather than reading a paused run as
    // a reason to end the round, is what keeps the pause meaning pause.

    while (status_ctx->devices_status == STATUS_PAUSED)
    {
      usleep (100000);
    }

    // Only a run that is still going picks itself up again. A crack that finished the hash list, an
    // abort and a quit all outrank a seek, and so does a checkpoint, which is a request to stop this
    // round where it is.
    //
    // A finish is not. It asks for no round after this one and leaves the device threads running, so
    // the seek is applied and the finish takes effect when the round ends on its own.

    if (status_ctx->devices_status      != STATUS_RUNNING) break;
    if (status_ctx->checkpoint_shutdown == true)           break;

    seek_apply (hashcat_ctx);
  }

  status_ctx->seek_pending = false;

  hcfree (c_threads);

  hcfree (threads_param);

  // checkpoint_taken covers the race the flag alone cannot: a cancel that arrived after a device had
  // already stopped used to clear checkpoint_shutdown here, and the round then fell through to
  // EXHAUSTED with its remaining keyspace never dispatched.

  if ((status_ctx->devices_status == STATUS_RUNNING) && ((status_ctx->checkpoint_shutdown == true) || (status_ctx->checkpoint_taken == true)))
  {
    myabort_checkpoint (hashcat_ctx);
  }

  if ((status_ctx->devices_status == STATUS_RUNNING) && (status_ctx->finish_shutdown == true))
  {
    myabort_finish (hashcat_ctx);
  }

  if ((status_ctx->devices_status != STATUS_CRACKED)
   && (status_ctx->devices_status != STATUS_ERROR)
   && (status_ctx->devices_status != STATUS_ABORTED)
   && (status_ctx->devices_status != STATUS_ABORTED_CHECKPOINT)
   && (status_ctx->devices_status != STATUS_ABORTED_FINISH)
   && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
   && (status_ctx->devices_status != STATUS_QUIT)
   && (status_ctx->devices_status != STATUS_BYPASS))
  {
    status_ctx->devices_status = STATUS_EXHAUSTED;
  }

  if (status_ctx->devices_status == STATUS_EXHAUSTED)
  {
    // the options speed-only and progress-only cause hashcat to abort quickly.
    // therefore, they will end up (if no other error occurred) as STATUS_EXHAUSTED.
    // however, that can create confusion in hashcats RC, because exhausted translates to RC = 1.
    // but then having RC = 1 does not match our exception if we use for speed-only and progress-only.
    // to get hashcat to return RC = 0 we have to set it to CRACKED or BYPASS
    // note: other options like --show, --left, --benchmark, --keyspace, --backend-info, etc.
    // do not reach this section of the code, they've returned already with rc 0.

    if ((user_options->speed_only == true) || (user_options->progress_only == true))
    {
      status_ctx->devices_status = STATUS_BYPASS;
    }
  }

  // A RUN WHERE EVERY DEVICE DIED COMPUTED NOTHING, AND MUST NOT REPORT SUCCESS.
  //
  // skipped_warning means a device came up and then went away during the run, which is what a bridge
  // sets when the last board behind a unit is dropped. Every loop that walks devices already skips
  // those, so once they are all in that state the walks find nobody, no work is done, and the run
  // ends normally with whatever status it happened to hold.
  //
  // On a real attack the self test catches the cause first and the process exits non-zero. Benchmark
  // mode has no self test, so an FPGA box whose only board was dropped printed a speed line for the
  // devices that were still nominally present and exited 0. Measured with a single board: no speed
  // line at all and exit 0, and with two units where one died, a total that silently omitted half the
  // hardware.
  //
  // Only devices that were meant to run are counted. A device the user excluded is 'skipped' and its
  // absence is not a failure.

  int devices_live = 0;
  int devices_lost = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    if (device_param->skipped_warning == true)
    {
      devices_lost++;

      continue;
    }

    devices_live++;
  }

  if ((devices_live == 0) && (devices_lost > 0))
  {
    event_log_error (hashcat_ctx, "All compute devices were lost during this attack, so nothing was computed.");

    status_ctx->devices_status = STATUS_ERROR;
  }

  // update some timer

  time_t runtime_stop;

  time (&runtime_stop);

  status_ctx->runtime_stop = runtime_stop;

  logfile_sub_uint (runtime_start);
  logfile_sub_uint (runtime_stop);

  if (hashcat_get_status (hashcat_ctx, status_ctx->hashcat_status_final) == -1)
  {
    fprintf (stderr, "Initialization problem: the hashcat status monitoring function returned an unexpected value\n");
  }

  status_ctx->accessible = false;

  // update newly cracked hashes per session

  logfile_sub_uint (hashes->digests_done_new);

  // Whether another round of the same attack follows this one. Only an exhausted round moves on: a
  // crack that finished the hash list, an abort and a quit all end the run here, and each of them
  // wants the final status printed rather than swallowed.
  //
  // inner1_loop is what actually decides to run the next round, and it decides on run_main_level3.
  // Asking the same question the same way is what keeps a round from being the last one silently.

  bool round_follows = false;

  if (user_options_extra->association_autosplit == true)
  {
    round_follows = ((status_ctx->run_main_level3 == true) && (status_ctx->devices_status == STATUS_EXHAUSTED) && (straight_ctx->dicts_pos + 1 < straight_ctx->dicts_cnt));
  }

  if (round_follows == false) EVENT (EVENT_CRACKER_FINISHED);

  // mark sub logfile

  logfile_sub_var_uint ("status-after-work", status_ctx->devices_status);

  logfile_sub_msg ("STOP");

  // stop loopback recording

  if (user_options->loopback == true)
  {
    loopback_write_close (hashcat_ctx);
  }

  // New induction folder check, which is a controlled recursion

  if (induct_ctx->induction_dictionaries_cnt == 0)
  {
    induct_ctx_scan (hashcat_ctx);

    bool induct_stop = false;

    while ((induct_ctx->induction_dictionaries_cnt) && (induct_stop == false))
    {
      for (induct_ctx->induction_dictionaries_pos = 0; induct_ctx->induction_dictionaries_pos < induct_ctx->induction_dictionaries_cnt; induct_ctx->induction_dictionaries_pos++)
      {
        if (status_ctx->devices_status == STATUS_EXHAUSTED)
        {
          if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

          if (status_ctx->run_main_level3 == false) break;
        }

        // the round that just finished still holds this file open, and Windows will not delete a
        // file that is open. Give the instance up first, then delete.

        generic_ctx_base_close (hashcat_ctx);

        const char *consumed = induct_ctx->induction_dictionaries[induct_ctx->induction_dictionaries_pos];

        if (unlink (consumed) == -1)
        {
          // a dictionary that cannot be deleted would be found again by the next scan and read
          // forever, so stop inducting rather than spin. Whatever has been cracked so far stands.

          event_log_warning (hashcat_ctx, "%s: %s", consumed, strerror (errno));
          event_log_warning (hashcat_ctx, "Induction is stopping because that file would otherwise be read again.");
          event_log_warning (hashcat_ctx, NULL);

          induct_stop = true;

          break;
        }
      }

      if (induct_stop == true) break;

      // induct_ctx_scan () owns the previous scan now, strings included

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

  EVENT (EVENT_INNERLOOP2_STARTING);

  if (restore_ctx->rd)
  {
    restore_data_t *rd = restore_ctx->rd;

    if (rd->dicts_pos > 0)
    {
      straight_ctx->dicts_pos = rd->dicts_pos;

      rd->dicts_pos = 0;
    }
  }

  if (straight_ctx->dicts_cnt)
  {
    for (u32 dicts_pos = straight_ctx->dicts_pos; dicts_pos < straight_ctx->dicts_cnt; dicts_pos++)
    {
      straight_ctx->dicts_pos = dicts_pos;

      if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

      if (status_ctx->run_main_level3 == false) break;
    }

    if (status_ctx->run_main_level3 == true)
    {
      if (straight_ctx->dicts_pos + 1 == straight_ctx->dicts_cnt) straight_ctx->dicts_pos = 0;
    }
  }
  else
  {
    if (inner2_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);
  }

  EVENT (EVENT_INNERLOOP2_FINISHED);

  return 0;
}

// outer_loop iterates through hash_modes (in benchmark mode)
// also initializes stuff that depend on hash mode

static int outer_loop (hashcat_ctx_t *hashcat_ctx, const int iteration)
{
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  hashes_t             *hashes              = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  module_ctx_t         *module_ctx          = hashcat_ctx->module_ctx;
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  outcheck_ctx_t       *outcheck_ctx        = hashcat_ctx->outcheck_ctx;
  restore_ctx_t        *restore_ctx         = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  status_ctx->devices_status = STATUS_INIT;

  //status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  if (iteration) backend_session_context_reset (hashcat_ctx);

  /**
   * setup variables and buffers depending on hash_mode
   */

  EVENT (EVENT_HASHCONFIG_PRE);

  if (hashconfig_init (hashcat_ctx) == -1)
  {
    event_log_error (hashcat_ctx, "Invalid hash-mode '%u' selected.", user_options->hash_mode);

    return -1;
  }

  // -a 7 cannot say where its base words come from until the kernel type is settled, and
  // hashconfig_init is what settles it.

  user_options_extra_init_late (hashcat_ctx);

  EVENT (EVENT_HASHCONFIG_POST);

  /**
   * deprecated notice
   */

  if (module_ctx->module_deprecated_notice != MODULE_DEFAULT)
  {
    if (user_options->deprecated_check == true)
    {
      if ((user_options->show == true) || (user_options->left == true))
      {
        const char *module_deprecated_notice = module_ctx->module_deprecated_notice (hashconfig, user_options, user_options_extra);

        event_log_warning (hashcat_ctx, "%s", module_deprecated_notice);
        event_log_warning (hashcat_ctx, NULL);
      }
      else if (user_options->benchmark == true)
      {
        if (user_options->hash_mode_chgd == true)
        {
          const char *module_deprecated_notice = module_ctx->module_deprecated_notice (hashconfig, user_options, user_options_extra);

          event_log_warning (hashcat_ctx, "%s", module_deprecated_notice);
          event_log_warning (hashcat_ctx, NULL);
        }
        else
        {
          return 0;
        }
      }
      else
      {
        const char *module_deprecated_notice = module_ctx->module_deprecated_notice (hashconfig, user_options, user_options_extra);

        event_log_error (hashcat_ctx, "%s", module_deprecated_notice);

        return 0;
      }
    }
  }

  /**
   * generate hashlist filename for later use
   */

  if (hashes_init_filename (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, stage 1
   */

  EVENT (EVENT_HASHLIST_PARSE_INPUT_PRE);

  const int hashes_stage1_rc = hashes_init_stage1 (hashcat_ctx);

  EVENT (EVENT_HASHLIST_PARSE_INPUT_POST);

  if (hashes_stage1_rc == -1) return -1;

  if ((user_options->keyspace == false) && (user_options->stdout_flag == false))
  {
    if (hashes->hashes_cnt == 0)
    {
      event_log_error (hashcat_ctx, "No hashes loaded.");

      return -1;
    }
  }

  /**
   * load hashes, stage 2, remove duplicates, build base structure
   */

  hashes->hashes_cnt_orig = hashes->hashes_cnt;

  if (hashes_init_stage2 (hashcat_ctx) == -1) return -1;

  /**
   * potfile removes
   */

  if (user_options->potfile == true)
  {
    EVENT (EVENT_POTFILE_REMOVE_PARSE_PRE);

    if (user_options->loopback == true)
    {
      loopback_write_open (hashcat_ctx);
    }

    potfile_remove_parse (hashcat_ctx);

    if (user_options->loopback == true)
    {
      loopback_write_close (hashcat_ctx);
    }

    EVENT (EVENT_POTFILE_REMOVE_PARSE_POST);
  }

  /**
   * zero hash removes
   */

  if (hashes_init_zerohash (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, stage 3, update cracked results from potfile
   */

  if (hashes_init_stage3 (hashcat_ctx) == -1) return -1;

  /**
   * potfile show/left handling
   */

  if (user_options->show == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    outfile_write_open (hashcat_ctx);

    if (potfile_handle_show (hashcat_ctx) == -1) return -1;

    outfile_write_close (hashcat_ctx);

    return 0;
  }

  if (user_options->left == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    outfile_write_open (hashcat_ctx);

    if (potfile_handle_left (hashcat_ctx) == -1) return -1;

    outfile_write_close (hashcat_ctx);

    return 0;
  }

  /**
   * check global hash count in case module developer sets a them to a specific limit
   */

  if (hashes->digests_cnt < hashconfig->hashes_count_min)
  {
    event_log_error (hashcat_ctx, "Not enough hashes loaded - minimum is %u for this hash-mode.", hashconfig->hashes_count_min);

    return -1;
  }

  if (hashes->digests_cnt > hashconfig->hashes_count_max)
  {
    event_log_error (hashcat_ctx, "Too many hashes loaded - maximum is %u for this hash-mode.", hashconfig->hashes_count_max);

    return -1;
  }

  /**
   * maybe all hashes were cracked, we can exit here
   */

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    if ((user_options->remove == true) && ((hashes->hashlist_mode == HL_MODE_FILE_PLAIN) || (hashes->hashlist_mode == HL_MODE_FILE_BINARY)))
    {
      if (hashes->digests_saved != hashes->digests_done)
      {
        const int rc = save_hash (hashcat_ctx);

        if (rc == -1) return -1;
      }
    }

    EVENT (EVENT_POTFILE_ALL_CRACKED);

    return 0;
  }

  /**
   * load hashes, stage 4, automatic Optimizers
   */

  if (hashes_init_stage4 (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, selftest
   */

  if (hashes_init_selftest (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, post automatisation
   */

  if (hashes_init_stage5 (hashcat_ctx) == -1) return -1;

  /**
   * load hashes, benchmark
   */

  if (hashes_init_benchmark (hashcat_ctx) == -1) return -1;

  /**
   * Done loading hashes, log results
   */

  hashes_logger (hashcat_ctx);

  /**
   * outfile check preflight
   */

  // Results another run has already written are worth reading before the expensive setup rather than
  // only during the attack. Everything below this point costs time and device memory, and a hash list
  // the check directory already accounts for needs none of it.

  if (outcheck_preflight (hashcat_ctx) == -1) return -1;

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    // --remove rewrites the hash file with what is left, and a run that ends here has to do that the
    // same way the potfile path above does. Ending early is not a reason to leave the file describing
    // hashes that are now accounted for.

    if ((user_options->remove == true) && ((hashes->hashlist_mode == HL_MODE_FILE_PLAIN) || (hashes->hashlist_mode == HL_MODE_FILE_BINARY)))
    {
      if (hashes->digests_saved != hashes->digests_done)
      {
        if (save_hash (hashcat_ctx) == -1) return -1;
      }
    }

    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, "INFO: All hashes were already found in the outfile check directory.");
      event_log_info (hashcat_ctx, NULL);
    }

    return 0;
  }

  /**
   * bitmaps
   */

  EVENT (EVENT_BITMAP_INIT_PRE);

  if (bitmap_ctx_init (hashcat_ctx) == -1) return -1;

  EVENT (EVENT_BITMAP_INIT_POST);

  /**
   * cracks-per-time allocate buffer
   */

  cpt_ctx_init (hashcat_ctx);

  /**
   * generic mode init
   */

  // Ahead of the combinator, because -a 1 amplifies with a wordlist and the number of amplifier words
  // is a feed instance's keyspace. Ahead of the mask too, which is the other way round: -a 6 and -a 7
  // amplify with the mask and the mask is only sized once per round, so the feed keyspace is left in
  // base words here and straight_ctx_update_loop finishes it.

  if (generic_ctx_init (hashcat_ctx) == -1) return -1;

  // A feed can be asked to describe the attack instead of running it, and by now it has answered.
  // There is nothing left for this run to do, so the queue of rounds is never entered.
  //
  // devices_status is set for the same reason --keyspace sets it further down. A bare return leaves
  // STATUS_INIT, EVENT_OUTERLOOP_FINISHED turns STATUS_INIT into STATUS_ERROR because the keypress
  // thread waits on it, and the status mapping at the end of this file then makes that
  // RC_FINAL_ERROR. A question that was answered is not a failure.
  //
  // The destroys are the ones the tail of this function would have run for what has been initialised
  // so far. generic_ctx_destroy () is the one that matters: it calls global_term (), so the feed
  // gives its grammar back rather than leaving it to process exit.

  if (generic_ctx_described (hashcat_ctx) == true)
  {
    status_ctx->devices_status = STATUS_RUNNING;

    generic_ctx_destroy (hashcat_ctx);
    cpt_ctx_destroy     (hashcat_ctx);
    bitmap_ctx_destroy  (hashcat_ctx);
    hashes_destroy      (hashcat_ctx);
    hashconfig_destroy  (hashcat_ctx);

    return 0;
  }

  EVENT (EVENT_CANDIDATE_SOURCE_PRE);

  /**
   * straight mode init
   */

  if (straight_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * combinator mode init
   */

  if (combinator_ctx_init (hashcat_ctx) == -1) return -1;

  // -a 1 has now chosen which of its two dictionaries is the base, which is the last thing needed to
  // say which of -j and -k applies to a base word and which to an amplifier word.

  user_options_extra_init_rules (hashcat_ctx);

  /**
   * charsets : keep them together for more easy maintenance
   */

  if (mask_ctx_init (hashcat_ctx) == -1) return -1;

  EVENT (EVENT_CANDIDATE_SOURCE_POST);

  /**
   * prevent the user from using --skip/--limit together with multiple word lists
   */

  // --increment and a mask file are a queue of rounds and the queue is one keyspace, so --skip and
  // --limit address the queue and no longer have to be refused. A queue of dictionaries is not the
  // same thing: induction writes the dictionary the next round reads, so the queue's length is not
  // known when the window would have to be divided up.

  if (user_options->skip != 0 || user_options->limit != 0)
  {
    if (straight_ctx->dicts_cnt > 1)
    {
      event_log_error (hashcat_ctx, "Use of --skip/--limit is not supported with multiple dictionaries or --stdout.");

      return -1;
    }

    // A resumed session starts inside one round of the queue, and the restore file records the
    // position in that round without recording how far into the queue the round itself begins. The
    // window cannot be divided up without that, and dividing it wrongly would run a chunk past its
    // own end, so the combination is refused rather than guessed at.

    if ((restore_ctx->restore_execute == true) && (mask_ctx->masks_cnt > 1))
    {
      event_log_error (hashcat_ctx, "Use of --skip/--limit is not supported with --restore over several masks.");

      return -1;
    }
  }

  /**
   * prevent the user from using --keyspace together with multiple word lists
   */

  if (user_options->keyspace == true)
  {
    if (straight_ctx->dicts_cnt > 1)
    {
      event_log_error (hashcat_ctx, "Use of --keyspace is not supported with multiple dictionaries.");

      return -1;
    }
  }

  /**
   * prevent the user from using -m/--hash-type together with --stdout
   */

  if (user_options->hash_mode_chgd == true && user_options->stdout_flag == true)
  {
    event_log_error (hashcat_ctx, "Use of -m/--hash-type is not supported with --stdout.");

    return -1;
  }

  /**
   * status progress init; needs hashes that's why we have to do it here and separate from status_ctx_init
   */

  if (status_progress_init (hashcat_ctx) == -1) return -1;

  /**
   * main screen
   */

  EVENT (EVENT_OUTERLOOP_MAINSCREEN);

  /**
   * Tell user about cracked hashes by potfile
   */

  EVENT (EVENT_POTFILE_NUM_CRACKED);

  /**
   * setup salts for bridges, needs to be after bridge init, but before session start
   */

  EVENT (EVENT_BRIDGES_SALT_PRE);

  if (bridges_salt_prepare (hashcat_ctx) == false)
  {
    event_log_error (hashcat_ctx, "Bridge salt preparation for hash-mode '%u' failed.", user_options->hash_mode);

    return -1;
  }

  EVENT (EVENT_BRIDGES_SALT_POST);

  /**
   * inform the user
   */

  EVENT (EVENT_BACKEND_SESSION_PRE);

  if (backend_session_begin (hashcat_ctx) == -1)
  {
    if (user_options->benchmark == true)
    {
      if (user_options->hash_mode_chgd == false)
      {
        // finalize backend session

        backend_session_destroy (hashcat_ctx);

        // clean up

        #ifdef WITH_BRAIN
        brain_ctx_destroy       (hashcat_ctx);
        #endif

        bridges_salt_destroy    (hashcat_ctx);
        bridges_destroy         (hashcat_ctx);
        bitmap_ctx_destroy      (hashcat_ctx);
        combinator_ctx_destroy  (hashcat_ctx);
        cpt_ctx_destroy         (hashcat_ctx);
        hashconfig_destroy      (hashcat_ctx);
        hashes_destroy          (hashcat_ctx);
        mask_ctx_destroy        (hashcat_ctx);
        status_progress_destroy (hashcat_ctx);
        generic_ctx_destroy     (hashcat_ctx);
        straight_ctx_destroy    (hashcat_ctx);

        return 0;
      }
    }

    backend_session_destroy (hashcat_ctx);

    return -1;
  }

  EVENT (EVENT_BACKEND_SESSION_POST);

  /**
   * create self-test threads
   */

  if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
  {
    EVENT (EVENT_SELFTEST_STARTING);

    thread_param_t *threads_param = (thread_param_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (thread_param_t));

    hc_thread_t *selftest_threads = (hc_thread_t *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (hc_thread_t));

    int selftest_threads_live = 0;

    status_ctx->devices_status = STATUS_SELFTEST;

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      thread_param_t *thread_param = threads_param + backend_devices_idx;

      thread_param->hashcat_ctx = hashcat_ctx;
      thread_param->tid         = backend_devices_idx;

      if (hc_thread_create_ok (selftest_threads[selftest_threads_live], thread_selftest, thread_param) == true)
      {
        selftest_threads_live++;
      }
      else
      {
        thread_selftest (thread_param);
      }
    }

    hc_thread_wait (selftest_threads_live, selftest_threads);

    hcfree (threads_param);

    hcfree (selftest_threads);

    // check for any selftest failures

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      if (backend_ctx->enabled == false) continue;

      hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      if (device_param->skipped == true) continue;

      if (device_param->st_status == ST_STATUS_FAILED)
      {
        event_log_error (hashcat_ctx, "Aborting session due to kernel self-test failure.");

        event_log_warning (hashcat_ctx, "You can use --self-test-disable to override, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        backend_ctx->self_test_warnings = true;

        return -1;
      }
    }

    status_ctx->devices_status = STATUS_INIT;

    EVENT (EVENT_SELFTEST_FINISHED);
  }

  /**
   * (old) weak hash check is the first to write to potfile, so open it for writing from here
   * the weak hash check was removed maybe we can move this more to the bottom now
   */

  if (potfile_write_open (hashcat_ctx) == -1) return -1;

  /**
   * status and monitor threads
   */

  int inner_threads_cnt = 0;

  hc_thread_t *inner_threads = (hc_thread_t *) hccalloc (10, sizeof (hc_thread_t));

  status_ctx->shutdown_inner = false;

  /**
    * Outfile remove
    */

  if (user_options->keyspace == false && user_options->stdout_flag == false && user_options->speed_only == false)
  {
    if (hc_thread_create_ok (inner_threads[inner_threads_cnt], thread_monitor, hashcat_ctx) == true)
    {
      inner_threads_cnt++;
    }
    else
    {
      event_log_error (hashcat_ctx, "Could not start the monitor thread.");

      return -1;
    }

    if (outcheck_ctx->enabled == true)
    {
      if (hc_thread_create_ok (inner_threads[inner_threads_cnt], thread_outfile_remove, hashcat_ctx) == true)
      {
        inner_threads_cnt++;
      }
      else
      {
        event_log_error (hashcat_ctx, "Could not start the outfile-check thread.");

        return -1;
      }
    }

    if (module_ctx->module_advice_notice != MODULE_DEFAULT && user_options->quiet == false)
    {
      char *t_module_advice_notice = (char *) module_ctx->module_advice_notice (hashconfig, hashcat_ctx->user_options, user_options_extra);
      const u64 module_kern_type = module_ctx->module_kern_type (hashconfig, hashcat_ctx->user_options, user_options_extra);
      event_log_advice(hashcat_ctx, "Module %" PRIu64 " advice notice: %s", module_kern_type, t_module_advice_notice);
      event_log_advice (hashcat_ctx, NULL);
    }
  }

  // main call

  if (restore_ctx->rd)
  {
    restore_data_t *rd = restore_ctx->rd;

    if (rd->masks_pos > 0)
    {
      mask_ctx->masks_pos = rd->masks_pos;

      rd->masks_pos = 0;
    }
  }

  EVENT (EVENT_INNERLOOP1_STARTING);

  // The queue of rounds starts here, so this is where how far into it the run has got starts at zero.

  status_ctx->words_walk_base = 0;
  status_ctx->words_walk_cnt  = 0;

  if (mask_ctx->masks_cnt)
  {
    for (u32 masks_pos = mask_ctx->masks_pos; masks_pos < mask_ctx->masks_cnt; masks_pos++)
    {
      mask_ctx->masks_pos = masks_pos;

      if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);

      if (status_ctx->run_main_level2 == false) break;
    }

    if (status_ctx->run_main_level2 == true)
    {
      if (mask_ctx->masks_pos + 1 == mask_ctx->masks_cnt) mask_ctx->masks_pos = 0;
    }
  }
  else
  {
    if (inner1_loop (hashcat_ctx) == -1) myabort (hashcat_ctx);
  }

  // --keyspace answers for the whole queue and the queue has now been walked, so this is the earliest
  // the answer exists. One number, whether the queue held one round or fifty, which is what lets
  // --skip and --limit address it.

  if (user_options->keyspace == true)
  {
    status_ctx->words_base = status_ctx->words_walk_base;
    status_ctx->words_cnt  = status_ctx->words_walk_cnt;

    EVENT (EVENT_CALCULATED_WORDS_BASE);
    EVENT (EVENT_CALCULATED_WORDS_CNT);
  }

  // --lookup borrows --keyspace to have every round sized, and answers here for the same reason
  // --keyspace does: the queue has been walked, so both the answer and the run it is a fraction of
  // exist. Nothing was attacked and no device was opened, exactly as for --keyspace.

  if (user_options->lookup != NULL)
  {
    // A queue in which every mask was passed over never reached the --keyspace short-circuit that
    // says a round ran, so STATUS_INIT survives and EVENT_OUTERLOOP_FINISHED turns it into
    // STATUS_ERROR. The question below is answered either way, and an answered question is not a
    // failure. Same reason, and same one line, as the block further up this file.

    if (status_ctx->devices_status == STATUS_INIT) status_ctx->devices_status = STATUS_RUNNING;

    // One of the two says nothing: each returns on the attack mode it is not for. Both are here
    // rather than behind a switch because that is where a third mode goes.

    mask_ctx_lookup_report     (hashcat_ctx);
    combi_ctx_lookup_report    (hashcat_ctx);
    straight_ctx_lookup_report (hashcat_ctx);
  }

  // wait for inner threads

  status_ctx->shutdown_inner = true;

  for (int thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &inner_threads[thread_idx]);
  }

  hcfree (inner_threads);

  EVENT (EVENT_INNERLOOP1_FINISHED);

  // finalize potfile

  potfile_write_close (hashcat_ctx);

  // finalize backend session

  backend_session_destroy (hashcat_ctx);

  // clean up

  #ifdef WITH_BRAIN
  brain_ctx_destroy       (hashcat_ctx);
  #endif

  bridges_salt_destroy    (hashcat_ctx);
  bridges_destroy         (hashcat_ctx);
  bitmap_ctx_destroy      (hashcat_ctx);
  combinator_ctx_destroy  (hashcat_ctx);
  cpt_ctx_destroy         (hashcat_ctx);
  hashconfig_destroy      (hashcat_ctx);
  hashes_destroy          (hashcat_ctx);
  mask_ctx_destroy        (hashcat_ctx);
  status_progress_destroy (hashcat_ctx);
  generic_ctx_destroy     (hashcat_ctx);
  straight_ctx_destroy    (hashcat_ctx);

  return 0;
}

static void event_stub (MAYBE_UNUSED const u32 id, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{

}

int hashcat_init (hashcat_ctx_t *hashcat_ctx, void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t))
{
  if (event == NULL)
  {
    hashcat_ctx->event = event_stub;
  }
  else
  {
    hashcat_ctx->event = event;
  }

  hashcat_ctx->bitmap_ctx         = (bitmap_ctx_t *)          hcmalloc (sizeof (bitmap_ctx_t));
  hashcat_ctx->brain_ctx          = (brain_ctx_t *)           hcmalloc (sizeof (brain_ctx_t));
  hashcat_ctx->bridge_ctx         = (bridge_ctx_t *)          hcmalloc (sizeof (bridge_ctx_t));
  hashcat_ctx->combinator_ctx     = (combinator_ctx_t *)      hcmalloc (sizeof (combinator_ctx_t));
  hashcat_ctx->cpt_ctx            = (cpt_ctx_t *)             hcmalloc (sizeof (cpt_ctx_t));
  hashcat_ctx->debugfile_ctx      = (debugfile_ctx_t *)       hcmalloc (sizeof (debugfile_ctx_t));
  hashcat_ctx->event_ctx          = (event_ctx_t *)           hcmalloc (sizeof (event_ctx_t));
  hashcat_ctx->folder_config      = (folder_config_t *)       hcmalloc (sizeof (folder_config_t));
  hashcat_ctx->generic_ctx        = (generic_ctx_t *)         hccalloc (GENERIC_ROLE_CNT, sizeof (generic_ctx_t));
  hashcat_ctx->hashcat_user       = (hashcat_user_t *)        hcmalloc (sizeof (hashcat_user_t));
  hashcat_ctx->hashconfig         = (hashconfig_t *)          hcmalloc (sizeof (hashconfig_t));
  hashcat_ctx->hashes             = (hashes_t *)              hcmalloc (sizeof (hashes_t));
  hashcat_ctx->hwmon_ctx          = (hwmon_ctx_t *)           hcmalloc (sizeof (hwmon_ctx_t));
  hashcat_ctx->induct_ctx         = (induct_ctx_t *)          hcmalloc (sizeof (induct_ctx_t));
  hashcat_ctx->logfile_ctx        = (logfile_ctx_t *)         hcmalloc (sizeof (logfile_ctx_t));
  hashcat_ctx->loopback_ctx       = (loopback_ctx_t *)        hcmalloc (sizeof (loopback_ctx_t));
  hashcat_ctx->mask_ctx           = (mask_ctx_t *)            hcmalloc (sizeof (mask_ctx_t));
  hashcat_ctx->module_ctx         = (module_ctx_t *)          hcmalloc (sizeof (module_ctx_t));
  hashcat_ctx->backend_ctx        = (backend_ctx_t *)         hcmalloc (sizeof (backend_ctx_t));
  hashcat_ctx->outcheck_ctx       = (outcheck_ctx_t *)        hcmalloc (sizeof (outcheck_ctx_t));
  hashcat_ctx->outfile_ctx        = (outfile_ctx_t *)         hcmalloc (sizeof (outfile_ctx_t));
  hashcat_ctx->pidfile_ctx        = (pidfile_ctx_t *)         hcmalloc (sizeof (pidfile_ctx_t));
  hashcat_ctx->pubkey_ctx         = (pubkey_ctx_t *)          hcmalloc (sizeof (pubkey_ctx_t));
  hashcat_ctx->potfile_ctx        = (potfile_ctx_t *)         hcmalloc (sizeof (potfile_ctx_t));
  hashcat_ctx->restore_ctx        = (restore_ctx_t *)         hcmalloc (sizeof (restore_ctx_t));
  hashcat_ctx->status_ctx         = (status_ctx_t *)          hcmalloc (sizeof (status_ctx_t));
  hashcat_ctx->straight_ctx       = (straight_ctx_t *)        hcmalloc (sizeof (straight_ctx_t));
  hashcat_ctx->tuning_db          = (tuning_db_t *)           hcmalloc (sizeof (tuning_db_t));
  hashcat_ctx->user_options_extra = (user_options_extra_t *)  hcmalloc (sizeof (user_options_extra_t));
  hashcat_ctx->user_options       = (user_options_t *)        hcmalloc (sizeof (user_options_t));

  // The event context is set up here rather than with the session, because the banner is printed
  // before a session exists and printing it takes the log mutex. A mutex that has only been zeroed
  // is a usable pthread mutex, so this reads as working on Linux, but it is not a usable Windows
  // CRITICAL_SECTION and entering one faults.

  if (event_ctx_init (hashcat_ctx) == -1) return -1;

  // The compression libraries are located here, while there is still one thread, and each one is
  // optional: a box without it runs everything that does not ask for that format. Whoever does ask
  // is the one told, and is told which file names were tried. iconv is located the same way and is
  // optional in the same sense: only --encoding-from and --encoding-to need it.

  hc_zlib_boot ();
  hc_lzma_boot ();
  hc_zstd_boot ();
  hc_iconv_boot ();

  return 0;
}

void hashcat_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hcfree (hashcat_ctx->bitmap_ctx);
  hcfree (hashcat_ctx->brain_ctx);
  hcfree (hashcat_ctx->bridge_ctx);
  hcfree (hashcat_ctx->combinator_ctx);
  hcfree (hashcat_ctx->cpt_ctx);
  hcfree (hashcat_ctx->debugfile_ctx);
  event_ctx_destroy (hashcat_ctx);

  hcfree (hashcat_ctx->event_ctx);
  hcfree (hashcat_ctx->folder_config);
  hcfree (hashcat_ctx->generic_ctx);
  hcfree (hashcat_ctx->hashcat_user);
  hcfree (hashcat_ctx->hashconfig);
  hcfree (hashcat_ctx->hashes);
  hcfree (hashcat_ctx->hwmon_ctx);
  hcfree (hashcat_ctx->induct_ctx);
  hcfree (hashcat_ctx->logfile_ctx);
  hcfree (hashcat_ctx->loopback_ctx);
  hcfree (hashcat_ctx->mask_ctx);
  hcfree (hashcat_ctx->module_ctx);
  hcfree (hashcat_ctx->backend_ctx);
  hcfree (hashcat_ctx->outcheck_ctx);
  hcfree (hashcat_ctx->outfile_ctx);
  hcfree (hashcat_ctx->pidfile_ctx);
  hcfree (hashcat_ctx->potfile_ctx);
  hcfree (hashcat_ctx->pubkey_ctx);
  hcfree (hashcat_ctx->restore_ctx);
  hcfree (hashcat_ctx->status_ctx);
  hcfree (hashcat_ctx->straight_ctx);
  hcfree (hashcat_ctx->tuning_db);
  hcfree (hashcat_ctx->user_options_extra);
  hcfree (hashcat_ctx->user_options);

  hc_zlib_shutdown ();
  hc_lzma_shutdown ();
  hc_zstd_shutdown ();
  hc_iconv_shutdown ();

  memset (hashcat_ctx, 0, sizeof (hashcat_ctx_t));
}

int hashcat_session_init (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, int argc, char **argv, const int comptime)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  /**
   * make it a bit more comfortable to use some of the special modes in hashcat
   */

  user_options_session_auto (hashcat_ctx);

  /**
   * event init (needed for logging so should be first)
   */


  /**
   * status init
   */

  if (status_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * folder
   */

  if (folder_config_init (hashcat_ctx, install_folder, shared_folder) == -1) return -1;

  /**
   * pidfile
   */

  if (pidfile_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * restore
   */

  if (restore_ctx_init (hashcat_ctx, argc, argv) == -1) return -1;

  // --restore has printed the command line the restore file holds and nothing else may run. Stopping
  // here rather than further down is the point: user_options_preprocess has not run, so nothing has
  // acted on a path that came out of the file and no output file or directory has been created.

  if (hashcat_ctx->restore_ctx->print_only == true) return 0;

  /**
   * process user input
   */

  user_options_preprocess (hashcat_ctx);

  user_options_extra_init (hashcat_ctx);

  user_options_postprocess (hashcat_ctx);

  /**
   * windows and sockets...
   */

  #ifdef WITH_BRAIN
  #if defined (_WIN)
  if (user_options->brain_client == true)
  {
    WSADATA wsaData;

    WORD wVersionRequested = MAKEWORD (2,2);

    if (WSAStartup (wVersionRequested, &wsaData) != NO_ERROR)
    {
      fprintf (stderr, "WSAStartup: %s\n", strerror (errno));

      return -1;
    }
  }
  #endif

  /**
   * brain
   */

  if (brain_ctx_init (hashcat_ctx) == -1) return -1;
  #endif

  /**
   * logfile
   */

  if (logfile_init (hashcat_ctx) == -1) return -1;

  /**
   * cpu affinity
   */

  if (set_cpu_affinity (hashcat_ctx) == -1) return -1;

  /**
   * prepare seeding for random number generator, required by logfile and rules generator
   */

  setup_seeding (user_options->rp_gen_seed_chgd, user_options->rp_gen_seed);

  /**
   * To help users a bit
   */

  setup_environment_variables (hashcat_ctx->folder_config, hashcat_ctx->user_options);

  setup_umask ();

  /**
   * tuning db
   */

  if (tuning_db_init (hashcat_ctx) == -1) return -1;

  /**
   * induction directory
   */

  if (induct_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * outfile-check directory
   */

  if (outcheck_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * public key encryption of recovered plains
   * done before any output path is set up so that a missing library or an unusable key
   * stops the run before it can produce a single unprotected result
   */

  if (pubkey_ctx_init (hashcat_ctx) == -1) return -1;

  /**
   * outfile itself
   */

  if (outfile_init (hashcat_ctx) == -1) return -1;

  /**
   * potfile init
   * this is only setting path because potfile can be used in read and write mode depending on user options
   * plus it depends on hash_mode, so we continue using it in outer_loop
   */

  if (potfile_init (hashcat_ctx) == -1) return -1;

  /**
   * loopback init
   */

  if (loopback_init (hashcat_ctx) == -1) return -1;

  /**
   * debugfile init
   */

  if (debugfile_init (hashcat_ctx) == -1) return -1;

  /**
   * Try to detect if all the files we're going to use are accessible in the mode we want them
   */

  if (user_options_check_files (hashcat_ctx) == -1) return -1;

  /**
   * Load bridge a bit too early actually, but we need to know the unit count so we can automatically configure virtualization for the user
   */

  EVENT (EVENT_BRIDGES_INIT_PRE);

  if (bridges_init (hashcat_ctx) == false)
  {
    event_log_error (hashcat_ctx, "Bridge initialization for hash-mode '%u' failed.", user_options->hash_mode);

    return -1;
  }

  EVENT (EVENT_BRIDGES_INIT_POST);

  /**
   * Init backend library loader
   */

  EVENT (EVENT_BACKEND_RUNTIMES_INIT_PRE);

  if (backend_ctx_init (hashcat_ctx) == -1) return -1;

  EVENT (EVENT_BACKEND_RUNTIMES_INIT_POST);

  /**
   * Init backend devices
   */

  EVENT (EVENT_BACKEND_DEVICES_INIT_PRE);

  if (backend_ctx_devices_init (hashcat_ctx, comptime) == -1) return -1;

  EVENT (EVENT_BACKEND_DEVICES_INIT_POST);

  /**
   * HM devices: init
   */

  if (hwmon_ctx_init (hashcat_ctx) == -1) return -1;

  // done

  return 0;
}

bool autodetect_hashmode_test (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t              *hashes             = hashcat_ctx->hashes;
  module_ctx_t          *module_ctx         = hashcat_ctx->module_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  // check for file or hash on command line
  // if file, find out if binary file

  if (hashconfig->opts_type & OPTS_TYPE_AUTODETECT_DISABLE) return false;

  if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
  {
    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
    {
      hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

      if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
      {
        hashes->hashfile = user_options_extra->hc_hash;
      }
    }
    else
    {
      hashes->hashlist_mode = HL_MODE_FILE_BINARY;

      if (hc_path_read (user_options_extra->hc_hash) == false) return false;

      hashes->hashfile = user_options_extra->hc_hash;
    }
  }
  else
  {
    hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

    if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      hashes->hashfile = user_options_extra->hc_hash;
    }
  }

  /**
   * load hashes, part I: find input mode
   */

  const char *hashfile      = hashes->hashfile;
  const u32   hashlist_mode = hashes->hashlist_mode;

  u32 hashlist_format = HLFMT_HASHCAT;

  if (hashlist_mode == HL_MODE_FILE_PLAIN)
  {
    HCFILE fp;

    if (hc_fopen (&fp, hashfile, "rb") == false) return false;

    hashlist_format = hlfmt_detect (hashcat_ctx, &fp, 100);

    hc_fclose (&fp);
  }

  hashes->hashlist_format = hashlist_format;

  /**
   * load hashes, part II: allocate required memory, set pointers
   */

  void   *digest    =            hccalloc (1, hashconfig->dgst_size);
  salt_t *salt      = (salt_t *) hccalloc (1, sizeof (salt_t));
  void   *esalt     = NULL;
  void   *hook_salt = NULL;

  if (hashconfig->esalt_size > 0)
  {
    esalt = hccalloc (1, hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hook_salt = hccalloc (1, hashconfig->hook_salt_size);
  }

  hashinfo_t *hash_info = (hashinfo_t *) hcmalloc (sizeof (hashinfo_t));

  hash_info->dynamicx = (dynamicx_t *) hcmalloc (sizeof (dynamicx_t));
  hash_info->user = (user_t *) hcmalloc (sizeof (user_t));
  hash_info->orighash = (char *) hcmalloc (256);
  hash_info->split = (split_t *) hcmalloc (sizeof (split_t));

  // this is required for multi hash iterations in binary files, for instance used in -m 14600
  #define HASHES_IN_BINARY 10

  hash_t *hashes_buf = (hash_t *) hccalloc (HASHES_IN_BINARY, sizeof (hash_t));

  for (int i = 0; i < HASHES_IN_BINARY; i++)
  {
    hashes_buf[i].digest    = digest;
    hashes_buf[i].salt      = salt;
    hashes_buf[i].esalt     = esalt;
    hashes_buf[i].hook_salt = hook_salt;
  }

  hashes->hashes_buf     = hashes_buf;
  hashes->digests_buf    = digest;
  hashes->salts_buf      = salt;
  hashes->esalts_buf     = esalt;
  hashes->hook_salts_buf = hook_salt;

  bool success = false;

  if (hashlist_mode == HL_MODE_ARG)
  {
    char *input_buf = user_options_extra->hc_hash;

    if (!input_buf) return false;

    size_t input_len = strlen (input_buf);

    char  *hash_buf = NULL;
    int    hash_len = 0;

    hlfmt_hash (hashcat_ctx, hashlist_format, input_buf, input_len, &hash_buf, &hash_len);

    bool hash_fmt_error = false;

    if (hash_len < 1)     hash_fmt_error = true;
    if (hash_buf == NULL) hash_fmt_error = true;

    if (hash_fmt_error) return false;

    const int parser_status = module_ctx->module_hash_decode (hashconfig, digest, salt, esalt, hook_salt, hash_info, hash_buf, hash_len);

    if (parser_status == PARSER_OK) success = true;
  }
  else if (hashlist_mode == HL_MODE_FILE_PLAIN)
  {
    HCFILE fp;

    int error_count = 0;

    if (hc_fopen (&fp, hashfile, "rb") == false) return false;

    char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

    while (!hc_feof (&fp))
    {
      const size_t line_len = fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

      if (line_len == 0) continue;

      char *hash_buf = NULL;
      int   hash_len = 0;

      hlfmt_hash (hashcat_ctx, hashlist_format, line_buf, line_len, &hash_buf, &hash_len);

      bool hash_fmt_error = false;

      if (hash_len < 1)     hash_fmt_error = true;
      if (hash_buf == NULL) hash_fmt_error = true;

      if (hash_fmt_error) continue;

      int parser_status = module_ctx->module_hash_decode (hashconfig, digest, salt, esalt, hook_salt, hash_info, hash_buf, hash_len);

      if (parser_status == PARSER_OK)
      {
        success = true;

        break;
      }

      // abort this list after 100 errors

      if (error_count == 100)
      {
        break;
      }
      else
      {
        error_count++;
      }
    }

    hcfree (line_buf);

    hc_fclose (&fp);
  }
  else if (hashlist_mode == HL_MODE_FILE_BINARY)
  {
    char *input_buf = user_options_extra->hc_hash;

    size_t input_len = strlen (input_buf);

    if (module_ctx->module_hash_binary_parse != MODULE_DEFAULT)
    {
      const int hashes_parsed = module_ctx->module_hash_binary_parse (hashconfig, user_options, user_options_extra, hashes);

      if (hashes_parsed > 0) success = true;
    }
    else
    {
      const int parser_status = module_ctx->module_hash_decode (hashconfig, digest, salt, esalt, hook_salt, hash_info, input_buf, input_len);

      if (parser_status == PARSER_OK) success = true;
    }
  }

  hcfree (digest);
  hcfree (salt);
  hcfree (hash_info);
  hcfree (hashes_buf);

  if (hashconfig->esalt_size > 0)
  {
    hcfree (esalt);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hcfree (hook_salt);
  }

  hashes->digests_buf    = NULL;
  hashes->salts_buf      = NULL;
  hashes->esalts_buf     = NULL;
  hashes->hook_salts_buf = NULL;

  return success;
}

int autodetect_hashmodes (hashcat_ctx_t *hashcat_ctx, usage_sort_t *usage_sort_buf)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  int usage_sort_cnt = 0;

  // save quiet state so we can restore later

  EVENT (EVENT_AUTODETECT_STARTING);

  const bool quiet_sav = user_options->quiet;

  user_options->quiet = true;

  char *modulefile = (char *) hcmalloc (HCBUFSIZ_TINY);

  if (modulefile == NULL) return -1;

  // brute force all the modes

  for (int i = 0; i < MODULE_HASH_MODES_MAXIMUM; i++)
  {
    user_options->hash_mode = i;

    // this is just to find out of that hash-mode exists or not

    module_filename (folder_config, i, modulefile, HCBUFSIZ_TINY);

    if (hc_path_exist (modulefile) == false) continue;

    // we know it exists, so load the plugin

    const int hashconfig_init_rc = hashconfig_init (hashcat_ctx);

    if (hashconfig_init_rc == 0)
    {
      const bool test_rc = autodetect_hashmode_test (hashcat_ctx);

      if (test_rc == true)
      {
        usage_sort_buf[usage_sort_cnt].hash_mode     = hashcat_ctx->hashconfig->hash_mode;
        usage_sort_buf[usage_sort_cnt].hash_name     = hcstrdup (hashcat_ctx->hashconfig->hash_name);
        usage_sort_buf[usage_sort_cnt].hash_category = hashcat_ctx->hashconfig->hash_category;

        usage_sort_cnt++;
      }
    }

    // clean up

    hashconfig_destroy (hashcat_ctx);
  }

  hcfree (modulefile);

  qsort (usage_sort_buf, usage_sort_cnt, sizeof (usage_sort_t), sort_by_usage);

  user_options->quiet = quiet_sav;

  EVENT (EVENT_AUTODETECT_FINISHED);

  return usage_sort_cnt;
}

int hashcat_session_execute (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  logfile_ctx_t   *logfile_ctx   = hashcat_ctx->logfile_ctx;
  status_ctx_t    *status_ctx    = hashcat_ctx->status_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;
  backend_ctx_t   *backend_ctx   = hashcat_ctx->backend_ctx;

  // start logfile entry

  const time_t proc_start = time (NULL);

  logfile_generate_topid (hashcat_ctx);

  logfile_top_msg ("START");

  // capture current working directory in session log
  // https://github.com/hashcat/hashcat/issues/2453

  logfile_top_string (folder_config->cwd);
  logfile_top_string (folder_config->install_dir);
  logfile_top_string (folder_config->profile_dir);
  logfile_top_string (folder_config->session_dir);
  logfile_top_string (folder_config->shared_dir);

  // add all user options to logfile in case we want to debug some user session

  user_options_logger (hashcat_ctx);

  // read dictionary cache


  // --dynamic-x: the number in the tag picks the hash-mode, and it does so before autodetect,
  // because autodetect cannot tell md5($p.$s) from md5($s.$p) by looking at a hash and the tag can

  if ((user_options->dynamic_x == true) && (user_options->identify == false))
  {
    if (dynamicx_session_hash_mode (hashcat_ctx) == -1) return -1;
  }

  // autodetect

  if (user_options->autodetect == true)
  {
    status_ctx->devices_status = STATUS_AUTODETECT;

    usage_sort_t *usage_sort_buf = (usage_sort_t *) hccalloc (MODULE_HASH_MODES_MAXIMUM, sizeof (usage_sort_t));

    if (usage_sort_buf == NULL) return -1;

    const int modes_cnt = autodetect_hashmodes (hashcat_ctx, usage_sort_buf);

    if (modes_cnt <= 0)
    {
      if (user_options->show == false)
      {
        event_log_error (hashcat_ctx, "No hash-mode matches the structure of the input hash.");

        // John writes the format into the line and autodetect does not read it, so a hash that
        // came from John lands here with nothing to go on

        if (dynamicx_first_number (hashcat_ctx) >= 0)
        {
          event_log_warning (hashcat_ctx, NULL);
          event_log_warning (hashcat_ctx, "This hash is in John's $dynamic_N$ format. Add --dynamic-x to load it.");
          event_log_warning (hashcat_ctx, NULL);
        }
      }

      return -1;
    }

    if (modes_cnt > 1)
    {
      if (user_options->machine_readable == false)
      {
        event_log_info (hashcat_ctx, "The following %d hash-modes match the structure of your input hash:", modes_cnt);
        event_log_info (hashcat_ctx, NULL);
        event_log_info (hashcat_ctx, "      # | Name                                                       | Category");
        event_log_info (hashcat_ctx, "  ======+============================================================+======================================");
      }

      for (int i = 0; i < modes_cnt; i++)
      {
        if (user_options->machine_readable == false)
        {
          event_log_info (hashcat_ctx, "%7u | %-58s | %s", usage_sort_buf[i].hash_mode, usage_sort_buf[i].hash_name, strhashcategory (usage_sort_buf[i].hash_category));
        }
        else
        {
          event_log_info (hashcat_ctx, "%u", usage_sort_buf[i].hash_mode);
        }

        hcfree (usage_sort_buf[i].hash_name);
      }

      hcfree (usage_sort_buf);

      if (user_options->machine_readable == false) event_log_info (hashcat_ctx, NULL);

      if (user_options->identify == false)
      {
        event_log_error (hashcat_ctx, "Please specify the hash-mode with -m [hash-mode].");

        return -1;
      }

      return 0;
    }

    // modes_cnt == 1

    if (user_options->identify == false)
    {
      event_log_warning (hashcat_ctx, "Hash-mode was not specified with -m. Attempting to auto-detect hash mode.");
      event_log_warning (hashcat_ctx, "The following mode was auto-detected as the only one matching your input hash:");
    }

    if (user_options->identify == true)
    {
      if (user_options->machine_readable == true)
      {
        event_log_info (hashcat_ctx, "%u", usage_sort_buf[0].hash_mode);
      }
      else
      {
        event_log_info (hashcat_ctx, "The following hash-mode match the structure of your input hash:");
        event_log_info (hashcat_ctx, NULL);
        event_log_info (hashcat_ctx, "      # | Name                                                       | Category");
        event_log_info (hashcat_ctx, "  ======+============================================================+======================================");
        event_log_info (hashcat_ctx, "%7u | %-58s | %s", usage_sort_buf[0].hash_mode, usage_sort_buf[0].hash_name, strhashcategory (usage_sort_buf[0].hash_category));
        event_log_info (hashcat_ctx, NULL);
      }
    }
    else
    {
      event_log_info (hashcat_ctx, "\n%u | %s | %s\n", usage_sort_buf[0].hash_mode, usage_sort_buf[0].hash_name, strhashcategory (usage_sort_buf[0].hash_category));
    }

    if (user_options->identify == false)
    {
      event_log_warning (hashcat_ctx, "NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!");
      event_log_warning (hashcat_ctx, "Do NOT report auto-detect issues unless you are certain of the hash type.");
      event_log_warning (hashcat_ctx, NULL);
    }

    user_options->hash_mode = usage_sort_buf[0].hash_mode;

    hcfree (usage_sort_buf[0].hash_name);
    hcfree (usage_sort_buf);

    if (user_options->identify == true) return 0;

    user_options->autodetect = false;
  }

  /**
   * outer loop
   */

  EVENT (EVENT_OUTERLOOP_STARTING);

  int rc_final = -1;

  if (user_options->benchmark == true)
  {
    const bool quiet_sav = user_options->quiet;

    user_options->quiet = true;

    if (user_options->hash_mode_chgd == true)
    {
      rc_final = outer_loop (hashcat_ctx, 0);

      if (rc_final == -1) myabort (hashcat_ctx);
    }
    else
    {
      int iteration = 0;

      int hash_mode = 0;

      while ((hash_mode = benchmark_next (hashcat_ctx)) != -1)
      {
        if ((u32) hash_mode < user_options->benchmark_min) continue;
        if ((u32) hash_mode > user_options->benchmark_max) continue;

        user_options->hash_mode = hash_mode;

        rc_final = outer_loop (hashcat_ctx, iteration++);

        if (rc_final == -1) myabort (hashcat_ctx);

        if (status_ctx->run_main_level1 == false) break;
      }
    }

    user_options->quiet = quiet_sav;
  }
  else
  {
    const bool quiet_sav = user_options->quiet;

    if (user_options->speed_only == true) user_options->quiet = true;

    rc_final = outer_loop (hashcat_ctx, 0);

    if (rc_final == -1) myabort (hashcat_ctx);

    if (user_options->speed_only == true) user_options->quiet = quiet_sav;
  }

  EVENT (EVENT_OUTERLOOP_FINISHED);

  // if exhausted or cracked, unlink the restore file

  unlink_restore (hashcat_ctx);

  // final update dictionary cache


  // final logfile entry

  const time_t proc_stop = time (NULL);

  logfile_top_uint (proc_start);
  logfile_top_uint (proc_stop);

  logfile_top_msg ("STOP");

  // set final status code

  if (rc_final == 0)
  {
    if (status_ctx->devices_status == STATUS_ABORTED_FINISH)      rc_final = RC_FINAL_ABORT_FINISH;
    if (status_ctx->devices_status == STATUS_ABORTED_RUNTIME)     rc_final = RC_FINAL_ABORT_RUNTIME;
    if (status_ctx->devices_status == STATUS_ABORTED_CHECKPOINT)  rc_final = RC_FINAL_ABORT_CHECKPOINT;
    if (status_ctx->devices_status == STATUS_ABORTED)             rc_final = RC_FINAL_ABORT;
    if (status_ctx->devices_status == STATUS_QUIT)                rc_final = RC_FINAL_ABORT;
    if (status_ctx->devices_status == STATUS_EXHAUSTED)           rc_final = RC_FINAL_EXHAUSTED;
    if (status_ctx->devices_status == STATUS_CRACKED)             rc_final = RC_FINAL_OK;
    if (status_ctx->devices_status == STATUS_ERROR)               rc_final = RC_FINAL_ERROR;
  }
  else if (rc_final == -1)
  {
    // set up the new negative status code, useful in test.sh
    // -2 is marked as used in status_codes.txt
    if (backend_ctx->runtime_skip_warning  == true)               rc_final = -3;
    if (backend_ctx->memory_hit_warning    == true)               rc_final = -4;
    if (backend_ctx->kernel_build_warning  == true)               rc_final = -5;
    if (backend_ctx->kernel_create_warning == true)               rc_final = -6;
    if (backend_ctx->kernel_accel_warnings == true)               rc_final = -7;
    if (backend_ctx->extra_size_warning    == true)               rc_final = -8;
    if (backend_ctx->mixed_warnings        == true)               rc_final = -9;
    if (backend_ctx->self_test_warnings    == true)               rc_final = -11;
  }

  // special case for --stdout

  if (user_options->stdout_flag == true)
  {
    if (status_ctx->devices_status == STATUS_EXHAUSTED)
    {
      rc_final = 0;
    }
  }

  // done

  return rc_final;
}

int hashcat_session_pause (hashcat_ctx_t *hashcat_ctx)
{
  return SuspendThreads (hashcat_ctx);
}

int hashcat_session_resume (hashcat_ctx_t *hashcat_ctx)
{
  return ResumeThreads (hashcat_ctx);
}

int hashcat_session_bypass (hashcat_ctx_t *hashcat_ctx)
{
  return bypass (hashcat_ctx);
}

int hashcat_session_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  return stop_at_checkpoint (hashcat_ctx);
}

int hashcat_session_finish (hashcat_ctx_t *hashcat_ctx)
{
  return finish_after_attack (hashcat_ctx);
}

int hashcat_session_quit (hashcat_ctx_t *hashcat_ctx)
{
  return myabort (hashcat_ctx);
}

int hashcat_session_destroy (hashcat_ctx_t *hashcat_ctx)
{
  #ifdef WITH_BRAIN
  #if defined (_WIN)
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->brain_client == true)
  {
    WSACleanup ();
  }
  #endif
  #endif

  debugfile_destroy           (hashcat_ctx);
  folder_config_destroy       (hashcat_ctx);
  hwmon_ctx_destroy           (hashcat_ctx);
  induct_ctx_destroy          (hashcat_ctx);
  logfile_destroy             (hashcat_ctx);
  loopback_destroy            (hashcat_ctx);
  backend_ctx_devices_destroy (hashcat_ctx);
  backend_ctx_destroy         (hashcat_ctx);
  outcheck_ctx_destroy        (hashcat_ctx);
  outfile_destroy             (hashcat_ctx);
  pidfile_ctx_destroy         (hashcat_ctx);
  potfile_destroy             (hashcat_ctx);
  pubkey_ctx_destroy          (hashcat_ctx);
  restore_ctx_destroy         (hashcat_ctx);
  tuning_db_destroy           (hashcat_ctx);
  user_options_destroy        (hashcat_ctx);
  user_options_extra_destroy  (hashcat_ctx);
  status_ctx_destroy          (hashcat_ctx);

  return 0;
}

char *hashcat_get_log (hashcat_ctx_t *hashcat_ctx)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  return event_ctx->msg_buf;
}

int hashcat_get_status (hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  memset (hashcat_status, 0, sizeof (hashcat_status_t));

  if (status_ctx == NULL) return -1; // way too early

  if (status_ctx->accessible == false)
  {
    if (status_ctx->hashcat_status_final->msec_running > 0)
    {
      memcpy (hashcat_status, status_ctx->hashcat_status_final, sizeof (hashcat_status_t));

      return 0;
    }

    return -1; // still too early
  }

  hashcat_status->digests_cnt                 = status_get_digests_cnt                (hashcat_ctx);
  hashcat_status->digests_done                = status_get_digests_done               (hashcat_ctx);
  hashcat_status->digests_done_pot            = status_get_digests_done_pot           (hashcat_ctx);
  hashcat_status->digests_done_zero           = status_get_digests_done_zero          (hashcat_ctx);
  hashcat_status->digests_done_new            = status_get_digests_done_new           (hashcat_ctx);
  hashcat_status->digests_percent             = status_get_digests_percent            (hashcat_ctx);
  hashcat_status->digests_percent_new         = status_get_digests_percent_new        (hashcat_ctx);
  hashcat_status->hash_target                 = status_get_hash_target                (hashcat_ctx);
  hashcat_status->hash_name                   = status_get_hash_name                  (hashcat_ctx);
  hashcat_status->guess_base                  = status_get_guess_base                 (hashcat_ctx);
  hashcat_status->guess_base_offset           = status_get_guess_base_offset          (hashcat_ctx);
  hashcat_status->guess_base_count            = status_get_guess_base_count           (hashcat_ctx);
  hashcat_status->guess_base_percent          = status_get_guess_base_percent         (hashcat_ctx);
  hashcat_status->guess_mod                   = status_get_guess_mod                  (hashcat_ctx);
  hashcat_status->guess_mod_q                 = status_get_guess_mod_q                (hashcat_ctx);
  hashcat_status->guess_mod_offset            = status_get_guess_mod_offset           (hashcat_ctx);
  hashcat_status->guess_mod_count             = status_get_guess_mod_count            (hashcat_ctx);
  hashcat_status->guess_mod_percent           = status_get_guess_mod_percent          (hashcat_ctx);
  hashcat_status->guess_charset               = status_get_guess_charset              (hashcat_ctx);
  hashcat_status->guess_mask_length           = status_get_guess_mask_length          (hashcat_ctx);
  hashcat_status->guess_mode                  = status_get_guess_mode                 (hashcat_ctx);
  hashcat_status->msec_paused                 = status_get_msec_paused                (hashcat_ctx);
  hashcat_status->msec_running                = status_get_msec_running               (hashcat_ctx);
  hashcat_status->msec_real                   = status_get_msec_real                  (hashcat_ctx);
  hashcat_status->progress_mode               = status_get_progress_mode              (hashcat_ctx);
  hashcat_status->progress_finished_percent   = status_get_progress_finished_percent  (hashcat_ctx);
  hashcat_status->progress_cur_relative_skip  = status_get_progress_cur_relative_skip (hashcat_ctx);
  hashcat_status->progress_cur                = status_get_progress_cur               (hashcat_ctx);
  hashcat_status->progress_done               = status_get_progress_done              (hashcat_ctx);
  hashcat_status->progress_end_relative_skip  = status_get_progress_end_relative_skip (hashcat_ctx);
  hashcat_status->progress_end                = status_get_progress_end               (hashcat_ctx);
  hashcat_status->progress_ignore             = status_get_progress_ignore            (hashcat_ctx);
  hashcat_status->progress_rejected           = status_get_progress_rejected          (hashcat_ctx);
  hashcat_status->progress_rejected_percent   = status_get_progress_rejected_percent  (hashcat_ctx);
  #ifdef WITH_BRAIN
  hashcat_status->brain_rejects_attacks       = status_get_brain_rejects_attacks      (hashcat_ctx);
  hashcat_status->brain_rejects_hashes        = status_get_brain_rejects_hashes       (hashcat_ctx);
  #endif
  hashcat_status->progress_restored           = status_get_progress_restored          (hashcat_ctx);
  hashcat_status->progress_skip               = status_get_progress_skip              (hashcat_ctx);
  hashcat_status->restore_point               = status_get_restore_point              (hashcat_ctx);
  hashcat_status->restore_total               = status_get_restore_total              (hashcat_ctx);
  hashcat_status->restore_percent             = status_get_restore_percent            (hashcat_ctx);
  hashcat_status->salts_cnt                   = status_get_salts_cnt                  (hashcat_ctx);
  hashcat_status->salts_done                  = status_get_salts_done                 (hashcat_ctx);
  hashcat_status->salts_percent               = status_get_salts_percent              (hashcat_ctx);
  hashcat_status->session                     = status_get_session                    (hashcat_ctx);
  #ifdef WITH_BRAIN
  hashcat_status->brain_session               = status_get_brain_session              (hashcat_ctx);
  hashcat_status->brain_attack                = status_get_brain_attack               (hashcat_ctx);
  hashcat_status->brain_rx_all                = status_get_brain_rx_all               (hashcat_ctx);
  hashcat_status->brain_tx_all                = status_get_brain_tx_all               (hashcat_ctx);
  #endif
  hashcat_status->status_string               = status_get_status_string              (hashcat_ctx);
  hashcat_status->status_number               = status_get_status_number              (hashcat_ctx);
  hashcat_status->time_estimated_absolute     = status_get_time_estimated_absolute    (hashcat_ctx);
  hashcat_status->time_estimated_relative     = status_get_time_estimated_relative    (hashcat_ctx);
  hashcat_status->time_started_absolute       = status_get_time_started_absolute      (hashcat_ctx);
  hashcat_status->time_started_relative       = status_get_time_started_relative      (hashcat_ctx);
  hashcat_status->cpt_cur_min                 = status_get_cpt_cur_min                (hashcat_ctx);
  hashcat_status->cpt_cur_hour                = status_get_cpt_cur_hour               (hashcat_ctx);
  hashcat_status->cpt_cur_day                 = status_get_cpt_cur_day                (hashcat_ctx);
  hashcat_status->cpt_avg_min                 = status_get_cpt_avg_min                (hashcat_ctx);
  hashcat_status->cpt_avg_hour                = status_get_cpt_avg_hour               (hashcat_ctx);
  hashcat_status->cpt_avg_day                 = status_get_cpt_avg_day                (hashcat_ctx);
  hashcat_status->cpt                         = status_get_cpt                        (hashcat_ctx);

  // multiple devices

  hashcat_status->device_info_cnt    = status_get_device_info_cnt    (hashcat_ctx);
  hashcat_status->device_info_active = status_get_device_info_active (hashcat_ctx);
  hashcat_status->group_info_active  = status_get_group_info_active  (hashcat_ctx);

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    device_info->skipped_dev                    = status_get_skipped_dev                    (hashcat_ctx, device_id);
    device_info->skipped_warning_dev            = status_get_skipped_warning_dev            (hashcat_ctx, device_id);
    device_info->group_id_dev                   = status_get_group_id_dev                   (hashcat_ctx, device_id);
    device_info->group_size_dev                 = status_get_group_size_dev                 (hashcat_ctx, device_id);
    device_info->hashes_msec_dev                = status_get_hashes_msec_dev                (hashcat_ctx, device_id);
    device_info->hashes_msec_dev_benchmark      = status_get_hashes_msec_dev_benchmark      (hashcat_ctx, device_id);
    device_info->exec_msec_dev                  = status_get_exec_msec_dev                  (hashcat_ctx, device_id);
    device_info->speed_sec_dev                  = status_get_speed_sec_dev                  (hashcat_ctx, device_id);
    device_info->guess_candidates_dev           = status_get_guess_candidates_dev           (hashcat_ctx, device_id);
    #if defined (__APPLE__)
    device_info->hwmon_fan_dev                  = status_get_hwmon_fan_dev                  (hashcat_ctx);
    #endif
    device_info->hwmon_dev                      = status_get_hwmon_dev                      (hashcat_ctx, device_id);
    device_info->corespeed_dev                  = status_get_corespeed_dev                  (hashcat_ctx, device_id);
    device_info->memoryspeed_dev                = status_get_memoryspeed_dev                (hashcat_ctx, device_id);
    device_info->progress_dev                   = status_get_progress_dev                   (hashcat_ctx, device_id);
    device_info->runtime_msec_dev               = status_get_runtime_msec_dev               (hashcat_ctx, device_id);
    device_info->kernel_accel_dev               = status_get_kernel_accel_dev               (hashcat_ctx, device_id);
    device_info->kernel_loops_dev               = status_get_kernel_loops_dev               (hashcat_ctx, device_id);
    device_info->kernel_threads_dev             = status_get_kernel_threads_dev             (hashcat_ctx, device_id);
    device_info->vector_width_dev               = status_get_vector_width_dev               (hashcat_ctx, device_id);
    device_info->kernel_power_dev               = status_get_kernel_power_dev               (hashcat_ctx, device_id);
    device_info->salt_pos_dev                   = status_get_salt_pos_dev                   (hashcat_ctx, device_id);
    device_info->innerloop_pos_dev              = status_get_innerloop_pos_dev              (hashcat_ctx, device_id);
    device_info->innerloop_left_dev             = status_get_innerloop_left_dev             (hashcat_ctx, device_id);
    device_info->iteration_pos_dev              = status_get_iteration_pos_dev              (hashcat_ctx, device_id);
    device_info->iteration_left_dev             = status_get_iteration_left_dev             (hashcat_ctx, device_id);
    device_info->device_name                    = status_get_device_name                    (hashcat_ctx, device_id);
    device_info->device_type                    = status_get_device_type                    (hashcat_ctx, device_id);
    #ifdef WITH_BRAIN
    device_info->brain_link_client_id_dev       = status_get_brain_link_client_id_dev       (hashcat_ctx, device_id);
    device_info->brain_link_status_dev          = status_get_brain_link_status_dev          (hashcat_ctx, device_id);
    device_info->brain_link_recv_bytes_dev      = status_get_brain_link_recv_bytes_dev      (hashcat_ctx, device_id);
    device_info->brain_link_send_bytes_dev      = status_get_brain_link_send_bytes_dev      (hashcat_ctx, device_id);
    device_info->brain_link_recv_bytes_sec_dev  = status_get_brain_link_recv_bytes_sec_dev  (hashcat_ctx, device_id);
    device_info->brain_link_send_bytes_sec_dev  = status_get_brain_link_send_bytes_sec_dev  (hashcat_ctx, device_id);
    #endif
  }

  hashcat_status->hashes_msec_all = status_get_hashes_msec_all (hashcat_ctx);
  hashcat_status->exec_msec_all   = status_get_exec_msec_all   (hashcat_ctx);
  hashcat_status->speed_sec_all   = status_get_speed_sec_all   (hashcat_ctx);

  return 0;
}
