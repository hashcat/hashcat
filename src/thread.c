/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "timer.h"
#include "user_options.h"
#include "thread.h"

/*
#if defined (_WIN)

BOOL WINAPI sigHandler_default (DWORD sig)
{
  switch (sig)
  {
    case CTRL_CLOSE_EVENT:

       *
       * special case see: https://stackoverflow.com/questions/3640633/c-setconsolectrlhandler-routine-issue/5610042#5610042
       * if the user interacts w/ the user-interface (GUI/cmd), we need to do the finalization job within this signal handler
       * function otherwise it is too late (e.g. after returning from this function)
       *

      myabort (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort (hashcat_ctx->status_ctx);

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

      myquit (hashcat_ctx->status_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit (hashcat_ctx->status_ctx);

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
  myabort (hashcat_ctx->status_ctx);

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit (hashcat_ctx->status_ctx);

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
*/

int mycracked (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_CRACKED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_CHECKPOINT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_finish (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_FINISH;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort_runtime (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->devices_status = STATUS_ABORTED_RUNTIME;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myabort (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  //those checks create problems in benchmark mode, it's simply too short of a timeframe where it's running as STATUS_RUNNING
  // not sure if this is still valid, but abort is also called by gpu temp monitor
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_ABORTED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int myquit (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const bool running = ((status_ctx->devices_status == STATUS_RUNNING) || (status_ctx->devices_status == STATUS_PAUSED));

  // A session that has already failed still has to be quittable.
  //
  // A device thread that gives up sets STATUS_ERROR and returns, and every other device thread keeps
  // running, because nothing clears the run flags on that path. The guard here used to refuse any
  // status but the two above, so q cleared nothing and returned -1, and the caller does not look at
  // the return value. The session was then unquittable and only a signal ended it. What made this
  // reachable was a bridge losing its last board: the status line said Error and the remaining
  // devices carried on with a keyspace 29 days wide.
  //
  // The error status is kept rather than replaced with STATUS_QUIT, because the session really did
  // fail and the exit code has to keep saying so.

  const bool failed = (status_ctx->devices_status == STATUS_ERROR);

  if ((running == false) && (failed == false)) return -1;

  if (running == true) status_ctx->devices_status = STATUS_QUIT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

// Move the dispatcher to the first word of the next source the feed was given, and say whether there
// was one.
//
// Bypass means "skip the wordlist I am on". Several dictionaries used to be several attacks, so ending
// the attack was the same thing as moving to the next one. A feed lays them end to end into a single
// keyspace, so ending the attack there skips every remaining dictionary at once, which is not what the
// key means and is what a user reported. The offsets of the sources are already known, because the
// status display uses them to say which one the run has reached.
//
// The words in between are booked as rejected. Progress counts everything that has been decided, not
// only what was hashed, and without booking them the run can never reach its keyspace and never ends.
//
// Returns false when there is nothing to move to, and then the caller bypasses the way it always did.
// That covers a single source, the last source, and every attack mode not reading from a feed.

static bool bypass_to_next_source (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options_extra->base_source != BASE_SOURCE_FEED) return false;

  const generic_ctx_t *generic_ctx = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];

  if (generic_ctx->enabled == false) return false;

  const generic_global_ctx_t *global_ctx = &generic_ctx->global_ctx;

  if (global_ctx->segments_cnt < 2) return false;

  hashes_t     *hashes     = hashcat_ctx->hashes;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const u64 words_off = status_ctx->words_off;

  bool found = false;

  u64 next_first = 0;

  for (u64 i = 0; i < global_ctx->segments_cnt; i++)
  {
    if (global_ctx->segment_first[i] <= words_off) continue;

    next_first = global_ctx->segment_first[i];

    found = true;

    break;
  }

  if (found == false)
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return false;
  }

  const u64 skipped = next_first - words_off;

  status_ctx->words_off = next_first;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  const u64 amplifier = user_options_extra_amplifier (hashcat_ctx);

  hc_thread_mutex_lock (status_ctx->mux_counter);

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    status_ctx->words_progress_rejected[salt_pos] += skipped * amplifier;
  }

  hc_thread_mutex_unlock (status_ctx->mux_counter);

  return true;
}

int bypass (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (bypass_to_next_source (hashcat_ctx) == true) return 0;

  status_ctx->devices_status = STATUS_BYPASS;

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  status_ctx->checkpoint_shutdown = false;
  status_ctx->checkpoint_taken    = false;
  status_ctx->finish_shutdown     = false;

  return 0;
}

int SuspendThreads (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

  hc_timer_set (&status_ctx->timer_paused);

  status_ctx->devices_status = STATUS_PAUSED;

  return 0;
}

int ResumeThreads (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status != STATUS_PAUSED) return -1;

  const double msec_paused = hc_timer_get (status_ctx->timer_paused);

  status_ctx->msec_paused += msec_paused;

  status_ctx->devices_status = STATUS_RUNNING;

  return 0;
}

int stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // this feature only makes sense if --restore-disable was not specified

  restore_ctx_t *restore_ctx = hashcat_ctx->restore_ctx;

  if (restore_ctx->enabled == false)
  {
    event_log_warning (hashcat_ctx, "This feature is disabled when --restore-disable is specified.");

    return -1;
  }

  // Enable or Disable

  if (status_ctx->checkpoint_shutdown == false)
  {
    status_ctx->checkpoint_shutdown = true;

    status_ctx->run_main_level1   = false;
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = false;
    status_ctx->run_thread_level2 = true;
  }
  else
  {
    // A cancel is only a cancel while every device is still running. Once one has left its loop for
    // the checkpoint it cannot be restarted, and clearing the flags here would leave the run looking
    // like an ordinary exhausted round: the rest of the dictionary would never be dispatched and the
    // restore file would be deleted with it. Say so instead of pretending.

    if (status_ctx->checkpoint_taken == true)
    {
      event_log_warning (hashcat_ctx, "Checkpoint has already been reached on at least one device and cannot be cancelled.");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    status_ctx->checkpoint_shutdown = false;

    status_ctx->run_main_level1   = true;
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }

  return 0;
}

int finish_after_attack (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // Enable or Disable

  if (status_ctx->finish_shutdown == false)
  {
    status_ctx->finish_shutdown = true;

    status_ctx->run_main_level1   = false;
    status_ctx->run_main_level2   = false;
    status_ctx->run_main_level3   = false;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }
  else
  {
    status_ctx->finish_shutdown = false;

    status_ctx->run_main_level1   = true;
    status_ctx->run_main_level2   = true;
    status_ctx->run_main_level3   = true;
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }

  return 0;
}
