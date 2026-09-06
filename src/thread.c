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

// A seek moves the position and rewrites the counters to what they say at that position. Neither is
// safe while a device thread runs. words_done is a per device high water mark that only ever rises,
// so lowering the restore point under a thread that is holding a batch is undone by the next batch
// that finishes. A seek therefore stops every device the way the bypass key does, and inner2_loop
// picks the run up again at the new position instead of ending the round.
//
// This is a contract with the user rather than a free move. Whatever the devices had in flight is
// dropped, and the progress the run had made is replaced by what the position means. It is the same
// bargain --restore already offers, where resuming a session does not recover the last few batches.

static void seek_arm (hashcat_ctx_t *hashcat_ctx, const u64 target)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // Under the dispatcher lock, because seek_apply () puts the run flags back up at the end of its own
  // work and a key pressed while it is part way through would otherwise have its request overwritten
  // and never applied.

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  status_ctx->seek_target  = target;
  status_ctx->seek_pending = true;

  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
}

// What the counters say at a position is closed form, so nothing has to be carried over the seek.
// Every base word before the position stands for one amplifier's worth of candidates, whether it was
// tried, rejected, or passed over by an earlier seek, and that is what --restore writes into these
// same three counters when a session resumes part way into a keyspace.
//
// The rejected counter goes back to zero with the other two rather than being adjusted. A word the
// run is no longer going to reach was never read, so it was never rejected, and a word before the
// position is already accounted for by the position. Rejects are also not uniform across salts:
// combs_buf_reject () books an amplifier line that filled no slot against the one salt it was read
// for, and a salt that is already cracked stops being counted at all. Writing all three counters from
// the position is what puts the salts back on the same footing.

void seek_apply (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hashes_t      *hashes      = hashcat_ctx->hashes;
  status_ctx_t  *status_ctx  = hashcat_ctx->status_ctx;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const u64 target = status_ctx->seek_target;

  status_ctx->seek_pending = false;

  status_ctx->words_off = target;
  status_ctx->words_cur = target;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    device_param->words_off        = target;
    device_param->words_done       = target;
    device_param->words_off_launch = target;

    // calc () ends a device by saving what autotune chose into the _prev fields and zeroing the live
    // ones, so that a device which has finished reports Accel:0 Loops:0 Thr:0 rather than the values
    // it is no longer using. It is written to run once for a round, and a seek runs it again.
    //
    // Handing the next launch a kernel_loops of zero does not fail, it hangs: choose_kernel () walks
    // the iteration space with loop_pos += kernel_loops, so a zero step never reaches the end and the
    // loop kernel is relaunched for ever on the same batch. The run stays alive at 0 H/s with its
    // progress frozen, which looks like a deadlock and is not one.

    device_param->kernel_accel   = device_param->kernel_accel_prev;
    device_param->kernel_loops   = device_param->kernel_loops_prev;
    device_param->kernel_threads = device_param->kernel_threads_prev;

    // The speed is the interval between launches, and run_copy () starts that clock only when it has
    // been zeroed. Left running it would measure the restart as if it were part of the first batch
    // after the seek, and report a speed for it that the device never ran at.

    #if defined (_WIN)
    device_param->timer_speed.QuadPart = 0;
    #else
    device_param->timer_speed.tv_sec = 0;
    #endif
  }

  // get_work () cuts the work slice down once the end of the keyspace is in sight, and remembers that
  // it has. A run that seeks back from near the end would otherwise keep handing out that small slice
  // for the rest of the attack.

  backend_ctx->kernel_power_final = 0;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  const u64 amplifier = user_options_extra_amplifier (hashcat_ctx);

  hc_thread_mutex_lock (status_ctx->mux_counter);

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    status_ctx->words_progress_done[salt_pos]     = 0;
    status_ctx->words_progress_rejected[salt_pos] = 0;
    status_ctx->words_progress_restored[salt_pos] = target * amplifier;
  }

  hc_thread_mutex_unlock (status_ctx->mux_counter);

  // Only put the run flags back up if nothing else asked the run to stop while this move was being
  // applied. A key pressed in that window armed another seek, and a quit, an abort or a crack lowered
  // the same flags to end the run: raising them again would undo either. Leaving them down costs one
  // generation of threads that end at once, and the next join does the right thing with them.

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  if ((status_ctx->seek_pending == false) && (status_ctx->devices_status == STATUS_RUNNING))
  {
    status_ctx->run_thread_level1 = true;
    status_ctx->run_thread_level2 = true;
  }

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
}

// Where this round stops. It is not words_base when --limit is given: get_work () stops at the smaller
// of the two and so does the progress end, so a seek bounded on words_base alone can put words_off
// past anywhere the dispatcher will reach, which ends the run as exhausted with the counters
// describing a keyspace that was never tried.

static u64 seek_end (const status_ctx_t *status_ctx)
{
  const u64 words_end = (status_ctx->words_limit == 0) ? status_ctx->words_base : MIN (status_ctx->words_limit, status_ctx->words_base);

  return words_end;
}

// Where the run has actually got to, which is what a step is measured from.
//
// words_cur and not words_off. words_off is the dispatcher's hand-out head: get_work () moves it the
// moment a producer claims a slice, and the producer runs whole batches ahead of the launcher, so the
// head leads the completed position by the work in flight. A seek books everything below its target
// as covered, so stepping from the head writes that in flight range into the restore point without
// having tried it. On a wordlist no larger than a couple of batches the head can sit near the end of
// the keyspace while nothing has finished, and one advance would then discard almost the whole
// attack. Whatever is in flight is dropped by the seek and walked again, which is the contract.
//
// A seek that has been asked for but not yet applied answers with its own target, so that pressing a
// key twice in a row moves twice rather than asking for the same move again.

u64 seek_position (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 position = (status_ctx->seek_pending == true) ? status_ctx->seek_target : status_ctx->words_cur;

  return position;
}

// A position as a percentage of the window the run walks, which is what the seek keys report. -s and
// -l narrow that window, and a seek moves inside it, so the percentage is of the window rather than
// of the whole keyspace.

double seek_percent (const hashcat_ctx_t *hashcat_ctx, const u64 words)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 words_end  = seek_end (status_ctx);
  const u64 words_skip = status_ctx->words_skip;

  if (words_end <= words_skip) return 0;
  if (words     <= words_skip) return 0;

  const double percent = ((double) (words - words_skip) / (double) (words_end - words_skip)) * 100;

  return percent;
}

// Move the run to a position, with every reason it cannot be done gathered in one place.
//
// A target beyond the keyspace is refused rather than clamped. Clamping would end the run and call
// it a seek, and a position past the end is a mistake worth telling the user about.

static int bypass_seek (hashcat_ctx_t *hashcat_ctx, const u64 target)
{
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // Candidates arriving on a pipe cannot be moved around in. There is no position to go back to,
  // and going forward would book words the stream is still going to deliver. The keypress thread is
  // not started for a stdin run today, so this cannot be reached, but the constraint belongs with
  // the seek rather than with the condition that decides whether keys are read at all.

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN) return -1;

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // A producer that cannot say how much keyspace it has leaves words_base derived from a count that
  // means "unknown", and a percentage of that is a position no run will ever reach.

  if (status_ctx->words_cnt == (u64) -1) return -1;

  // Asking to move the run is asking to run it, so a paused run is resumed rather than refused. That
  // is also what makes the move possible at all: a paused device thread is parked in a wait of its
  // own, and nothing short of the run coming back gets it out of there.

  if (status_ctx->devices_status == STATUS_PAUSED) ResumeThreads (hashcat_ctx);

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

  const u64 words_end = seek_end (status_ctx);

  // -s and -l narrow the range the run will ever walk, so they narrow where a seek may land as well.
  // words_off starts at words_skip rather than at zero, and get_work () stops at words_end, so a
  // target outside that window names a position the dispatcher is never going to reach.

  if (target <  status_ctx->words_skip) return -1;
  if (target >= words_end)              return -1;

  seek_arm (hashcat_ctx, target);

  return 0;
}

// The first press of a seek key moves this many base words.
//
// An absolute count rather than a fraction of the keyspace. An attack is ordered by how likely a
// candidate is to crack something, so what makes the front of one worth searching finely is an
// absolute number of candidates: the best few thousand words of a wordlist are the best few thousand
// whether the run is 14 million long or 240 billion. A step that scales with the keyspace is coarsest
// exactly where it needs to be finest.

#define SEEK_STEP_WORDS 5000

// On a window too small for that to be a nudge, the first press takes this fraction of it instead.
// The two together put the crossover at SEEK_STEP_WORDS times this, ten million base words, above
// which the absolute count is the smaller of the two and takes over.

#define SEEK_STEP_DIV 2000

// Every further press in the same direction multiplies the step, so a held key reaches the ceiling
// below in a handful of repeats while a single press stays a nudge. The ramp is what carries the
// ordering: a run whose value is all at the front is crossed by holding the key, and the presses that
// matter are the small ones near where the user stopped.

#define SEEK_STEP_GROW 2

// No single press moves more than this much of the window, however long the key is held.
//
// A held key repeats tens of times a second, so without a ceiling the ramp reaches the end of the
// keyspace almost as soon as the user leans on it, and every press near the top overshoots by a jump
// far larger than anything the user can aim with. This is the number that decides how long a hold
// takes to cross the window, which is 100 divided by it in presses, and letting go anywhere leaves
// the next press a nudge again.

#define SEEK_STEP_CAP_PCT 0.5

// A key that is being held down repeats. One that has not repeated within this long has been let go,
// and the next press starts the run over.
//
// A terminal reports no key release, so the release is the gap where the repeats stop. This sits well
// above a repeat interval, which is tens of milliseconds, and below the delay a keyboard waits before
// it starts repeating, which is about half a second. Holding a key therefore gives one nudge, a
// pause, and then the ramp.

#define SEEK_RELEASE_MS 400

// Move the run by one press of a seek key.
//
// The step accelerates while the key is held and starts over when it is let go or the direction
// changes. Changing direction starting over is the point of it: a user holds the key through ground
// that is not producing, overshoots, and then wants to come back in small steps to hunt.

int bypass_seek_step (hashcat_ctx_t *hashcat_ctx, const int direction)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  // -a 9 pairs one base word with one hash rather than running every word against every salt, so
  // words_progress_restored is indexed by hash there. The counters a seek writes are the per salt
  // ones and would describe something the attack is not doing.

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION) return -1;

  #ifdef WITH_BRAIN
  // A brain keeps its own record of what the session has already tried, and it rejects a word it has
  // seen. Going back over ground it remembers would find nothing, so the key would appear to work and
  // do nothing at all.

  if (user_options->brain_client == true) return -1;
  #endif

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 words_end  = seek_end (status_ctx);
  const u64 words_skip = status_ctx->words_skip;

  if (words_end <= words_skip) return -1;

  const u64 base = seek_position (hashcat_ctx);

  if (base < words_skip) return -1;

  const u64 span = words_end - words_skip;

  const double since = hc_timer_get (status_ctx->seek_timer);

  const bool held = ((status_ctx->seek_dir == direction) && (since < SEEK_RELEASE_MS));

  double step = 0;

  if (held == true)
  {
    step = status_ctx->seek_step * SEEK_STEP_GROW;
  }
  else
  {
    u64 first = span / SEEK_STEP_DIV;

    if (first == 0) first = 1;

    first = MIN (first, (u64) SEEK_STEP_WORDS);

    step = (double) first;
  }

  const double cap = ((double) span / 100) * SEEK_STEP_CAP_PCT;

  if (step > cap) step = cap;

  if (step < 1) step = 1;

  status_ctx->seek_step = step;
  status_ctx->seek_dir  = direction;

  hc_timer_set (&status_ctx->seek_timer);

  const u64 words = (u64) (step + 0.5);

  u64 target = 0;

  if (direction >= 0)
  {
    // The end of the window is not a position to sit at, it is where the round finishes, so an
    // advance stops on the last word of it rather than running off the end.

    if (base >= (words_end - 1)) return -1;

    target = base + words;

    if (target >= words_end) target = words_end - 1;
  }
  else
  {
    target = (base > (words_skip + words)) ? base - words : words_skip;
  }

  if (target == base) return -1;

  const int rc = bypass_seek (hashcat_ctx, target);

  return rc;
}

// Change how much time a --runtime deadline has left. The monitor reads this alongside the paused
// time it already folds in, so the deadline moves by exactly what was asked for and the user is
// told the new figure rather than having to watch the clock to find out.

int runtime_adjust (hashcat_ctx_t *hashcat_ctx, const int seconds)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->runtime == 0) return -1;

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->runtime_adjust_sec += seconds;

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

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const u64 words_off = status_ctx->words_off;

  u64 next_first = 0;

  bool found = false;

  for (u64 i = 0; i < global_ctx->segments_cnt; i++)
  {
    if (global_ctx->segment_first[i] <= words_off) continue;

    next_first = global_ctx->segment_first[i];

    found = true;

    break;
  }

  if (found == false) return false;

  // Through the seek, so that a source boundary the run is never going to reach is refused for the
  // same reasons any other position out of range is.

  const int rc = bypass_seek (hashcat_ctx, next_first);

  const bool moved = (rc == 0);

  return moved;
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
