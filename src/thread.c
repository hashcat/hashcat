/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "timer.h"
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

  if (status_ctx->devices_status != STATUS_RUNNING && status_ctx->devices_status != STATUS_PAUSED) return -1;

  status_ctx->devices_status = STATUS_QUIT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  return 0;
}

int bypass (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

  status_ctx->devices_status = STATUS_BYPASS;

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  status_ctx->checkpoint_shutdown = false;
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

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

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

  if (status_ctx->devices_status != STATUS_RUNNING) return -1;

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
