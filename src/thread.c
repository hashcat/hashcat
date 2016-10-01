/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "timer.h"
#include "shared.h"
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

      hc_sleep (10);

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

      hc_sleep (10);

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

void mycracked (status_ctx_t *status_ctx)
{
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_CRACKED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;
}

void myabort (status_ctx_t *status_ctx)
{
  //those checks create problems in benchmark mode, it's simply too short of a timeframe where it's running as STATUS_RUNNING
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_ABORTED;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;
}

void myquit (status_ctx_t *status_ctx)
{
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_QUIT;

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;
}

void bypass (status_ctx_t *status_ctx)
{
  //if (status_ctx->devices_status != STATUS_RUNNING) return;

  status_ctx->devices_status = STATUS_BYPASS;

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

void SuspendThreads (status_ctx_t *status_ctx)
{
  if (status_ctx->devices_status != STATUS_RUNNING) return;

  hc_timer_set (&status_ctx->timer_paused);

  status_ctx->devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

void ResumeThreads (status_ctx_t *status_ctx)
{
  if (status_ctx->devices_status != STATUS_PAUSED) return;

  double ms_paused = hc_timer_get (status_ctx->timer_paused);

  status_ctx->ms_paused += ms_paused;

  status_ctx->devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}
