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
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "thread.h"
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

extern hc_global_data_t data;

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

      myabort (data.opencl_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myabort (data.opencl_ctx);

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

      myquit (data.opencl_ctx);

      SetConsoleCtrlHandler (NULL, TRUE);

      hc_sleep (10);

      return TRUE;

    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:

      myquit (data.opencl_ctx);

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
  myabort (data.opencl_ctx);

  signal (sig, NULL);
}

void sigHandler_benchmark (int sig)
{
  myquit (data.opencl_ctx);

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

void mycracked (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_RUNNING) return;

  opencl_ctx->devices_status = STATUS_CRACKED;

  opencl_ctx->run_main_level1   = false;
  opencl_ctx->run_main_level2   = false;
  opencl_ctx->run_main_level3   = false;
  opencl_ctx->run_thread_level1 = false;
  opencl_ctx->run_thread_level2 = false;
}

void myabort (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_RUNNING) return;

  opencl_ctx->devices_status = STATUS_ABORTED;

  opencl_ctx->run_main_level1   = false;
  opencl_ctx->run_main_level2   = false;
  opencl_ctx->run_main_level3   = false;
  opencl_ctx->run_thread_level1 = false;
  opencl_ctx->run_thread_level2 = false;
}

void myquit (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_RUNNING) return;

  opencl_ctx->devices_status = STATUS_QUIT;

  opencl_ctx->run_main_level1   = false;
  opencl_ctx->run_main_level2   = false;
  opencl_ctx->run_main_level3   = false;
  opencl_ctx->run_thread_level1 = false;
  opencl_ctx->run_thread_level2 = false;
}

void bypass (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_RUNNING) return;

  opencl_ctx->devices_status = STATUS_BYPASS;

  opencl_ctx->run_main_level1   = true;
  opencl_ctx->run_main_level2   = true;
  opencl_ctx->run_main_level3   = true;
  opencl_ctx->run_thread_level1 = false;
  opencl_ctx->run_thread_level2 = false;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

void SuspendThreads (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_RUNNING) return;

  hc_timer_set (&data.timer_paused);

  opencl_ctx->devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

void ResumeThreads (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->devices_status != STATUS_PAUSED) return;

  double ms_paused;

  hc_timer_get (data.timer_paused, ms_paused);

  data.ms_paused += ms_paused;

  opencl_ctx->devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}
