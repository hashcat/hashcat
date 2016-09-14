/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
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
#include "data.h"
#include "shared.h"

extern hc_global_data_t data;

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
