/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "opencl.h"
#include "thread.h"
#include "rp_cpu.h"
#include "terminal.h"
#include "interface.h"
#include "hwmon.h"
#include "mpsp.h"
#include "restore.h"
#include "outfile.h"
#include "potfile.h"
#include "loopback.h"
#include "status.h"
#include "data.h"
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
