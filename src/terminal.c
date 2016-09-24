/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "logging.h"
#include "interface.h"
#include "timer.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "status.h"
#include "shared.h"
#include "terminal.h"

extern hc_global_data_t data;

extern hc_thread_mutex_t mux_display;

const char *PROMPT = "[s]tatus [p]ause [r]esume [b]ypass [c]heckpoint [q]uit => ";

void send_prompt ()
{
  fprintf (stdout, "%s", PROMPT);

  fflush (stdout);
}

void clear_prompt ()
{
  fputc ('\r', stdout);

  for (size_t i = 0; i < strlen (PROMPT); i++)
  {
    fputc (' ', stdout);
  }

  fputc ('\r', stdout);

  fflush (stdout);
}

void *thread_keypress (void *p)
{
  opencl_ctx_t *opencl_ctx = data.opencl_ctx;

  while (opencl_ctx->devices_status == STATUS_INIT) hc_sleep_ms (100);

  restore_ctx_t        *restore_ctx        = data.restore_ctx;
  user_options_t       *user_options       = data.user_options;
  user_options_extra_t *user_options_extra = data.user_options_extra;
  hashconfig_t         *hashconfig         = data.hashconfig;
  hashes_t             *hashes             = data.hashes;
  rules_ctx_t          *rules_ctx          = data.rules_ctx;

  const bool quiet = user_options->quiet;

  tty_break ();

  while (data.shutdown_outer == 0)
  {
    int ch = tty_getchar ();

    if (ch == -1) break;

    if (ch ==  0) continue;

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_lock (mux_display);

    log_info ("");

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        log_info ("");

        status_display (opencl_ctx, hashconfig, hashes, restore_ctx, user_options, user_options_extra, rules_ctx);

        log_info ("");

        if (quiet == false) send_prompt ();

        break;

      case 'b':

        log_info ("");

        bypass (opencl_ctx);

        log_info ("");

        if (quiet == false) send_prompt ();

        break;

      case 'p':

        log_info ("");

        SuspendThreads (opencl_ctx);

        log_info ("");

        if (quiet == false) send_prompt ();

        break;

      case 'r':

        log_info ("");

        ResumeThreads (opencl_ctx);

        log_info ("");

        if (quiet == false) send_prompt ();

        break;

      case 'c':

        log_info ("");

        stop_at_checkpoint (restore_ctx, opencl_ctx);

        log_info ("");

        if (quiet == false) send_prompt ();

        break;

      case 'q':

        log_info ("");

        myabort (opencl_ctx);

        break;
    }

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_unlock (mux_display);
  }

  tty_fix ();

  return (p);
}

#if defined (_WIN)
void SetConsoleWindowSize (const int x)
{
  HANDLE h = GetStdHandle (STD_OUTPUT_HANDLE);

  if (h == INVALID_HANDLE_VALUE) return;

  CONSOLE_SCREEN_BUFFER_INFO bufferInfo;

  if (!GetConsoleScreenBufferInfo (h, &bufferInfo)) return;

  SMALL_RECT *sr = &bufferInfo.srWindow;

  sr->Right = MAX (sr->Right, x - 1);

  COORD co;

  co.X = sr->Right + 1;
  co.Y = 9999;

  if (!SetConsoleScreenBufferSize (h, co)) return;

  if (!SetConsoleWindowInfo (h, TRUE, sr)) return;
}
#endif

#if defined (__linux__)
static struct termios savemodes;
static int havemodes = 0;

int tty_break()
{
  struct termios modmodes;

  if (tcgetattr (fileno (stdin), &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return tcsetattr (fileno (stdin), TCSANOW, &modmodes);
}

int tty_getchar()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar();
}

int tty_fix()
{
  if (!havemodes) return 0;

  return tcsetattr (fileno (stdin), TCSADRAIN, &savemodes);
}
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
static struct termios savemodes;
static int havemodes = 0;

int tty_break()
{
  struct termios modmodes;

  if (ioctl (fileno (stdin), TIOCGETA, &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return ioctl (fileno (stdin), TIOCSETAW, &modmodes);
}

int tty_getchar()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar();
}

int tty_fix()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TIOCSETAW, &savemodes);
}
#endif

#if defined (_WIN)
static DWORD saveMode = 0;

int tty_break()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  GetConsoleMode (stdinHandle, &saveMode);
  SetConsoleMode (stdinHandle, ENABLE_PROCESSED_INPUT);

  return 0;
}

int tty_getchar()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  DWORD rc = WaitForSingleObject (stdinHandle, 1000);

  if (rc == WAIT_TIMEOUT)   return  0;
  if (rc == WAIT_ABANDONED) return -1;
  if (rc == WAIT_FAILED)    return -1;

  // The whole ReadConsoleInput () part is a workaround.
  // For some unknown reason, maybe a mingw bug, a random signal
  // is sent to stdin which unblocks WaitForSingleObject () and sets rc 0.
  // Then it wants to read with getche () a keyboard input
  // which has never been made.

  INPUT_RECORD buf[100];

  DWORD num = 0;

  memset (buf, 0, sizeof (buf));

  ReadConsoleInput (stdinHandle, buf, 100, &num);

  FlushConsoleInputBuffer (stdinHandle);

  for (DWORD i = 0; i < num; i++)
  {
    if (buf[i].EventType != KEY_EVENT) continue;

    KEY_EVENT_RECORD KeyEvent = buf[i].Event.KeyEvent;

    if (KeyEvent.bKeyDown != TRUE) continue;

    return KeyEvent.uChar.AsciiChar;
  }

  return 0;
}

int tty_fix()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  SetConsoleMode (stdinHandle, saveMode);

  return 0;
}
#endif
