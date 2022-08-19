/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "thread.h"
#include "status.h"
#include "shared.h"
#include "hwmon.h"
#include "interface.h"
#include "hashcat.h"
#include "timer.h"
#include "terminal.h"

static const size_t MAXIMUM_EXAMPLE_HASH_LENGTH = 200;

static const size_t TERMINAL_LINE_LENGTH = 79;

static const char *const PROMPT_ACTIVE = "[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => ";
static const char *const PROMPT_PAUSED = "[s]tatus [r]esume [b]ypass [c]heckpoint [f]inish [q]uit => ";

void welcome_screen (hashcat_ctx_t *hashcat_ctx, const char *version_tag)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet       == true) return;
  if (user_options->keyspace    == true) return;
  if (user_options->stdout_flag == true) return;
  if (user_options->show        == true) return;
  if (user_options->left        == true) return;
  if (user_options->identify    == true) return;

  if (user_options->usage == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in help mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, "%s (%s) starting in benchmark mode", PROGNAME, version_tag);

      event_log_info (hashcat_ctx, NULL);

      if (user_options->workload_profile_chgd == false)
      {
        event_log_advice (hashcat_ctx, "Benchmarking uses hand-optimized kernel code by default.");
        event_log_advice (hashcat_ctx, "You can use it in your cracking session by setting the -O option.");
        event_log_advice (hashcat_ctx, "Note: Using optimized kernel code limits the maximum supported password length.");
        event_log_advice (hashcat_ctx, "To disable the optimized kernel code in benchmark mode, use the -w option.");
        event_log_advice (hashcat_ctx, NULL);
      }
    }
    else
    {
      event_log_info (hashcat_ctx, "# version: %s", version_tag);
    }
  }
  else if (user_options->restore == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in restore mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->speed_only == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in speed-only mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->progress_only == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in progress-only mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->backend_info > 0)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in backend information mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->hash_mode_chgd == false)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in autodetect mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else if (user_options->hash_info == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in hash-info mode", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }
  else
  {
    event_log_info (hashcat_ctx, "%s (%s) starting", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, NULL);
  }

  if (user_options->force == true)
  {
    event_log_warning (hashcat_ctx, "You have enabled --force to bypass dangerous warnings and errors!");
    event_log_warning (hashcat_ctx, "This can hide serious problems and should only be done when debugging.");
    event_log_warning (hashcat_ctx, "Do not report hashcat issues encountered when using --force.");
    event_log_warning (hashcat_ctx, NULL);
  }
}

void goodbye_screen (hashcat_ctx_t *hashcat_ctx, const time_t proc_start, const time_t proc_stop)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet       == true) return;
  if (user_options->keyspace    == true) return;
  if (user_options->stdout_flag == true) return;
  if (user_options->show        == true) return;
  if (user_options->left        == true) return;
  if (user_options->identify    == true) return;

  char start_buf[32]; memset (start_buf, 0, sizeof (start_buf));
  char stop_buf[32];  memset (stop_buf,  0, sizeof (stop_buf));

  event_log_info_nn (hashcat_ctx, "Started: %s", ctime_r (&proc_start, start_buf));
  event_log_info_nn (hashcat_ctx, "Stopped: %s", ctime_r (&proc_stop,  stop_buf));
}

int setup_console ()
{
  #if defined (_WIN)
  SetConsoleWindowSize (132);

  if (_setmode (_fileno (stdin), _O_BINARY) == -1)
  {
    __mingw_fprintf (stderr, "%s: %m", "stdin");

    return -1;
  }

  if (_setmode (_fileno (stdout), _O_BINARY) == -1)
  {
    __mingw_fprintf (stderr, "%s: %m", "stdin"); // stdout ?

    return -1;
  }

  if (_setmode (_fileno (stderr), _O_BINARY) == -1)
  {
    __mingw_fprintf (stderr, "%s: %m", "stdin"); // stderr ?

    return -1;
  }
  #endif

  return 0;
}

void send_prompt (hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status == STATUS_PAUSED)
  {
    fprintf (stdout, "%s", PROMPT_PAUSED);
  }
  else
  {
    fprintf (stdout, "%s", PROMPT_ACTIVE);
  }

  fflush (stdout);
}

void clear_prompt (hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  size_t prompt_sz = 0;

  if (status_ctx->devices_status == STATUS_PAUSED)
  {
    prompt_sz = strlen (PROMPT_PAUSED);
  }
  else
  {
    prompt_sz = strlen (PROMPT_ACTIVE);
  }

  fputc ('\r', stdout);

  for (size_t i = 0; i < prompt_sz; i++)
  {
    fputc (' ', stdout);
  }

  fputc ('\r', stdout);

  fflush (stdout);
}

static void keypress (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  // this is required, because some of the variables down there are not initialized at that point
  while (status_ctx->devices_status == STATUS_INIT) usleep (100000);

  const bool quiet = user_options->quiet;

  tty_break ();

  while (status_ctx->shutdown_outer == false)
  {
    int ch = tty_getchar ();

    if (ch == -1) break;

    if (ch ==  0) continue;

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_lock (status_ctx->mux_display);

    event_log_info (hashcat_ctx, NULL);

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        event_log_info (hashcat_ctx, NULL);

        status_display (hashcat_ctx);

        event_log_info (hashcat_ctx, NULL);

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'b':

        event_log_info (hashcat_ctx, NULL);

        bypass (hashcat_ctx);

        event_log_info (hashcat_ctx, "Next dictionary / mask in queue selected. Bypassing current one.");

        event_log_info (hashcat_ctx, NULL);

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'p':

        if (status_ctx->devices_status != STATUS_PAUSED)
        {
          event_log_info (hashcat_ctx, NULL);

          time_t now;

          time (&now);

          SuspendThreads (hashcat_ctx);

          if (status_ctx->devices_status == STATUS_PAUSED)
          {
            char buf[32] = { 0 };

            char *pause_time = ctime_r (&now, buf);

            const size_t pause_time_len = strlen (pause_time);

            if (pause_time[pause_time_len - 1] == '\n') pause_time[pause_time_len - 1] = 0;
            if (pause_time[pause_time_len - 2] == '\r') pause_time[pause_time_len - 2] = 0;

            event_log_info (hashcat_ctx, "Paused at %s", pause_time);
          }

          event_log_info (hashcat_ctx, NULL);
        }

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'r':

        if (status_ctx->devices_status == STATUS_PAUSED)
        {
          event_log_info (hashcat_ctx, NULL);

          time_t now;

          time (&now);

          const double msec_paused = hc_timer_get (status_ctx->timer_paused);

          ResumeThreads (hashcat_ctx);

          if (status_ctx->devices_status != STATUS_PAUSED)
          {
            char buf[32] = { 0 };

            char *resume_time = ctime_r (&now, buf);

            const size_t resume_time_len = strlen (resume_time);

            if (resume_time[resume_time_len - 1] == '\n') resume_time[resume_time_len - 1] = 0;
            if (resume_time[resume_time_len - 2] == '\r') resume_time[resume_time_len - 2] = 0;

            struct tm *tmp;
            struct tm  tm;

            time_t sec_run = msec_paused / 1000;

            tmp = gmtime_r (&sec_run, &tm);

            char *display_pause = (char *) hcmalloc (HCBUFSIZ_TINY);

            format_timer_display (tmp, display_pause, HCBUFSIZ_TINY);

            event_log_info (hashcat_ctx, "Resumed at %s (paused for %s)", resume_time, display_pause);

            hcfree (display_pause);
          }

          event_log_info (hashcat_ctx, NULL);
        }

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'c':

        event_log_info (hashcat_ctx, NULL);

        stop_at_checkpoint (hashcat_ctx);

        if (status_ctx->checkpoint_shutdown == true)
        {
          event_log_info (hashcat_ctx, "Checkpoint enabled. Will quit at next restore-point update.");
        }
        else
        {
          event_log_info (hashcat_ctx, "Checkpoint disabled. Restore-point updates will no longer be monitored.");
        }

        event_log_info (hashcat_ctx, NULL);

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'f':

        event_log_info (hashcat_ctx, NULL);

        finish_after_attack (hashcat_ctx);

        if (status_ctx->finish_shutdown == true)
        {
          event_log_info (hashcat_ctx, "Finish enabled. Will quit after this attack.");
        }
        else
        {
          event_log_info (hashcat_ctx, "Finish disabled. Will continue after this attack.");
        }

        event_log_info (hashcat_ctx, NULL);

        if (quiet == false) send_prompt (hashcat_ctx);

        break;

      case 'q':

        event_log_info (hashcat_ctx, NULL);

        myquit (hashcat_ctx);

        break;

      default:

        if (quiet == false) send_prompt (hashcat_ctx);

        break;
    }

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_unlock (status_ctx->mux_display);
  }

  tty_fix ();
}

HC_API_CALL void *thread_keypress (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  keypress (hashcat_ctx);

  return NULL;
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

#if defined (__FreeBSD__) || defined (__NetBSD__) || defined (__linux__) || defined (__CYGWIN__)
static struct termios savemodes;
static int havemodes = 0;

int tty_break ()
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

int tty_getchar ()
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

  return getchar ();
}

int tty_fix ()
{
  if (!havemodes) return 0;

  return tcsetattr (fileno (stdin), TCSADRAIN, &savemodes);
}
#endif

#if defined (__APPLE__) || defined (__FreeBSD__)
static struct termios savemodes;
static int havemodes = 0;

int tty_break ()
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

int tty_getchar ()
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

  return getchar ();
}

int tty_fix ()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TIOCSETAW, &savemodes);
}
#endif

#if defined (_WIN)
static DWORD saveMode = 0;

int tty_break ()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  GetConsoleMode (stdinHandle, &saveMode);
  SetConsoleMode (stdinHandle, ENABLE_PROCESSED_INPUT);

  return 0;
}

int tty_getchar ()
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

int tty_fix ()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  SetConsoleMode (stdinHandle, saveMode);

  return 0;
}
#endif

bool is_stdout_terminal (void)
{
#if defined(_WIN)
  return _isatty(_fileno (stdout));
#else
  return isatty (fileno (stdout));
#endif
}

void compress_terminal_line_length (char *out_buf, const size_t keep_from_beginning, const size_t keep_from_end)
{
  const size_t target_len = TERMINAL_LINE_LENGTH - keep_from_beginning;

  const size_t out_len = strlen (out_buf);

  if (out_len < target_len) return;

  char *ptr1 = out_buf + target_len - 3 - keep_from_end;
  char *ptr2 = out_buf + out_len - keep_from_end;

  *ptr1++ = '.';
  *ptr1++ = '.';
  *ptr1++ = '.';

  for (size_t i = 0; i < keep_from_end; i++)
  {
    *ptr1++ = *ptr2++;
  }

  *ptr1 = 0;
}

void hash_info_single_json (hashcat_ctx_t *hashcat_ctx, user_options_extra_t *user_options_extra)
{
  if (hashconfig_init (hashcat_ctx) == 0)
  {
    hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

    printf ("\"%u\": { ", hashconfig->hash_mode);
    printf ("\"name\": \"%s\", ", hashconfig->hash_name);
    printf ("\"category\": \"%s\", ", strhashcategory (hashconfig->hash_category));
    printf ("\"slow_hash\": %s, ", (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) ? "false" : "true");

    printf ("\"password_len_min\": %u, ", hashconfig->pw_min);
    printf ("\"password_len_max\": %u, ", hashconfig->pw_max);

    printf ("\"is_salted\": %s, ", (hashconfig->is_salted == true) ? "true" : "false");

    if (hashconfig->is_salted == true)
    {
      u32 t = hashconfig->salt_type;
      const char *t_desc = (t == SALT_TYPE_EMBEDDED) ? "embedded" : (t == SALT_TYPE_GENERIC) ? "generic" : "virtual";
      printf ("\"salt_type\": \"%s\", ", t_desc);
      printf ("\"salt_len_min\": %u, ", hashconfig->salt_min);
      printf ("\"salt_len_max\": %u, ", hashconfig->salt_max);
    }

    if ((hashconfig->has_pure_kernel) && (hashconfig->has_optimized_kernel))
    {
      printf ("\"kernel_type\": %s, ", "[ \"pure\", \"optimized\" ]");
    }
    else if (hashconfig->has_pure_kernel)
    {
      printf ("\"kernel_type\": %s, ", "[ \"pure\" ]");
    }
    else if (hashconfig->has_optimized_kernel)
    {
      printf ("\"kernel_type\": %s, ", "[ \"optimized\" ]");
    }

    if ((hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL))
    {
      if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
      {
        if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
        {
          printf ("\"example_hash_format\": \"%s\", ", "hex-encoded");
        }
        else
        {
          printf ("\"example_hash_format\": \"%s\", ", "hex-encoded (binary file only)");
        }
        printf ("\"example_hash\": \"%s\", ", hashconfig->st_hash);
      }
      else
      {
        printf ("\"example_hash_format\": \"%s\", ", "plain");
        printf ("\"example_hash\": \"%s\", ", hashconfig->st_hash);
      }

      if (need_hexify ((const u8 *) hashconfig->st_pass, strlen (hashconfig->st_pass), user_options_extra->separator, false))
      {
        char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

        int tmp_len = 0;

        tmp_buf[tmp_len++] = '$';
        tmp_buf[tmp_len++] = 'H';
        tmp_buf[tmp_len++] = 'E';
        tmp_buf[tmp_len++] = 'X';
        tmp_buf[tmp_len++] = '[';

        exec_hexify ((const u8 *) hashconfig->st_pass, strlen (hashconfig->st_pass), (u8 *) tmp_buf + tmp_len);

        tmp_len += strlen (hashconfig->st_pass) * 2;

        tmp_buf[tmp_len++] = ']';
        tmp_buf[tmp_len++] = 0;

        printf ("\"example_pass\": \"%s\", ", tmp_buf);

        hcfree (tmp_buf);
      }
      else if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
      {
        size_t st_pass_len = strlen (hashconfig->st_pass);

        char *tmp_buf = (char *) hcmalloc (st_pass_len + 1);

        strncpy (tmp_buf, hashconfig->st_pass, st_pass_len);

        uppercase ((u8 *) tmp_buf, st_pass_len);

        printf ("\"example_pass\": \"%s\", ", tmp_buf);

        hcfree (tmp_buf);
      }
      else
      {
        printf ("\"example_pass\": \"%s\", ", hashconfig->st_pass);
      }
    }
    else
    {
      printf ("\"example_hash_format\": \"%s\", ", "N/A");
      printf ("\"example_hash\": \"%s\", ", "N/A");
      printf ("\"example_pass\": \"%s\", ", "N/A");
    }

    if (hashconfig->benchmark_mask != NULL)
    {
      printf ("\"benchmark_mask\": \"%s\", ", hashconfig->benchmark_mask);
    }
    else
    {
      printf ("\"benchmark_mask\": \"%s\", ", "N/A");
    }

    if (hashconfig->benchmark_charset != NULL)
    {
      printf ("\"benchmark_charset1\": \"%s\", ", hashconfig->benchmark_charset);
    }
    else
    {
      printf ("\"benchmark_charset1\": \"%s\", ", "N/A");
    }

    printf ("\"autodetect_enabled\": %s, ", (hashconfig->opts_type & OPTS_TYPE_AUTODETECT_DISABLE) ? "false" : "true");
    printf ("\"self_test_enabled\": %s, ", (hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) ? "false" : "true");
    printf ("\"potfile_enabled\": %s, ", (hashconfig->opts_type & OPTS_TYPE_POTFILE_NOPASS) ? "false" : "true");
    printf ("\"custom_plugin\": %s, ", (hashconfig->opts_type & OPTS_TYPE_STOCK_MODULE) ? "false" : "true");

    if (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_ASCII)
    {
      printf ("\"plaintext_encoding\": %s", "[ \"ASCII\" ]");
    }
    else if (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_HEXIFY)
    {
      printf ("\"plaintext_encoding\": %s", "[ \"HEX\" ]");
    }
    else
    {
      printf ("\"plaintext_encoding\": %s", "[ \"ASCII\", \"HEX\" ]");
    }

    event_log_info (hashcat_ctx, NULL);
  }

  printf (" }");

  hashconfig_destroy (hashcat_ctx);
}

void hash_info_single (hashcat_ctx_t *hashcat_ctx, user_options_extra_t *user_options_extra)
{
  if (hashconfig_init (hashcat_ctx) == 0)
  {
    hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

    event_log_info (hashcat_ctx, "Hash mode #%u", hashconfig->hash_mode);
    event_log_info (hashcat_ctx, "  Name................: %s", hashconfig->hash_name);
    event_log_info (hashcat_ctx, "  Category............: %s", strhashcategory (hashconfig->hash_category));
    event_log_info (hashcat_ctx, "  Slow.Hash...........: %s", (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) ? "No" : "Yes");

    event_log_info (hashcat_ctx, "  Password.Len.Min....: %u", hashconfig->pw_min);
    event_log_info (hashcat_ctx, "  Password.Len.Max....: %u", hashconfig->pw_max);

    if (hashconfig->is_salted == true)
    {
      u32 t = hashconfig->salt_type;
      const char *t_desc = (t == SALT_TYPE_EMBEDDED) ? "Embedded\0" : (t == SALT_TYPE_GENERIC) ? "Generic\0" : "Virtual\0";
      event_log_info (hashcat_ctx, "  Salt.Type...........: %s", t_desc);
      event_log_info (hashcat_ctx, "  Salt.Len.Min........: %u", hashconfig->salt_min);
      event_log_info (hashcat_ctx, "  Salt.Len.Max........: %u", hashconfig->salt_max);
    }

    // almost always 1 and -1
    //event_log_info (hashcat_ctx, "  Hashes.Count.Min....: %d", hashconfig->hashes_count_min);
    //event_log_info (hashcat_ctx, "  Hashes.Count.Max....: %u", hashconfig->hashes_count_max);

    if ((hashconfig->has_pure_kernel) && (hashconfig->has_optimized_kernel))
    {
      event_log_info (hashcat_ctx, "  Kernel.Type(s)......: pure, optimized");
    }
    else if (hashconfig->has_pure_kernel)
    {
      event_log_info (hashcat_ctx, "  Kernel.Type(s)......: pure");
    }
    else if (hashconfig->has_optimized_kernel)
    {
      event_log_info (hashcat_ctx, "  Kernel.Type(s)......: optimized");
    }

    if ((hashconfig->st_hash != NULL) && (hashconfig->st_pass != NULL))
    {
      if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
      {
        if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
        {
          event_log_info (hashcat_ctx, "  Example.Hash.Format.: hex-encoded");
        }
        else
        {
          event_log_info (hashcat_ctx, "  Example.Hash.Format.: hex-encoded (binary file only)");
        }
      }
      else
      {
        event_log_info (hashcat_ctx, "  Example.Hash.Format.: plain");
      }

      if (strlen (hashconfig->st_hash) > MAXIMUM_EXAMPLE_HASH_LENGTH)
      {
        char *st_hash = hcstrdup (hashconfig->st_hash);

        compress_terminal_line_length (st_hash, 24, 5);

        event_log_info (hashcat_ctx, "  Example.Hash........: %s [Truncated, use --mach for full length]", st_hash);

        hcfree (st_hash);
      }
      else
      {
        event_log_info (hashcat_ctx, "  Example.Hash........: %s", hashconfig->st_hash);
      }

      if (need_hexify ((const u8 *) hashconfig->st_pass, strlen (hashconfig->st_pass), user_options_extra->separator, false))
      {
        char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

        int tmp_len = 0;

        tmp_buf[tmp_len++] = '$';
        tmp_buf[tmp_len++] = 'H';
        tmp_buf[tmp_len++] = 'E';
        tmp_buf[tmp_len++] = 'X';
        tmp_buf[tmp_len++] = '[';

        exec_hexify ((const u8 *) hashconfig->st_pass, strlen (hashconfig->st_pass), (u8 *) tmp_buf + tmp_len);

        tmp_len += strlen (hashconfig->st_pass) * 2;

        tmp_buf[tmp_len++] = ']';
        tmp_buf[tmp_len++] = 0;

        event_log_info (hashcat_ctx, "  Example.Pass........: %s", tmp_buf);

        hcfree (tmp_buf);
      }
      else if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
      {
        size_t st_pass_len = strlen (hashconfig->st_pass);

        char *tmp_buf = (char *) hcmalloc (st_pass_len + 1);

        strncpy (tmp_buf, hashconfig->st_pass, st_pass_len);

        uppercase ((u8 *) tmp_buf, st_pass_len);

        event_log_info (hashcat_ctx, "  Example.Pass........: %s", tmp_buf);

        hcfree (tmp_buf);
      }
      else
      {
        event_log_info (hashcat_ctx, "  Example.Pass........: %s", hashconfig->st_pass);
      }
    }
    else
    {
      event_log_info (hashcat_ctx, "  Example.Hash.Format.: N/A");
      event_log_info (hashcat_ctx, "  Example.Hash........: N/A");
      event_log_info (hashcat_ctx, "  Example.Pass........: N/A");
    }

    if (hashconfig->benchmark_mask != NULL)
    {
      event_log_info (hashcat_ctx, "  Benchmark.Mask......: %s", hashconfig->benchmark_mask);
    }
    else
    {
      event_log_info (hashcat_ctx, "  Benchmark.Mask......: N/A");
    }

    if (hashconfig->benchmark_charset != NULL)
    {
      event_log_info (hashcat_ctx, "  Benchmark.Charset1..: %s", hashconfig->benchmark_charset);
    }
    // else // almost always empty
    // {
    //   event_log_info (hashcat_ctx, "  Benchmark.Charset1..: N/A");
    // }

    event_log_info (hashcat_ctx, "  Autodetect.Enabled..: %s", (hashconfig->opts_type & OPTS_TYPE_AUTODETECT_DISABLE) ? "No" : "Yes");
    event_log_info (hashcat_ctx, "  Self.Test.Enabled...: %s", (hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) ? "No" : "Yes");
    event_log_info (hashcat_ctx, "  Potfile.Enabled.....: %s", (hashconfig->opts_type & OPTS_TYPE_POTFILE_NOPASS) ? "No" : "Yes");
    event_log_info (hashcat_ctx, "  Custom.Plugin.......: %s", (hashconfig->opts_type & OPTS_TYPE_STOCK_MODULE) ? "No" : "Yes");

    if (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_ASCII)
    {
      event_log_info (hashcat_ctx, "  Plaintext.Encoding..: ASCII only");
    }
    else if (hashconfig->opts_type & OPTS_TYPE_PT_ALWAYS_HEXIFY)
    {
      event_log_info (hashcat_ctx, "  Plaintext.Encoding..: HEX only");
    }
    else
    {
      event_log_info (hashcat_ctx, "  Plaintext.Encoding..: ASCII, HEX");
    }

    event_log_info (hashcat_ctx, NULL);
  }

  hashconfig_destroy (hashcat_ctx);
}

void hash_info (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t      *folder_config      = hashcat_ctx->folder_config;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->machine_readable == false)
  {
    event_log_info (hashcat_ctx, "Hash Info:");
    event_log_info (hashcat_ctx, "==========");
    event_log_info (hashcat_ctx, NULL);
  }

  if (user_options->hash_mode_chgd == true)
  {
    if (user_options->machine_readable == true)
    {
      printf ("{ ");
      hash_info_single_json (hashcat_ctx, user_options_extra);
      printf (" }");
    }
    else
    {
      hash_info_single (hashcat_ctx, user_options_extra);
    }
  }
  else
  {
    char *modulefile = (char *) hcmalloc (HCBUFSIZ_TINY);

    if (user_options->machine_readable == true) printf ("{ ");

    for (int i = 0; i < MODULE_HASH_MODES_MAXIMUM; i++)
    {
      user_options->hash_mode = i;

      module_filename (folder_config, i, modulefile, HCBUFSIZ_TINY);

      if (hc_path_exist (modulefile) == false) continue;

      if (user_options->machine_readable == true)
      {
        if (i != 0)
        {
          printf (", ");
        }

        hash_info_single_json (hashcat_ctx, user_options_extra);
      }
      else
      {
        hash_info_single (hashcat_ctx, user_options_extra);
      }
    }

    if (user_options->machine_readable == true) printf (" }");

    hcfree (modulefile);
  }
}

void backend_info (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t   *backend_ctx   = hashcat_ctx->backend_ctx;
  const user_options_t  *user_options  = hashcat_ctx->user_options;
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  if (user_options->backend_info > 1)
  {
    event_log_info (hashcat_ctx, "System Info:");
    event_log_info (hashcat_ctx, "============");
    event_log_info (hashcat_ctx, NULL);

    #if defined (_WIN) || defined (__CYGWIN__) || defined (__MSYS__)
    // TODO
    event_log_info (hashcat_ctx, "OS.Name......: Windows");
    event_log_info (hashcat_ctx, "OS.Release...: N/A");
    event_log_info (hashcat_ctx, "HW.Platform..: N/A");
    event_log_info (hashcat_ctx, "HW.Model.....: N/A");
    #else

    struct utsname utsbuf;

    bool rc_uname  = false;
    bool rc_sysctl = false;

    char *hw_model_buf = NULL;

    #if !defined (__linux__)

    size_t hw_model_len = 0;

    if (sysctlbyname ("hw.model", NULL, &hw_model_len, NULL, 0) == 0 && hw_model_len > 0)
    {
      hw_model_buf = (char *) hcmalloc (hw_model_len);

      if (sysctlbyname ("hw.model", hw_model_buf, &hw_model_len, NULL, 0) != 0)
      {
        hw_model_buf = NULL;
        hw_model_len = 0;

        hcfree (hw_model_buf);
      }
      else
      {
        rc_sysctl = true;
      }
    }
    #endif // ! __linux__

    if (uname (&utsbuf) == 0)
    {
      rc_uname = true;
    }

    event_log_info (hashcat_ctx, "OS.Name......: %s", (rc_uname  == true) ? utsbuf.sysname : "N/A");
    event_log_info (hashcat_ctx, "OS.Release...: %s", (rc_uname  == true) ? utsbuf.release : "N/A");
    event_log_info (hashcat_ctx, "HW.Model.....: %s", (rc_sysctl == true) ? hw_model_buf   : "N/A");
    event_log_info (hashcat_ctx, "HW.Platform..: %s", (rc_uname  == true) ? utsbuf.machine : "N/A");

    if (rc_sysctl == true)
    {
      hcfree (hw_model_buf);
    }
    #endif // _WIN || __CYGWIN__ || __MSYS__

    event_log_info (hashcat_ctx, NULL);

    event_log_info (hashcat_ctx, "Environment Info:");
    event_log_info (hashcat_ctx, "=================");
    event_log_info (hashcat_ctx, NULL);

    event_log_info (hashcat_ctx, "Cur.Work.Dir.: %s", folder_config->cwd);
    event_log_info (hashcat_ctx, "Install.Dir..: %s", folder_config->install_dir);
    event_log_info (hashcat_ctx, "Profile.Dir..: %s", folder_config->profile_dir);
    event_log_info (hashcat_ctx, "Cache.Dir....: %s", folder_config->cache_dir);
    // uninitialized at this point, for instance if the user uses --session
    //event_log_info (hashcat_ctx, "Session.Dir..: %s", folder_config->session_dir);
    event_log_info (hashcat_ctx, "Shared.Dir...: %s", folder_config->shared_dir);
    event_log_info (hashcat_ctx, "CL.Inc.Path..: %s", folder_config->cpath_real);

    event_log_info (hashcat_ctx, NULL);
  }

  if (backend_ctx->cuda)
  {
    event_log_info (hashcat_ctx, "CUDA Info:");
    event_log_info (hashcat_ctx, "==========");
    event_log_info (hashcat_ctx, NULL);

    int cuda_devices_cnt    = backend_ctx->cuda_devices_cnt;
    int cuda_driver_version = backend_ctx->cuda_driver_version;

    event_log_info (hashcat_ctx, "CUDA.Version.: %u.%u", cuda_driver_version / 1000, (cuda_driver_version % 100) / 10);
    event_log_info (hashcat_ctx, NULL);

    for (int cuda_devices_idx = 0; cuda_devices_idx < cuda_devices_cnt; cuda_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_cuda[cuda_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id                 = device_param->device_id;
      char *device_name               = device_param->device_name;
      u32   device_processors         = device_param->device_processors;
      u32   device_maxclock_frequency = device_param->device_maxclock_frequency;
      u64   device_local_mem_size     = device_param->device_local_mem_size;
      u64   device_available_mem      = device_param->device_available_mem;
      u64   device_global_mem         = device_param->device_global_mem;
      u8    pcie_domain               = device_param->pcie_domain;
      u8    pcie_bus                  = device_param->pcie_bus;
      u8    pcie_device               = device_param->pcie_device;
      u8    pcie_function             = device_param->pcie_function;

      if (device_param->device_id_alias_cnt)
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u (Alias: #%u)", device_id + 1, device_param->device_id_alias_buf[0] + 1);
      }
      else
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u", device_id + 1);
      }

      event_log_info (hashcat_ctx, "  Name...........: %s", device_name);
      event_log_info (hashcat_ctx, "  Processor(s)...: %u", device_processors);
      event_log_info (hashcat_ctx, "  Clock..........: %u", device_maxclock_frequency);
      event_log_info (hashcat_ctx, "  Memory.Total...: %" PRIu64 " MB", device_global_mem / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Memory.Free....: %" PRIu64 " MB", device_available_mem / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Local.Memory...: %" PRIu64 " KB", device_local_mem_size / 1024);
      event_log_info (hashcat_ctx, "  PCI.Addr.BDFe..: %04x:%02x:%02x.%u", (u16) pcie_domain, pcie_bus, pcie_device, pcie_function);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  if (backend_ctx->hip)
  {
    event_log_info (hashcat_ctx, "HIP Info:");
    event_log_info (hashcat_ctx, "=========");
    event_log_info (hashcat_ctx, NULL);

    int hip_devices_cnt    = backend_ctx->hip_devices_cnt;
    int hip_runtimeVersion = backend_ctx->hip_runtimeVersion;

    if (hip_runtimeVersion > 1000)
    {
      int hip_version_major = (hip_runtimeVersion - 0) / 10000000;
      int hip_version_minor = (hip_runtimeVersion - (hip_version_major * 10000000)) / 100000;
      int hip_version_patch = (hip_runtimeVersion - (hip_version_major * 10000000) - (hip_version_minor * 100000));

      event_log_info (hashcat_ctx, "HIP.Version.: %u.%u.%u", hip_version_major, hip_version_minor, hip_version_patch);
      event_log_info (hashcat_ctx, NULL);
    }
    else
    {
      event_log_info (hashcat_ctx, "HIP.Version.: %u.%u", hip_runtimeVersion / 100, hip_runtimeVersion % 10);
      event_log_info (hashcat_ctx, NULL);
    }

    for (int hip_devices_idx = 0; hip_devices_idx < hip_devices_cnt; hip_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_hip[hip_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id                 = device_param->device_id;
      char *device_name               = device_param->device_name;
      u32   device_processors         = device_param->device_processors;
      u32   device_maxclock_frequency = device_param->device_maxclock_frequency;
      u64   device_local_mem_size     = device_param->device_local_mem_size;
      u64   device_available_mem      = device_param->device_available_mem;
      u64   device_global_mem         = device_param->device_global_mem;
      u8    pcie_domain               = device_param->pcie_domain;
      u8    pcie_bus                  = device_param->pcie_bus;
      u8    pcie_device               = device_param->pcie_device;
      u8    pcie_function             = device_param->pcie_function;

      if (device_param->device_id_alias_cnt)
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u (Alias: #%u)", device_id + 1, device_param->device_id_alias_buf[0] + 1);
      }
      else
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u", device_id + 1);
      }

      event_log_info (hashcat_ctx, "  Name...........: %s", device_name);
      event_log_info (hashcat_ctx, "  Processor(s)...: %u", device_processors);
      event_log_info (hashcat_ctx, "  Clock..........: %u", device_maxclock_frequency);
      event_log_info (hashcat_ctx, "  Memory.Total...: %" PRIu64 " MB", device_global_mem / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Memory.Free....: %" PRIu64 " MB", device_available_mem / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Local.Memory...: %" PRIu64 " KB", device_local_mem_size / 1024);
      event_log_info (hashcat_ctx, "  PCI.Addr.BDFe..: %04x:%02x:%02x.%u", (u16) pcie_domain, pcie_bus, pcie_device, pcie_function);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  #if defined (__APPLE__)
  if (backend_ctx->mtl)
  {
    event_log_info (hashcat_ctx, "Metal Info:");
    event_log_info (hashcat_ctx, "===========");
    event_log_info (hashcat_ctx, NULL);

    int metal_devices_cnt = backend_ctx->metal_devices_cnt;
    int metal_runtimeVersion = backend_ctx->metal_runtimeVersion;
    char *metal_runtimeVersionStr = backend_ctx->metal_runtimeVersionStr;

    if (metal_runtimeVersionStr != NULL)
    {
      event_log_info (hashcat_ctx, "Metal.Version.: %s", metal_runtimeVersionStr);
    }
    else
    {
      event_log_info (hashcat_ctx, "Metal.Version.: %u", metal_runtimeVersion);
    }

    event_log_info (hashcat_ctx, NULL);

    for (int metal_devices_idx = 0; metal_devices_idx < metal_devices_cnt; metal_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_metal[metal_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id                 = device_param->device_id;
      int   device_mtl_maj            = device_param->mtl_major;
      int   device_mtl_min            = device_param->mtl_minor;
      int   device_max_transfer_rate  = device_param->device_max_transfer_rate;
      int   device_physical_location  = device_param->device_physical_location;
      int   device_location_number    = device_param->device_location_number;
      int   device_registryID         = device_param->device_registryID;
      int   device_is_headless        = device_param->device_is_headless;
      int   device_is_low_power       = device_param->device_is_low_power;
      int   device_is_removable       = device_param->device_is_removable;

      char *device_name               = device_param->device_name;

      u32   device_processors         = device_param->device_processors;

      u64   device_global_mem         = device_param->device_global_mem;
      u64   device_maxmem_alloc       = device_param->device_maxmem_alloc;
      u64   device_available_mem      = device_param->device_available_mem;
      u64   device_local_mem_size     = device_param->device_local_mem_size;

      cl_device_type opencl_device_type         = device_param->opencl_device_type;
      cl_uint        opencl_device_vendor_id    = device_param->opencl_device_vendor_id;
      char          *opencl_device_vendor       = device_param->opencl_device_vendor;

      if (device_param->device_id_alias_cnt)
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u (Alias: #%u)", device_id + 1, device_param->device_id_alias_buf[0] + 1);
      }
      else
      {
        event_log_info (hashcat_ctx, "Backend Device ID #%u", device_id + 1);
      }

      event_log_info (hashcat_ctx, "  Type...........: %s", ((opencl_device_type & CL_DEVICE_TYPE_CPU) ? "CPU" : ((opencl_device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : "Accelerator")));
      event_log_info (hashcat_ctx, "  Vendor.ID......: %u", opencl_device_vendor_id);
      event_log_info (hashcat_ctx, "  Vendor.........: %s", opencl_device_vendor);
      event_log_info (hashcat_ctx, "  Name...........: %s", device_name);
      event_log_info (hashcat_ctx, "  Processor(s)...: %u", device_processors);
      event_log_info (hashcat_ctx, "  Clock..........: N/A");
      event_log_info (hashcat_ctx, "  Memory.Total...: %" PRIu64 " MB (limited to %" PRIu64 " MB allocatable in one block)", device_global_mem / 1024 / 1024, device_maxmem_alloc / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Memory.Free....: %" PRIu64 " MB", device_available_mem / 1024 / 1024);
      event_log_info (hashcat_ctx, "  Local.Memory...: %" PRIu64 " KB", device_local_mem_size / 1024);

      switch (device_physical_location)
      {
        case MTL_DEVICE_LOCATION_BUILTIN:     event_log_info (hashcat_ctx, "  Phys.Location..: built-in"); break;
        case MTL_DEVICE_LOCATION_SLOT:        event_log_info (hashcat_ctx, "  Phys.Location..: connected to slot %u", device_location_number); break;
        case MTL_DEVICE_LOCATION_EXTERNAL:    event_log_info (hashcat_ctx, "  Phys.Location..: connected via an external interface (port %u)", device_location_number); break;
        case MTL_DEVICE_LOCATION_UNSPECIFIED: event_log_info (hashcat_ctx, "  Phys.Location..: unspecified"); break;
        default:                              event_log_info (hashcat_ctx, "  Phys.Location..: N/A"); break;
      }

      if (device_mtl_maj > 0 && device_mtl_min > 0)
      {
        event_log_info (hashcat_ctx, "  Feature.Set....: macOS GPU Family %u v%u", device_mtl_maj, device_mtl_min);
      }
      else
      {
        event_log_info (hashcat_ctx, "  Feature.Set....: N/A");
      }

      event_log_info (hashcat_ctx, "  Registry.ID....: %u", device_registryID);

      if (device_physical_location != MTL_DEVICE_LOCATION_BUILTIN)
      {
        event_log_info (hashcat_ctx, "  Max.TX.Rate....: %u MB/sec", device_max_transfer_rate);
      }
      else
      {
        event_log_info (hashcat_ctx, "  Max.TX.Rate....: N/A");
      }

      event_log_info (hashcat_ctx, "  GPU.Properties.: headless %u, low-power %u, removable %u", device_is_headless, device_is_low_power, device_is_removable);
      event_log_info (hashcat_ctx, NULL);
    }
  }
  #endif

  if (backend_ctx->ocl)
  {
    event_log_info (hashcat_ctx, "OpenCL Info:");
    event_log_info (hashcat_ctx, "============");
    event_log_info (hashcat_ctx, NULL);

    cl_uint   opencl_platforms_cnt         = backend_ctx->opencl_platforms_cnt;
    cl_uint  *opencl_platforms_devices_cnt = backend_ctx->opencl_platforms_devices_cnt;
    char    **opencl_platforms_name        = backend_ctx->opencl_platforms_name;
    char    **opencl_platforms_vendor      = backend_ctx->opencl_platforms_vendor;
    char    **opencl_platforms_version     = backend_ctx->opencl_platforms_version;

    for (cl_uint opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
    {
      char     *opencl_platform_vendor       = opencl_platforms_vendor[opencl_platforms_idx];
      char     *opencl_platform_name         = opencl_platforms_name[opencl_platforms_idx];
      char     *opencl_platform_version      = opencl_platforms_version[opencl_platforms_idx];
      cl_uint   opencl_platform_devices_cnt  = opencl_platforms_devices_cnt[opencl_platforms_idx];

      event_log_info (hashcat_ctx, "OpenCL Platform ID #%u", opencl_platforms_idx + 1);
      event_log_info (hashcat_ctx, "  Vendor..: %s",  opencl_platform_vendor);
      event_log_info (hashcat_ctx, "  Name....: %s",  opencl_platform_name);
      event_log_info (hashcat_ctx, "  Version.: %s",  opencl_platform_version);
      event_log_info (hashcat_ctx, NULL);

      for (cl_uint opencl_platform_devices_idx = 0; opencl_platform_devices_idx < opencl_platform_devices_cnt; opencl_platform_devices_idx++)
      {
        const int backend_devices_idx = backend_ctx->backend_device_from_opencl_platform[opencl_platforms_idx][opencl_platform_devices_idx];

        const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

        int            device_id                  = device_param->device_id;
        char          *device_name                = device_param->device_name;
        u32            device_processors          = device_param->device_processors;
        u32            device_maxclock_frequency  = device_param->device_maxclock_frequency;
        u64            device_maxmem_alloc        = device_param->device_maxmem_alloc;
        u64            device_local_mem_size      = device_param->device_local_mem_size;
        u64            device_available_mem       = device_param->device_available_mem;
        u64            device_global_mem          = device_param->device_global_mem;
        cl_device_type opencl_device_type         = device_param->opencl_device_type;
        cl_uint        opencl_device_vendor_id    = device_param->opencl_device_vendor_id;
        char          *opencl_device_vendor       = device_param->opencl_device_vendor;
        char          *opencl_device_c_version    = device_param->opencl_device_c_version;
        char          *opencl_device_version      = device_param->opencl_device_version;
        char          *opencl_driver_version      = device_param->opencl_driver_version;

        if (device_param->device_id_alias_cnt)
        {
          event_log_info (hashcat_ctx, "  Backend Device ID #%u (Alias: #%u)", device_id + 1, device_param->device_id_alias_buf[0] + 1);
        }
        else
        {
          event_log_info (hashcat_ctx, "  Backend Device ID #%u", device_id + 1);
        }

        event_log_info (hashcat_ctx, "    Type...........: %s", ((opencl_device_type & CL_DEVICE_TYPE_CPU) ? "CPU" : ((opencl_device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : "Accelerator")));
        event_log_info (hashcat_ctx, "    Vendor.ID......: %u", opencl_device_vendor_id);
        event_log_info (hashcat_ctx, "    Vendor.........: %s", opencl_device_vendor);
        event_log_info (hashcat_ctx, "    Name...........: %s", device_name);
        event_log_info (hashcat_ctx, "    Version........: %s", opencl_device_version);
        event_log_info (hashcat_ctx, "    Processor(s)...: %u", device_processors);
        event_log_info (hashcat_ctx, "    Clock..........: %u", device_maxclock_frequency);
        event_log_info (hashcat_ctx, "    Memory.Total...: %" PRIu64 " MB (limited to %" PRIu64 " MB allocatable in one block)", device_global_mem / 1024 / 1024, device_maxmem_alloc / 1024 / 1024);
        event_log_info (hashcat_ctx, "    Memory.Free....: %" PRIu64 " MB", device_available_mem / 1024 / 1024);
        event_log_info (hashcat_ctx, "    Local.Memory...: %" PRIu64 " KB", device_local_mem_size / 1024);
        event_log_info (hashcat_ctx, "    OpenCL.Version.: %s", opencl_device_c_version);
        event_log_info (hashcat_ctx, "    Driver.Version.: %s", opencl_driver_version);

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          u8 pcie_bus      = device_param->pcie_bus;
          u8 pcie_device   = device_param->pcie_device;
          u8 pcie_function = device_param->pcie_function;

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            event_log_info (hashcat_ctx, "    PCI.Addr.BDF...: %02x:%02x.%u", pcie_bus, pcie_device, pcie_function);
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
          {
            event_log_info (hashcat_ctx, "    PCI.Addr.BDF...: %02x:%02x.%u", pcie_bus, pcie_device, pcie_function);
          }
        }

        event_log_info (hashcat_ctx, NULL);
      }
    }
  }
}

void backend_info_compact (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet            == true) return;
  if (user_options->machine_readable == true) return;
  if (user_options->status_json      == true) return;

  /**
   * CUDA
   */

  if (backend_ctx->cuda)
  {
    int cuda_devices_cnt    = backend_ctx->cuda_devices_cnt;
    int cuda_driver_version = backend_ctx->cuda_driver_version;

    const size_t len = event_log_info (hashcat_ctx, "CUDA API (CUDA %u.%u)", cuda_driver_version / 1000, (cuda_driver_version % 100) / 10);

    char line[HCBUFSIZ_TINY] = { 0 };

    memset (line, '=', len);

    line[len] = 0;

    event_log_info (hashcat_ctx, "%s", line);

    for (int cuda_devices_idx = 0; cuda_devices_idx < cuda_devices_cnt; cuda_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_cuda[cuda_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id            = device_param->device_id;
      char *device_name          = device_param->device_name;
      u32   device_processors    = device_param->device_processors;
      u64   device_global_mem    = device_param->device_global_mem;
      u64   device_available_mem = device_param->device_available_mem;

      if ((device_param->skipped == false) && (device_param->skipped_warning == false))
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, %" PRIu64 "/%" PRIu64 " MB, %uMCU",
                  device_id + 1,
                  device_name,
                  device_available_mem / 1024 / 1024,
                  device_global_mem    / 1024 / 1024,
                  device_processors);
      }
      else
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, skipped",
                  device_id + 1,
                  device_name);
      }
    }

    event_log_info (hashcat_ctx, NULL);
  }

  /**
   * HIP
   */

  if (backend_ctx->hip)
  {
    int hip_devices_cnt    = backend_ctx->hip_devices_cnt;
    int hip_runtimeVersion = backend_ctx->hip_runtimeVersion;

    size_t len;

    if (hip_runtimeVersion > 1000)
    {
      int hip_version_major = (hip_runtimeVersion - 0) / 10000000;
      int hip_version_minor = (hip_runtimeVersion - (hip_version_major * 10000000)) / 100000;
      int hip_version_patch = (hip_runtimeVersion - (hip_version_major * 10000000) - (hip_version_minor * 100000));

      len = event_log_info (hashcat_ctx, "HIP API (HIP %u.%u.%u)", hip_version_major, hip_version_minor, hip_version_patch);
    }
    else
    {
      len = event_log_info (hashcat_ctx, "HIP API (HIP %u.%u)", hip_runtimeVersion / 100, hip_runtimeVersion % 10);
    }

    char line[HCBUFSIZ_TINY] = { 0 };

    memset (line, '=', len);

    line[len] = 0;

    event_log_info (hashcat_ctx, "%s", line);

    for (int hip_devices_idx = 0; hip_devices_idx < hip_devices_cnt; hip_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_hip[hip_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id            = device_param->device_id;
      char *device_name          = device_param->device_name;
      u32   device_processors    = device_param->device_processors;
      u64   device_global_mem    = device_param->device_global_mem;
      u64   device_available_mem = device_param->device_available_mem;

      if ((device_param->skipped == false) && (device_param->skipped_warning == false))
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, %" PRIu64 "/%" PRIu64 " MB, %uMCU",
                  device_id + 1,
                  device_name,
                  device_available_mem / 1024 / 1024,
                  device_global_mem    / 1024 / 1024,
                  device_processors);
      }
      else
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, skipped",
                  device_id + 1,
                  device_name);
      }
    }

    event_log_info (hashcat_ctx, NULL);
  }

  #if defined (__APPLE__)
  /**
   * Metal
   */

  if (backend_ctx->mtl)
  {
    int metal_devices_cnt    = backend_ctx->metal_devices_cnt;
    char *metal_runtimeVersionStr = backend_ctx->metal_runtimeVersionStr;

    size_t len = event_log_info (hashcat_ctx, "METAL API (Metal %s)", metal_runtimeVersionStr);

    char line[HCBUFSIZ_TINY] = { 0 };

    memset (line, '=', len);

    line[len] = 0;

    event_log_info (hashcat_ctx, "%s", line);

    for (int metal_devices_idx = 0; metal_devices_idx < metal_devices_cnt; metal_devices_idx++)
    {
      const int backend_devices_idx = backend_ctx->backend_device_from_metal[metal_devices_idx];

      const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

      int   device_id            = device_param->device_id;
      char *device_name          = device_param->device_name;
      u32   device_processors    = device_param->device_processors;
      u64   device_global_mem    = device_param->device_global_mem;
      u64   device_available_mem = device_param->device_available_mem;

      if ((device_param->skipped == false) && (device_param->skipped_warning == false))
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, %" PRIu64 "/%" PRIu64 " MB, %uMCU",
                  device_id + 1,
                  device_name,
                  device_available_mem / 1024 / 1024,
                  device_global_mem    / 1024 / 1024,
                  device_processors);
      }
      else
      {
        event_log_info (hashcat_ctx, "* Device #%u: %s, skipped",
                  device_id + 1,
                  device_name);
      }
    }

    event_log_info (hashcat_ctx, NULL);
  }
  #endif

  /**
   * OpenCL
   */

  if (backend_ctx->ocl)
  {
    cl_uint   opencl_platforms_cnt         = backend_ctx->opencl_platforms_cnt;
    cl_uint  *opencl_platforms_devices_cnt = backend_ctx->opencl_platforms_devices_cnt;
    char    **opencl_platforms_vendor      = backend_ctx->opencl_platforms_vendor;
    char    **opencl_platforms_version     = backend_ctx->opencl_platforms_version;

    for (cl_uint opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
    {
      char     *opencl_platform_vendor       = opencl_platforms_vendor[opencl_platforms_idx];
      char     *opencl_platform_version      = opencl_platforms_version[opencl_platforms_idx];
      cl_uint   opencl_platform_devices_cnt  = opencl_platforms_devices_cnt[opencl_platforms_idx];

      // hide empty OpenCL platforms
      if (opencl_platform_devices_cnt == 0) continue;

      const size_t len = event_log_info (hashcat_ctx, "OpenCL API (%s) - Platform #%u [%s]", opencl_platform_version, opencl_platforms_idx + 1, opencl_platform_vendor);

      char line[HCBUFSIZ_TINY] = { 0 };

      memset (line, '=', len);

      line[len] = 0;

      event_log_info (hashcat_ctx, "%s", line);

      for (cl_uint opencl_platform_devices_idx = 0; opencl_platform_devices_idx < opencl_platform_devices_cnt; opencl_platform_devices_idx++)
      {
        const int backend_devices_idx = backend_ctx->backend_device_from_opencl_platform[opencl_platforms_idx][opencl_platform_devices_idx];

        const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

        int   device_id            = device_param->device_id;
        char *device_name          = device_param->device_name;
        u32   device_processors    = device_param->device_processors;
        u64   device_maxmem_alloc  = device_param->device_maxmem_alloc;
        u64   device_global_mem    = device_param->device_global_mem;
        u64   device_available_mem = device_param->device_available_mem;

        if ((device_param->skipped == false) && (device_param->skipped_warning == false))
        {
          if (strncmp (device_name, "Apple M", 7) == 0)
          {
            cl_device_type opencl_device_type = device_param->opencl_device_type;

            const char *device_type_desc = ((opencl_device_type & CL_DEVICE_TYPE_CPU) ? "CPU" : ((opencl_device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : "Accelerator"));

            event_log_info (hashcat_ctx, "* Device #%u: %s, %s, %" PRIu64 "/%" PRIu64 " MB (%" PRIu64 " MB allocatable), %uMCU",
                      device_id + 1,
                      device_name,
                      device_type_desc,
                      device_available_mem / 1024 / 1024,
                      device_global_mem    / 1024 / 1024,
                      device_maxmem_alloc  / 1024 / 1024,
                      device_processors);
          }
          else
          {
            event_log_info (hashcat_ctx, "* Device #%u: %s, %" PRIu64 "/%" PRIu64 " MB (%" PRIu64 " MB allocatable), %uMCU",
                      device_id + 1,
                      device_name,
                      device_available_mem / 1024 / 1024,
                      device_global_mem    / 1024 / 1024,
                      device_maxmem_alloc  / 1024 / 1024,
                      device_processors);
          }
        }
        else
        {
          event_log_info (hashcat_ctx, "* Device #%u: %s, skipped",
                    device_id + 1,
                    device_name);
        }
      }

      event_log_info (hashcat_ctx, NULL);
    }
  }
}

void status_display_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  const hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  printf ("STATUS\t%d\t", hashcat_status->status_number);

  printf ("SPEED\t");

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    printf ("%" PRIu64 "\t", (u64) (device_info->hashes_msec_dev * 1000));

    // that 1\t is for backward compatibility
    printf ("1000\t");
  }

  printf ("EXEC_RUNTIME\t");

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    printf ("%f\t", device_info->exec_msec_dev);
  }

  printf ("CURKU\t%" PRIu64 "\t", hashcat_status->restore_point);

  printf ("PROGRESS\t%" PRIu64 "\t%" PRIu64 "\t", hashcat_status->progress_cur_relative_skip, hashcat_status->progress_end_relative_skip);

  printf ("RECHASH\t%u\t%u\t", hashcat_status->digests_done, hashcat_status->digests_cnt);

  printf ("RECSALT\t%u\t%u\t", hashcat_status->salts_done, hashcat_status->salts_cnt);

  if (hwmon_ctx->enabled == true)
  {
    printf ("TEMP\t");

    for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
    {
      const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

      if (device_info->skipped_dev == true) continue;
      if (device_info->skipped_warning_dev == true) continue;

      const int temp = hm_get_temperature_with_devices_idx (hashcat_ctx, device_id);

      printf ("%d\t", temp);
    }
  }

  printf ("REJECTED\t%" PRIu64 "\t", hashcat_status->progress_rejected);

  printf ("UTIL\t");

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    // ok, little cheat here again...

    const int util = hm_get_utilization_with_devices_idx (hashcat_ctx, device_id);

    printf ("%d\t", util);
  }

  fwrite (EOL, strlen (EOL), 1, stdout);

  fflush (stdout);

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void json_encode (char *text, char *escaped)
{
  /*
   * Based on https://www.freeformatter.com/json-escape.html, below these 7 different chars
   * are getting escaped before being printed.
   */

  size_t len = strlen (text);
  unsigned long i, j;

  for (i = 0, j = 0; i < len; i++, j++)
  {
    char c = text[i];

    switch (c)
    {
      case '\b': c =  'b'; escaped[j] = '\\'; j++; break;
      case '\t': c =  't'; escaped[j] = '\\'; j++; break;
      case '\n': c =  'n'; escaped[j] = '\\'; j++; break;
      case '\f': c =  'f'; escaped[j] = '\\'; j++; break;
      case '\r': c =  'r'; escaped[j] = '\\'; j++; break;
      case '\\': c = '\\'; escaped[j] = '\\'; j++; break;
      case  '"': c =  '"'; escaped[j] = '\\'; j++; break;
    }

    escaped[j] = c;
  }

  escaped[j] = 0;
}

void status_display_status_json (hashcat_ctx_t *hashcat_ctx)
{
  const hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  time_t time_now;

  time (&time_now);

  time_t end;

  time_t sec_etc = status_get_sec_etc (hashcat_ctx);

  if (overflow_check_u64_add (time_now, sec_etc) == false)
  {
    end = 1;
  }
  else
  {
    end = time_now + sec_etc;
  }

  printf ("{ \"session\": \"%s\",", hashcat_status->session);
  printf (" \"guess\": {");
  if (hashcat_status->guess_base)
  {
    printf (" \"guess_base\": \"%s\",", hashcat_status->guess_base);
  }
  else
  {
    printf (" \"guess_base\": null,");
  }

  printf (" \"guess_base_count\": %u,", hashcat_status->guess_base_count);
  printf (" \"guess_base_offset\": %u,", hashcat_status->guess_base_offset);
  printf (" \"guess_base_percent\": %.02f,", hashcat_status->guess_base_percent);
  printf (" \"guess_mask_length\": %u,", hashcat_status->guess_mask_length);

  if (hashcat_status->guess_mod)
  {
    printf (" \"guess_mod\": \"%s\",", hashcat_status->guess_mod);
  }
  else
  {
    printf (" \"guess_mod\": null,");
  }

  printf (" \"guess_mod_count\": %u,", hashcat_status->guess_mod_count);
  printf (" \"guess_mod_offset\": %u,", hashcat_status->guess_mod_offset);
  printf (" \"guess_mod_percent\": %.02f,", hashcat_status->guess_mod_percent);
  printf (" \"guess_mode\": %u", hashcat_status->guess_mode);
  printf (" },");
  printf (" \"status\": %d,", hashcat_status->status_number);

  /*
   * As the hash target can contain the hash (in case of a single attacked hash), especially
   * some salts can contain chars which need to be escaped to not break the JSON encoding.
   */
  char *target_json_encoded = (char *) hcmalloc (strlen (hashcat_status->hash_target) * 2);
  json_encode (hashcat_status->hash_target, target_json_encoded);
  printf (" \"target\": \"%s\",", target_json_encoded);
  hcfree (target_json_encoded);

  printf (" \"progress\": [%" PRIu64 ", %" PRIu64 "],", hashcat_status->progress_cur_relative_skip, hashcat_status->progress_end_relative_skip);
  printf (" \"restore_point\": %" PRIu64 ",", hashcat_status->restore_point);
  printf (" \"recovered_hashes\": [%u, %u],", hashcat_status->digests_done, hashcat_status->digests_cnt);
  printf (" \"recovered_salts\": [%u, %u],", hashcat_status->salts_done, hashcat_status->salts_cnt);
  printf (" \"rejected\": %" PRIu64 ",", hashcat_status->progress_rejected);
  printf (" \"devices\": [");

  int device_num = 0;

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    if (device_num != 0)
    {
      printf (",");
    }

    printf (" { \"device_id\": %u,", device_id + 1);

    char *device_name_json_encoded = (char *) hcmalloc (strlen (device_info->device_name) * 2);
    json_encode (device_info->device_name, device_name_json_encoded);
    printf (" \"device_name\": \"%s\",", device_name_json_encoded);
    hcfree (device_name_json_encoded);

    const char *device_type_desc = ((device_info->device_type & CL_DEVICE_TYPE_CPU) ? "CPU" :
                                   ((device_info->device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : "Accelerator"));
    printf (" \"device_type\": \"%s\",", device_type_desc);

    printf (" \"speed\": %" PRIu64 ",", (u64) (device_info->hashes_msec_dev * 1000));

    if (hwmon_ctx->enabled == true)
    {
      const int temp = hm_get_temperature_with_devices_idx (hashcat_ctx, device_id);

      printf (" \"temp\": %d,", temp);
    }

    const int util = hm_get_utilization_with_devices_idx (hashcat_ctx, device_id);

    printf (" \"util\": %d }", util);

    device_num++;
  }
  printf (" ],");
  printf (" \"time_start\": %" PRIu64 ",", (u64) status_ctx->runtime_start);
  printf (" \"estimated_stop\": %" PRIu64 " }", (u64) end);

  fwrite (EOL, strlen (EOL), 1, stdout);

  fflush (stdout);

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_display (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->machine_readable == true)
  {
    status_display_machine_readable (hashcat_ctx);

    return;
  }

  if (user_options->status_json == true)
  {
    status_display_status_json (hashcat_ctx);

    return;
  }

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  /**
   * show something
   */

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    event_log_info (hashcat_ctx,
      "Session..........: %s (Brain Session/Attack:0x%08x/0x%08x)",
      hashcat_status->session,
      hashcat_status->brain_session,
      hashcat_status->brain_attack);
  }
  else
  {
    event_log_info (hashcat_ctx,
      "Session..........: %s",
      hashcat_status->session);
  }
  #else
  event_log_info (hashcat_ctx,
    "Session..........: %s",
    hashcat_status->session);
  #endif

  event_log_info (hashcat_ctx,
    "Status...........: %s",
    hashcat_status->status_string);

  event_log_info (hashcat_ctx,
    "Hash.Mode........: %u (%s)",
    hashconfig->hash_mode,
    hashcat_status->hash_name);

  event_log_info (hashcat_ctx,
    "Hash.Target......: %s",
    hashcat_status->hash_target);

  if (user_options->force == true)
  {
    event_log_info (hashcat_ctx,
    "Time.Started.....: %s, (%s)",
    hashcat_status->time_started_absolute,
    hashcat_status->time_started_relative);
  }
  else
  {
    event_log_info (hashcat_ctx,
    "Time.Started.....: %s (%s)",
    hashcat_status->time_started_absolute,
    hashcat_status->time_started_relative);
  }

  if (user_options->force == true)
  {
    event_log_info (hashcat_ctx,
    "Time.Estimated...: %s, (%s)",
    hashcat_status->time_estimated_absolute,
    hashcat_status->time_estimated_relative);
  }
  else
  {
    event_log_info (hashcat_ctx,
    "Time.Estimated...: %s (%s)",
    hashcat_status->time_estimated_absolute,
    hashcat_status->time_estimated_relative);
  }

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    event_log_info (hashcat_ctx, "Kernel.Feature...: Optimized Kernel");
  }
  else
  {
    event_log_info (hashcat_ctx, "Kernel.Feature...: Pure Kernel");
  }

  switch (hashcat_status->guess_mode)
  {
    case GUESS_MODE_STRAIGHT_FILE:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s)",
        hashcat_status->guess_base);

      break;

    case GUESS_MODE_STRAIGHT_FILE_RULES_FILE:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s)",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Rules (%s)",
        hashcat_status->guess_mod);

      break;

    case GUESS_MODE_STRAIGHT_FILE_RULES_GEN:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s)",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Rules (Generated)");

      break;

    case GUESS_MODE_STRAIGHT_STDIN:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: Pipe");

      break;

    case GUESS_MODE_STRAIGHT_STDIN_RULES_FILE:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: Pipe");

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Rules (%s)",
        hashcat_status->guess_mod);

      break;

    case GUESS_MODE_STRAIGHT_STDIN_RULES_GEN:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: Pipe");

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Rules (Generated)");

      break;

    case GUESS_MODE_COMBINATOR_BASE_LEFT:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s), Left Side",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: File (%s), Right Side",
        hashcat_status->guess_mod);

      break;

    case GUESS_MODE_COMBINATOR_BASE_RIGHT:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s), Right Side",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: File (%s), Left Side",
        hashcat_status->guess_mod);

      break;

    case GUESS_MODE_MASK:

      event_log_info (hashcat_ctx,
        "Guess.Mask.......: %s [%u]",
        hashcat_status->guess_base,
        hashcat_status->guess_mask_length);

      break;

    case GUESS_MODE_MASK_CS:

      event_log_info (hashcat_ctx,
        "Guess.Mask.......: %s [%u]",
        hashcat_status->guess_base,
        hashcat_status->guess_mask_length);

      event_log_info (hashcat_ctx,
        "Guess.Charset....: %s ",
        hashcat_status->guess_charset);

      break;

    case GUESS_MODE_HYBRID1:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s), Left Side",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Mask (%s) [%u], Right Side",
        hashcat_status->guess_mod,
        hashcat_status->guess_mask_length);

      break;

    case GUESS_MODE_HYBRID1_CS:

      event_log_info (hashcat_ctx,
        "Guess.Base.......: File (%s), Left Side",
        hashcat_status->guess_base);

      event_log_info (hashcat_ctx,
        "Guess.Mod........: Mask (%s) [%u], Right Side",
        hashcat_status->guess_mod,
        hashcat_status->guess_mask_length);

      event_log_info (hashcat_ctx,
        "Guess.Charset....: %s",
        hashcat_status->guess_charset);

      break;

    case GUESS_MODE_HYBRID2:

      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        event_log_info (hashcat_ctx,
          "Guess.Base.......: Mask (%s) [%u], Left Side",
          hashcat_status->guess_base,
          hashcat_status->guess_mask_length);

        event_log_info (hashcat_ctx,
          "Guess.Mod........: File (%s), Right Side",
          hashcat_status->guess_mod);
      }
      else
      {
        event_log_info (hashcat_ctx,
          "Guess.Base.......: File (%s), Right Side",
          hashcat_status->guess_base);

        event_log_info (hashcat_ctx,
          "Guess.Mod........: Mask (%s) [%u], Left Side",
          hashcat_status->guess_mod,
          hashcat_status->guess_mask_length);
      }

      break;

    case GUESS_MODE_HYBRID2_CS:

      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        event_log_info (hashcat_ctx,
          "Guess.Base.......: Mask (%s) [%u], Left Side",
          hashcat_status->guess_base,
          hashcat_status->guess_mask_length);

        event_log_info (hashcat_ctx,
          "Guess.Mod........: File (%s), Right Side",
          hashcat_status->guess_mod);

        event_log_info (hashcat_ctx,
          "Guess.Charset....: %s",
          hashcat_status->guess_charset);
      }
      else
      {
        event_log_info (hashcat_ctx,
          "Guess.Base.......: File (%s), Right Side",
          hashcat_status->guess_base);

        event_log_info (hashcat_ctx,
          "Guess.Mod........: Mask (%s) [%u], Left Side",
          hashcat_status->guess_mod,
          hashcat_status->guess_mask_length);

        event_log_info (hashcat_ctx,
          "Guess.Charset....: %s",
          hashcat_status->guess_charset);
      }

      break;
  }

  switch (hashcat_status->guess_mode)
  {
    case GUESS_MODE_STRAIGHT_FILE:

      event_log_info (hashcat_ctx,
        "Guess.Queue......: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      break;

    case GUESS_MODE_STRAIGHT_FILE_RULES_FILE:

      event_log_info (hashcat_ctx,
        "Guess.Queue......: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      break;

    case GUESS_MODE_STRAIGHT_FILE_RULES_GEN:

      event_log_info (hashcat_ctx,
        "Guess.Queue......: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      break;

    case GUESS_MODE_MASK:

      event_log_info (hashcat_ctx,
        "Guess.Queue......: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      break;

    case GUESS_MODE_MASK_CS:

      event_log_info (hashcat_ctx,
        "Guess.Queue......: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      break;

    case GUESS_MODE_HYBRID1:

      event_log_info (hashcat_ctx,
        "Guess.Queue.Base.: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      event_log_info (hashcat_ctx,
        "Guess.Queue.Mod..: %u/%u (%.02f%%)",
        hashcat_status->guess_mod_offset,
        hashcat_status->guess_mod_count,
        hashcat_status->guess_mod_percent);

      break;

    case GUESS_MODE_HYBRID2:

      event_log_info (hashcat_ctx,
        "Guess.Queue.Base.: %u/%u (%.02f%%)",
        hashcat_status->guess_base_offset,
        hashcat_status->guess_base_count,
        hashcat_status->guess_base_percent);

      event_log_info (hashcat_ctx,
        "Guess.Queue.Mod..: %u/%u (%.02f%%)",
        hashcat_status->guess_mod_offset,
        hashcat_status->guess_mod_count,
        hashcat_status->guess_mod_percent);

      break;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Speed.#%u.........: %9sH/s (%0.2fms) @ Accel:%u Loops:%u Thr:%u Vec:%u", device_id + 1,
      device_info->speed_sec_dev,
      device_info->exec_msec_dev,
      device_info->kernel_accel_dev,
      device_info->kernel_loops_dev,
      device_info->kernel_threads_dev,
      device_info->vector_width_dev);
  }

  if (hashcat_status->device_info_active > 1)
  {
    event_log_info (hashcat_ctx,
      "Speed.#*.........: %9sH/s",
      hashcat_status->speed_sec_all);
  }

  if (hashcat_status->salts_cnt > 1)
  {
    event_log_info (hashcat_ctx,
      "Recovered........: %u/%u (%.2f%%) Digests (total), %u/%u (%.2f%%) Digests (new), %u/%u (%.2f%%) Salts",
      hashcat_status->digests_done,
      hashcat_status->digests_cnt,
      hashcat_status->digests_percent,
      hashcat_status->digests_done_new,
      hashcat_status->digests_cnt,
      hashcat_status->digests_percent_new,
      hashcat_status->salts_done,
      hashcat_status->salts_cnt,
      hashcat_status->salts_percent);
  }
  else
  {
    event_log_info (hashcat_ctx,
      "Recovered........: %u/%u (%.2f%%) Digests (total), %u/%u (%.2f%%) Digests (new)",
      hashcat_status->digests_done,
      hashcat_status->digests_cnt,
      hashcat_status->digests_percent,
      hashcat_status->digests_done_new,
      hashcat_status->digests_cnt,
      hashcat_status->digests_percent_new);
  }

  if (hashcat_status->digests_cnt > 1000)
  {
    const int    digests_remain         = hashcat_status->digests_cnt - hashcat_status->digests_done;
    const double digests_remain_percent = (double) digests_remain / (double) hashcat_status->digests_cnt * 100;

    const int    salts_remain           = hashcat_status->salts_cnt - hashcat_status->salts_done;
    const double salts_remain_percent   = (double) salts_remain / (double) hashcat_status->salts_cnt * 100;

    if (hashcat_status->salts_cnt > 1)
    {
      event_log_info (hashcat_ctx,
        "Remaining........: %u (%.2f%%) Digests, %u (%.2f%%) Salts",
        digests_remain,
        digests_remain_percent,
        salts_remain,
        salts_remain_percent);
    }
    else
    {
      event_log_info (hashcat_ctx,
        "Remaining........: %u (%.2f%%) Digests",
        digests_remain,
        digests_remain_percent);
    }
  }

  if (hashcat_status->digests_cnt > 1000)
  {
    event_log_info (hashcat_ctx,
      "Recovered/Time...: %s",
      hashcat_status->cpt);
  }

  switch (hashcat_status->progress_mode)
  {
    case PROGRESS_MODE_KEYSPACE_KNOWN:

      event_log_info (hashcat_ctx,
        "Progress.........: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        hashcat_status->progress_cur_relative_skip,
        hashcat_status->progress_end_relative_skip,
        hashcat_status->progress_finished_percent);

      event_log_info (hashcat_ctx,
        "Rejected.........: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        hashcat_status->progress_rejected,
        hashcat_status->progress_cur_relative_skip,
        hashcat_status->progress_rejected_percent);

      break;

    case PROGRESS_MODE_KEYSPACE_UNKNOWN:

      event_log_info (hashcat_ctx,
        "Progress.........: %" PRIu64,
        hashcat_status->progress_cur_relative_skip);

      event_log_info (hashcat_ctx,
        "Rejected.........: %" PRIu64,
        hashcat_status->progress_rejected);

      break;
  }

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    event_log_info (hashcat_ctx,
      "Brain.Link.All...: RX: %sB, TX: %sB",
      hashcat_status->brain_rx_all,
      hashcat_status->brain_tx_all);

    for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
    {
      const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

      if (device_info->skipped_dev == true) continue;
      if (device_info->skipped_warning_dev == true) continue;

      if (device_info->brain_link_status_dev == BRAIN_LINK_STATUS_CONNECTED)
      {
        event_log_info (hashcat_ctx,
          "Brain.Link.#%u....: RX: %sB (%sbps), TX: %sB (%sbps), idle", device_id + 1,
          device_info->brain_link_recv_bytes_dev,
          device_info->brain_link_recv_bytes_sec_dev,
          device_info->brain_link_send_bytes_dev,
          device_info->brain_link_send_bytes_sec_dev);
      }
      else if (device_info->brain_link_status_dev == BRAIN_LINK_STATUS_RECEIVING)
      {
        event_log_info (hashcat_ctx,
          "Brain.Link.#%u....: RX: %sB (%sbps), TX: %sB (%sbps), receiving", device_id + 1,
          device_info->brain_link_recv_bytes_dev,
          device_info->brain_link_recv_bytes_sec_dev,
          device_info->brain_link_send_bytes_dev,
          device_info->brain_link_send_bytes_sec_dev);
      }
      else if (device_info->brain_link_status_dev == BRAIN_LINK_STATUS_SENDING)
      {
        event_log_info (hashcat_ctx,
          "Brain.Link.#%u....: RX: %sB (%sbps), TX: %sB (%sbps), sending", device_id + 1,
          device_info->brain_link_recv_bytes_dev,
          device_info->brain_link_recv_bytes_sec_dev,
          device_info->brain_link_send_bytes_dev,
          device_info->brain_link_send_bytes_sec_dev);
      }
      else
      {
        if ((device_info->brain_link_time_recv_dev > 0) && (device_info->brain_link_time_send_dev > 0))
        {
          event_log_info (hashcat_ctx,
            "Brain.Link.#%u....: RX: %sB (%sbps), TX: %sB (%sbps)", device_id + 1,
            device_info->brain_link_recv_bytes_dev,
            device_info->brain_link_recv_bytes_sec_dev,
            device_info->brain_link_send_bytes_dev,
            device_info->brain_link_send_bytes_sec_dev);
        }
        else
        {
          event_log_info (hashcat_ctx,
            "Brain.Link.#%u....: N/A", device_id + 1);
        }
      }
    }
  }
  #endif

  switch (hashcat_status->progress_mode)
  {
    case PROGRESS_MODE_KEYSPACE_KNOWN:

      event_log_info (hashcat_ctx,
        "Restore.Point....: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        hashcat_status->restore_point,
        hashcat_status->restore_total,
        hashcat_status->restore_percent);

      break;

    case PROGRESS_MODE_KEYSPACE_UNKNOWN:

      event_log_info (hashcat_ctx,
        "Restore.Point....: %" PRIu64,
        hashcat_status->restore_point);

      break;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Restore.Sub.#%u...: Salt:%u Amplifier:%u-%u Iteration:%u-%u", device_id + 1,
      device_info->salt_pos_dev,
      device_info->innerloop_pos_dev,
      device_info->innerloop_pos_dev + device_info->innerloop_left_dev,
      device_info->iteration_pos_dev,
      device_info->iteration_pos_dev + device_info->iteration_left_dev);
  }

  //if (hashconfig->opts_type & OPTS_TYPE_SLOW_CANDIDATES)
  if (user_options->slow_candidates == true)
  {
    event_log_info (hashcat_ctx, "Candidate.Engine.: Host Generator + PCIe");
  }
  else
  {
    event_log_info (hashcat_ctx, "Candidate.Engine.: Device Generator");
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    if (device_info->guess_candidates_dev == NULL) continue;

    event_log_info (hashcat_ctx,
      "Candidates.#%u....: %s", device_id + 1,
      device_info->guess_candidates_dev);
  }

  if (hwmon_ctx->enabled == true)
  {
    #if defined(__APPLE__)
    bool first_dev = true;
    #endif

    for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
    {
      const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

      if (device_info->skipped_dev == true) continue;
      if (device_info->skipped_warning_dev == true) continue;

      if (device_info->hwmon_dev == NULL) continue;

      #if defined(__APPLE__)
      if (first_dev && strlen (device_info->hwmon_fan_dev) > 0)
      {
        event_log_info (hashcat_ctx, "Hardware.Mon.SMC.: %s", device_info->hwmon_fan_dev);
        first_dev = false;
      }
      #endif

      event_log_info (hashcat_ctx,
        "Hardware.Mon.#%u..: %s", device_id + 1,
        device_info->hwmon_dev);
    }
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_benchmark_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const u32 hash_mode = hashconfig->hash_mode;

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx, "%u:%u:%u:%u:%.2f:%" PRIu64, device_id + 1, hash_mode, device_info->corespeed_dev, device_info->memoryspeed_dev, device_info->exec_msec_dev, (u64) (device_info->hashes_msec_dev_benchmark * 1000));
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_benchmark (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->machine_readable == true)
  {
    status_benchmark_machine_readable (hashcat_ctx);

    return;
  }

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Speed.#%u.........: %9sH/s (%0.2fms) @ Accel:%u Loops:%u Thr:%u Vec:%u", device_id + 1,
      device_info->speed_sec_dev,
      device_info->exec_msec_dev,
      device_info->kernel_accel_dev,
      device_info->kernel_loops_dev,
      device_info->kernel_threads_dev,
      device_info->vector_width_dev);
  }

  if (hashcat_status->device_info_active > 1)
  {
    event_log_info (hashcat_ctx,
      "Speed.#*.........: %9sH/s",
      hashcat_status->speed_sec_all);
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_speed_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx, "%d:%" PRIu64, device_id + 1, (u64) (device_info->hashes_msec_dev_benchmark * 1000));
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_speed_json (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  printf ("{ \"devices\": [");

  int device_num = 0;

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    if (device_num != 0)
    {
      printf (",");
    }

    printf (" { \"device_id\": %u,", device_id + 1);
    printf (" \"speed\": %" PRIu64 " }", (u64) (device_info->hashes_msec_dev_benchmark * 1000));
    device_num++;
  }

  printf (" ] }");

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_speed (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->machine_readable == true)
  {
    status_speed_machine_readable (hashcat_ctx);

    return;
  }

  if (user_options->status_json == true)
  {
    status_speed_json (hashcat_ctx);

    return;
  }

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Speed.#%u.........: %9sH/s (%0.2fms)", device_id + 1,
      device_info->speed_sec_dev,
      device_info->exec_msec_dev);
  }

  if (hashcat_status->device_info_active > 1)
  {
    event_log_info (hashcat_ctx,
      "Speed.#*.........: %9sH/s",
      hashcat_status->speed_sec_all);
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_progress_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx, "%u:%" PRIu64 ":%0.2f", device_id + 1, device_info->progress_dev, device_info->runtime_msec_dev);
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_progress_json (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  printf ("{ \"devices\": [");

  int device_num = 0;

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    if (device_num != 0)
    {
      printf (",");
    }

    printf (" { \"device_id\": %u,", device_id + 1);
    printf (" \"progress\": %" PRIu64 ",", device_info->progress_dev);
    printf (" \"runtime\": %0.2f }", device_info->runtime_msec_dev);
    device_num++;
  }

  printf (" ] }");

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}

void status_progress (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->machine_readable == true)
  {
    status_progress_machine_readable (hashcat_ctx);

    return;
  }

  if (user_options->status_json == true)
  {
    status_progress_json (hashcat_ctx);

    return;
  }

  hashcat_status_t *hashcat_status = (hashcat_status_t *) hcmalloc (sizeof (hashcat_status_t));

  if (hashcat_get_status (hashcat_ctx, hashcat_status) == -1)
  {
    hcfree (hashcat_status);

    return;
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Progress.#%u......: %" PRIu64, device_id + 1,
      device_info->progress_dev);
  }

  for (int device_id = 0; device_id < hashcat_status->device_info_cnt; device_id++)
  {
    const device_info_t *device_info = hashcat_status->device_info_buf + device_id;

    if (device_info->skipped_dev == true) continue;
    if (device_info->skipped_warning_dev == true) continue;

    event_log_info (hashcat_ctx,
      "Runtime.#%u.......: %0.2fms", device_id + 1,
      device_info->runtime_msec_dev);
  }

  status_status_destroy (hashcat_ctx, hashcat_status);

  hcfree (hashcat_status);
}
