/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "convert.h"
#include "thread.h"
#include "timer.h"
#include "status.h"
#include "restore.h"
#include "shared.h"
#include "hwmon.h"
#include "interface.h"
#include "outfile.h"
#include "terminal.h"

const char *PROMPT = "[s]tatus [p]ause [r]esume [b]ypass [c]heckpoint [q]uit => ";

void welcome_screen (hashcat_ctx_t *hashcat_ctx, const time_t proc_start, const char *version_tag)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet       == true) return;
  if (user_options->keyspace    == true) return;
  if (user_options->stdout_flag == true) return;
  if (user_options->show        == true) return;
  if (user_options->left        == true) return;

  if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, "%s (%s) starting in benchmark mode...", PROGNAME, version_tag);
      event_log_info (hashcat_ctx, "");
    }
    else
    {
      event_log_info (hashcat_ctx, "# %s (%s) %s", PROGNAME, version_tag, ctime (&proc_start));
    }
  }
  else if (user_options->restore == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in restore mode...", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, "");
  }
  else if (user_options->speed_only == true)
  {
    event_log_info (hashcat_ctx, "%s (%s) starting in speed-only mode...", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, "");
  }
  else
  {
    event_log_info (hashcat_ctx, "%s (%s) starting...", PROGNAME, version_tag);
    event_log_info (hashcat_ctx, "");
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

  event_log_info_nn (hashcat_ctx, "Started: %s", ctime (&proc_start));
  event_log_info_nn (hashcat_ctx, "Stopped: %s", ctime (&proc_stop));
}

int setup_console (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  #if defined (_WIN)
  SetConsoleWindowSize (132);

  if (_setmode (_fileno (stdin), _O_BINARY) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", "stdin", strerror (errno));

    return -1;
  }

  if (_setmode (_fileno (stdout), _O_BINARY) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", "stdout", strerror (errno));

    return -1;
  }

  if (_setmode (_fileno (stderr), _O_BINARY) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", "stderr", strerror (errno));

    return -1;
  }
  #endif

  return 0;
}

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

static void keypress (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  // this is required, because some of the variables down there are not initialized at that point
  while (status_ctx->devices_status == STATUS_INIT) hc_sleep_msec (100);

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

    event_log_info (hashcat_ctx, "");

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        event_log_info (hashcat_ctx, "");

        status_display (hashcat_ctx);

        event_log_info (hashcat_ctx, "");

        if (quiet == false) send_prompt ();

        break;

      case 'b':

        event_log_info (hashcat_ctx, "");

        bypass (hashcat_ctx);

        event_log_info (hashcat_ctx, "Next dictionary / mask in queue selected, bypassing current one");

        event_log_info (hashcat_ctx, "");

        if (quiet == false) send_prompt ();

        break;

      case 'p':

        event_log_info (hashcat_ctx, "");

        SuspendThreads (hashcat_ctx);

        if (status_ctx->devices_status == STATUS_PAUSED)
        {
          event_log_info (hashcat_ctx, "Paused");
        }

        event_log_info (hashcat_ctx, "");

        if (quiet == false) send_prompt ();

        break;

      case 'r':

        event_log_info (hashcat_ctx, "");

        ResumeThreads (hashcat_ctx);

        if (status_ctx->devices_status == STATUS_RUNNING)
        {
          event_log_info (hashcat_ctx, "Resumed");
        }

        event_log_info (hashcat_ctx, "");

        if (quiet == false) send_prompt ();

        break;

      case 'c':

        event_log_info (hashcat_ctx, "");

        stop_at_checkpoint (hashcat_ctx);

        event_log_info (hashcat_ctx, "");

        if (quiet == false) send_prompt ();

        break;

      case 'q':

        event_log_info (hashcat_ctx, "");

        myquit (hashcat_ctx);

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

void *thread_keypress (void *p)
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

void status_display_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    event_log_error (hashcat_ctx, "status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    event_log_error (hashcat_ctx, "status view is not available during autotune phase");

    return;
  }

  FILE *out = stdout;

  fprintf (out, "STATUS\t%u\t", status_ctx->devices_status);

  /**
   * speed new
   */

  fprintf (out, "SPEED\t");

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    u64    speed_cnt  = 0;
    double speed_msec = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      speed_cnt  += device_param->speed_cnt[i];
      speed_msec += device_param->speed_msec[i];
    }

    speed_cnt  /= SPEED_CACHE;
    speed_msec /= SPEED_CACHE;

    fprintf (out, "%" PRIu64 "\t%f\t", speed_cnt, speed_msec);
  }

  /**
   * exec time
   */

  fprintf (out, "EXEC_RUNTIME\t");

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    const double exec_msec_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    fprintf (out, "%f\t", exec_msec_avg);
  }

  /**
   * words_cur
   */

  u64 words_cur = get_lowest_words_done (hashcat_ctx);

  fprintf (out, "CURKU\t%" PRIu64 "\t", words_cur);

  /**
   * counter
   */

  u64 progress_total = status_ctx->words_cnt * hashes->salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    all_done     += status_ctx->words_progress_done[salt_pos];
    all_rejected += status_ctx->words_progress_rejected[salt_pos];
    all_restored += status_ctx->words_progress_restored[salt_pos];
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (user_options->skip)
  {
    progress_skip = MIN (user_options->skip, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_skip *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_skip *= mask_ctx->bfs_cnt;
  }

  if (user_options->limit)
  {
    progress_end = MIN (user_options->limit, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_end  *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_end  *= mask_ctx->bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  fprintf (out, "PROGRESS\t%" PRIu64 "\t%" PRIu64 "\t", progress_cur_relative_skip, progress_end_relative_skip);

  /**
   * cracks
   */

  fprintf (out, "RECHASH\t%u\t%u\t", hashes->digests_done, hashes->digests_cnt);
  fprintf (out, "RECSALT\t%u\t%u\t", hashes->salts_done,   hashes->salts_cnt);

  /**
   * temperature
   */

  if (user_options->gpu_temp_disable == false)
  {
    fprintf (out, "TEMP\t");

    hc_thread_mutex_lock (status_ctx->mux_hwmon);

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      int temp = hm_get_temperature_with_device_id (hashcat_ctx, device_id);

      fprintf (out, "%d\t", temp);
    }

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);
  }

  /**
   * flush
   */

  fputs (EOL, out);
  fflush (out);
}

void status_display (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    event_log_error (hashcat_ctx, "Status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    event_log_error (hashcat_ctx, "Status view is not available during autotune phase");

    return;
  }

  if (status_ctx->shutdown_inner == true)
  {
    // in this case some required buffers are free'd, ascii_digest() would run into segfault

    event_log_error (hashcat_ctx, "Status view is not available during shutdown phase");

    return;
  }

  if (user_options->machine_readable == true)
  {
    status_display_machine_readable (hashcat_ctx);

    return;
  }

  /**
   * show something
   */

  event_log_info (hashcat_ctx, "Session........: %s", status_get_session       (hashcat_ctx));
  event_log_info (hashcat_ctx, "Status.........: %s", status_get_status_string (hashcat_ctx));
  event_log_info (hashcat_ctx, "Time.Started...: %s (%s)",
    status_get_time_started_absolute   (hashcat_ctx),
    status_get_time_started_relative   (hashcat_ctx));
  event_log_info (hashcat_ctx, "Time.Estimated.: %s (%s)",
    status_get_time_estimated_absolute (hashcat_ctx),
    status_get_time_estimated_relative (hashcat_ctx));
  event_log_info (hashcat_ctx, "Hash.Type......: %s", status_get_hash_type     (hashcat_ctx));
  event_log_info (hashcat_ctx, "Hash.Target....: %s", status_get_hash_target   (hashcat_ctx));

  switch (status_get_input_mode (hashcat_ctx))
  {
    case INPUT_MODE_STRAIGHT_FILE:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s)",             status_get_input_base (hashcat_ctx));
      break;
    case INPUT_MODE_STRAIGHT_FILE_RULES_FILE:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s)",             status_get_input_base (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Rules (%s)",            status_get_input_mod  (hashcat_ctx));
      break;
    case INPUT_MODE_STRAIGHT_FILE_RULES_GEN:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s)",             status_get_input_base (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Rules (Generated)");
      break;
    case INPUT_MODE_STRAIGHT_STDIN:
      event_log_info (hashcat_ctx, "Input.Base.....: Pipe");
      break;
    case INPUT_MODE_STRAIGHT_STDIN_RULES_FILE:
      event_log_info (hashcat_ctx, "Input.Base.....: Pipe");
      event_log_info (hashcat_ctx, "Input.Mod......: Rules (%s)",            status_get_input_mod (hashcat_ctx));
      break;
    case INPUT_MODE_STRAIGHT_STDIN_RULES_GEN:
      event_log_info (hashcat_ctx, "Input.Base.....: Pipe");
      event_log_info (hashcat_ctx, "Input.Mod......: Rules (Generated)");
      break;
    case INPUT_MODE_COMBINATOR_BASE_LEFT:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Left Side",  status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: File (%s), Right Side", status_get_input_mod     (hashcat_ctx));
      break;
    case INPUT_MODE_COMBINATOR_BASE_RIGHT:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Right Side", status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: File (%s), Left Side",  status_get_input_mod     (hashcat_ctx));
      break;
    case INPUT_MODE_MASK:
      event_log_info (hashcat_ctx, "Input.Mask.....: %s",                    status_get_input_base    (hashcat_ctx));
      break;
    case INPUT_MODE_MASK_CS:
      event_log_info (hashcat_ctx, "Input.Mask.....: %s",                    status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Charset..: %s",                    status_get_input_charset (hashcat_ctx));
      break;
    case INPUT_MODE_HYBRID1:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Left Side",  status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Mask (%s), Right Side", status_get_input_mod     (hashcat_ctx));
      break;
    case INPUT_MODE_HYBRID1_CS:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Left Side",  status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Mask (%s), Right Side", status_get_input_mod     (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Charset..: %s",                    status_get_input_charset (hashcat_ctx));
      break;
    case INPUT_MODE_HYBRID2:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Right Side", status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Mask (%s), Left Side",  status_get_input_mod     (hashcat_ctx));
      break;
    case INPUT_MODE_HYBRID2_CS:
      event_log_info (hashcat_ctx, "Input.Base.....: File (%s), Right Side", status_get_input_base    (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Mod......: Mask (%s), Left Side",  status_get_input_mod     (hashcat_ctx));
      event_log_info (hashcat_ctx, "Input.Charset..: %s",                    status_get_input_charset (hashcat_ctx));
      break;
  }

  for (int device_id = 0; device_id < status_get_device_info_cnt (hashcat_ctx); device_id++)
  {
    if (status_get_skipped_dev (hashcat_ctx, device_id) == true) continue;

    event_log_info (hashcat_ctx, "Candidates.#%d..: %s", device_id + 1, status_get_input_candidates_dev (hashcat_ctx, device_id));
  }

  switch (status_get_progress_mode (hashcat_ctx))
  {
    case PROGRESS_MODE_KEYSPACE_KNOWN:
      event_log_info (hashcat_ctx, "Progress.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        status_get_progress_cur_relative_skip (hashcat_ctx),
        status_get_progress_end_relative_skip (hashcat_ctx),
        status_get_progress_finished_percent  (hashcat_ctx));
      event_log_info (hashcat_ctx, "Rejected.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        status_get_progress_rejected          (hashcat_ctx),
        status_get_progress_cur_relative_skip (hashcat_ctx),
        status_get_progress_rejected_percent  (hashcat_ctx));
      event_log_info (hashcat_ctx, "Restore.Point..: %" PRIu64 "/%" PRIu64 " (%.02f%%)",
        status_get_restore_point              (hashcat_ctx),
        status_get_restore_total              (hashcat_ctx),
        status_get_restore_percent            (hashcat_ctx));
      break;
    case PROGRESS_MODE_KEYSPACE_UNKNOWN:
      event_log_info (hashcat_ctx, "Progress.......: %" PRIu64, status_get_progress_cur_relative_skip (hashcat_ctx));
      event_log_info (hashcat_ctx, "Rejected.......: %" PRIu64, status_get_progress_rejected          (hashcat_ctx));
      event_log_info (hashcat_ctx, "Restore.Point..: %" PRIu64, status_get_restore_point              (hashcat_ctx));
      break;
  }

  event_log_info (hashcat_ctx, "Recovered......: %u/%u (%.2f%%) Digests, %u/%u (%.2f%%) Salts",
    status_get_digests_done    (hashcat_ctx),
    status_get_digests_cnt     (hashcat_ctx),
    status_get_digests_percent (hashcat_ctx),
    status_get_salts_done      (hashcat_ctx),
    status_get_salts_cnt       (hashcat_ctx),
    status_get_salts_percent   (hashcat_ctx));
  event_log_info (hashcat_ctx, "Recovered/Time.: %s", status_get_cpt (hashcat_ctx));

  for (int device_id = 0; device_id < status_get_device_info_cnt (hashcat_ctx); device_id++)
  {
    if (status_get_skipped_dev (hashcat_ctx, device_id) == true) continue;

    event_log_info (hashcat_ctx, "Speed.Dev.#%d...: %9sH/s (%0.2fms)", device_id + 1,
      status_get_speed_sec_dev (hashcat_ctx, device_id),
      status_get_exec_msec_dev (hashcat_ctx, device_id));
  }

  if (status_get_device_info_active (hashcat_ctx) > 1) event_log_info (hashcat_ctx, "Speed.Dev.#*...: %9sH/s", status_get_speed_sec_all (hashcat_ctx));

  if (user_options->gpu_temp_disable == false)
  {
    hc_thread_mutex_lock (status_ctx->mux_hwmon);

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      const int num_temperature = hm_get_temperature_with_device_id (hashcat_ctx, device_id);
      const int num_fanspeed    = hm_get_fanspeed_with_device_id    (hashcat_ctx, device_id);
      const int num_utilization = hm_get_utilization_with_device_id (hashcat_ctx, device_id);
      const int num_corespeed   = hm_get_corespeed_with_device_id   (hashcat_ctx, device_id);
      const int num_memoryspeed = hm_get_memoryspeed_with_device_id (hashcat_ctx, device_id);
      const int num_buslanes    = hm_get_buslanes_with_device_id    (hashcat_ctx, device_id);
      const int num_throttle    = hm_get_throttle_with_device_id    (hashcat_ctx, device_id);

      char output_buf[256] = { 0 };

      int output_len = 0;

      if (num_temperature >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Temp:%3uc", num_temperature);

        output_len = strlen (output_buf);
      }

      if (num_fanspeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Fan:%3u%%", num_fanspeed);

        output_len = strlen (output_buf);
      }

      if (num_utilization >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Util:%3u%%", num_utilization);

        output_len = strlen (output_buf);
      }

      if (num_corespeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Core:%4uMhz", num_corespeed);

        output_len = strlen (output_buf);
      }

      if (num_memoryspeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Mem:%4uMhz", num_memoryspeed);

        output_len = strlen (output_buf);
      }

      if (num_buslanes >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Lanes:%u", num_buslanes);

        output_len = strlen (output_buf);
      }

      if (num_throttle >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " *Throttled*");

        output_len = strlen (output_buf);
      }

      if (output_len == 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " N/A");

        output_len = strlen (output_buf);
      }

      event_log_info (hashcat_ctx, "HWMon.Dev.#%d...:%s", device_id + 1, output_buf);
    }

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);
  }
}

void status_benchmark_automate (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    event_log_error (hashcat_ctx, "status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    event_log_error (hashcat_ctx, "status view is not available during autotune phase");

    return;
  }

  u64    speed_cnt[DEVICES_MAX]  = { 0 };
  double speed_msec[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id]  = device_param->speed_cnt[0];
    speed_msec[device_id] = device_param->speed_msec[0];
  }

  u64 hashes_dev_msec[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_msec[device_id] = 0;

    if (speed_msec[device_id] > 0)
    {
      hashes_dev_msec[device_id] = (double) speed_cnt[device_id] / speed_msec[device_id];
    }
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    event_log_info (hashcat_ctx, "%u:%u:%" PRIu64 "", device_id + 1, hashconfig->hash_mode, (hashes_dev_msec[device_id] * 1000));
  }
}

void status_benchmark (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    event_log_error (hashcat_ctx, "status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    event_log_error (hashcat_ctx, "status view is not available during autotune phase");

    return;
  }

  if (status_ctx->shutdown_inner == 1) return;

  if (user_options->machine_readable == true)
  {
    status_benchmark_automate (hashcat_ctx);

    return;
  }

  u64    speed_cnt[DEVICES_MAX]  = { 0 };
  double speed_msec[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id]  = device_param->speed_cnt[0];
    speed_msec[device_id] = device_param->speed_msec[0];
  }

  double hashes_all_msec = 0;

  double hashes_dev_msec[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_msec[device_id] = 0;

    if (speed_msec[device_id] > 0)
    {
      hashes_dev_msec[device_id] = (double) speed_cnt[device_id] / speed_msec[device_id];

      hashes_all_msec += hashes_dev_msec[device_id];
    }
  }

  /**
   * exec time
   */

  double exec_all_msec[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_msec_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_msec[device_id] = exec_msec_avg;
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display ((double) hashes_dev_msec[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    if (opencl_ctx->devices_active >= 10)
    {
      event_log_info (hashcat_ctx, "Speed.Dev.#%d: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_msec[device_id]);
    }
    else
    {
      event_log_info (hashcat_ctx, "Speed.Dev.#%d.: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_msec[device_id]);
    }
  }

  char display_all_cur[16] = { 0 };

  strncpy (display_all_cur, "0.00", 4);

  format_speed_display ((double) hashes_all_msec * 1000, display_all_cur, sizeof (display_all_cur));

  if (opencl_ctx->devices_active > 1) event_log_info (hashcat_ctx, "Speed.Dev.#*.: %9sH/s", display_all_cur);
}
