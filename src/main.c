/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "types.h"
#include "user_options.h"
#include "usage.h"
#include "memory.h"
#include "hashcat.h"
#include "terminal.h"
#include "thread.h"
#include "status.h"
#include "interface.h"
#include "event.h"

#if defined (__MINGW64__) || defined (__MINGW32__)
int _dowildcard = -1;
#endif

static void main_log_clear_line (MAYBE_UNUSED const int prev_len, MAYBE_UNUSED FILE *fp)
{
  #if defined (_WIN)

  fputc ('\r', fp);

  for (int i = 0; i < prev_len; i++)
  {
    fputc (' ', fp);
  }

  fputc ('\r', fp);

  #else

  printf ("\033[2K\r");

  #endif
}

static void main_log (hashcat_ctx_t *hashcat_ctx, FILE *fp, const int loglevel)
{
  event_ctx_t *event_ctx = hashcat_ctx->event_ctx;

  const char *msg_buf     = event_ctx->msg_buf;
  const int   msg_len     = event_ctx->msg_len;
  const bool  msg_newline = event_ctx->msg_newline;

  // handle last_len

  const int prev_len = event_ctx->prev_len;

  if (prev_len)
  {
    main_log_clear_line (prev_len, fp);
  }

  if (msg_newline == true)
  {
    event_ctx->prev_len = 0;
  }
  else
  {
    event_ctx->prev_len = msg_len;
  }

  // color stuff pre

  #if defined (_WIN)
  HANDLE hConsole = GetStdHandle (STD_OUTPUT_HANDLE);

  CONSOLE_SCREEN_BUFFER_INFO con_info;

  GetConsoleScreenBufferInfo (hConsole, &con_info);

  const int orig = con_info.wAttributes;

  switch (loglevel)
  {
    case LOGLEVEL_INFO:
      break;
    case LOGLEVEL_WARNING: SetConsoleTextAttribute (hConsole, 6);
      break;
    case LOGLEVEL_ERROR:   SetConsoleTextAttribute (hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
      break;
    case LOGLEVEL_ADVICE:  SetConsoleTextAttribute (hConsole, 6);
      break;
  }

  #else
  switch (loglevel)
  {
    case LOGLEVEL_INFO:                                   break;
    case LOGLEVEL_WARNING: fwrite ("\033[33m", 5, 1, fp); break;
    case LOGLEVEL_ERROR:   fwrite ("\033[31m", 5, 1, fp); break;
    case LOGLEVEL_ADVICE:  fwrite ("\033[33m", 5, 1, fp); break;
  }
  #endif

  // finally, print

  fwrite (msg_buf, msg_len, 1, fp);

  // color stuff post

  #if defined (_WIN)
  switch (loglevel)
  {
    case LOGLEVEL_INFO:                                              break;
    case LOGLEVEL_WARNING: SetConsoleTextAttribute (hConsole, orig); break;
    case LOGLEVEL_ERROR:   SetConsoleTextAttribute (hConsole, orig); break;
    case LOGLEVEL_ADVICE:  SetConsoleTextAttribute (hConsole, orig); break;
  }
  #else
  switch (loglevel)
  {
    case LOGLEVEL_INFO:                                  break;
    case LOGLEVEL_WARNING: fwrite ("\033[0m", 4, 1, fp); break;
    case LOGLEVEL_ERROR:   fwrite ("\033[0m", 4, 1, fp); break;
    case LOGLEVEL_ADVICE:  fwrite ("\033[0m", 4, 1, fp); break;
  }
  #endif

  // eventual newline

  if (msg_newline == true)
  {
    fwrite (EOL, strlen (EOL), 1, fp);

    // on error, add another newline

    if (loglevel == LOGLEVEL_ERROR)
    {
      fwrite (EOL, strlen (EOL), 1, fp);
    }
  }

  fflush (fp);
}

static void main_log_advice (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->advice_disable == true) return;

  main_log (hashcat_ctx, stdout, LOGLEVEL_ADVICE);
}

static void main_log_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  main_log (hashcat_ctx, stdout, LOGLEVEL_INFO);
}

static void main_log_warning (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  main_log (hashcat_ctx, stdout, LOGLEVEL_WARNING);
}

static void main_log_error (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  main_log (hashcat_ctx, stderr, LOGLEVEL_ERROR);
}

static void main_outerloop_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  /**
   * keypress thread
   */

  hashcat_user->outer_threads_cnt = 0;

  hashcat_user->outer_threads = (hc_thread_t *) hccalloc (2, sizeof (hc_thread_t)); if (hashcat_user->outer_threads == NULL) return;

  status_ctx->shutdown_outer = false;

  if ((user_options->keyspace == false) && (user_options->stdout_flag == false) && (user_options->opencl_info == false) && (user_options->speed_only == false))
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      // see thread_keypress() how to access status information

      hc_thread_create (hashcat_user->outer_threads[hashcat_user->outer_threads_cnt], thread_keypress, hashcat_ctx);

      hashcat_user->outer_threads_cnt++;
    }
  }
}

static void main_outerloop_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  // wait for outer threads

  status_ctx->shutdown_outer = true;

  for (int thread_idx = 0; thread_idx < hashcat_user->outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &hashcat_user->outer_threads[thread_idx]);
  }

  hcfree (hashcat_user->outer_threads);

  hashcat_user->outer_threads_cnt = 0;
}

static void main_cracker_starting (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  // Tell the user we're about to start

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if ((user_options->quiet == false) && (user_options->speed_only == false))
    {
      event_log_info_nn (hashcat_ctx, NULL);

      send_prompt ();
    }
  }
  else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    event_log_info (hashcat_ctx, "Starting attack in stdin mode...");
    event_log_info (hashcat_ctx, NULL);
  }
}

static void main_cracker_finished (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const hashes_t             *hashes             = hashcat_ctx->hashes;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->keyspace    == true) return;
  if (user_options->opencl_info == true) return;
  if (user_options->stdout_flag == true) return;

  // if we had a prompt, clear it

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if ((user_options->speed_only == false) && (user_options->quiet == false))
    {
      clear_prompt ();
    }
  }

  // print final status

  if (user_options->benchmark == true)
  {
    status_benchmark (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->progress_only == true)
  {
    status_progress (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->speed_only == true)
  {
    status_speed (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
  else if (user_options->machine_readable == true)
  {
    status_display (hashcat_ctx);
  }
  else
  {
    if (user_options->quiet == false)
    {
      if (hashes->digests_saved != hashes->digests_done) event_log_info (hashcat_ctx, NULL);

      status_display (hashcat_ctx);

      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_cracker_hash_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t         *outfile_ctx        = hashcat_ctx->outfile_ctx;
  status_ctx_t          *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  if (outfile_ctx->fp != NULL) return; // cracked hash was not written to an outfile

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (outfile_ctx->filename == NULL) if (user_options->quiet == false) clear_prompt ();
  }

  fwrite (buf, len,          1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (status_ctx->devices_status != STATUS_CRACKED)
    {
      if (outfile_ctx->filename == NULL) if (user_options->quiet == false) send_prompt ();
    }
  }
}

static void main_calculated_words_base (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->keyspace == false) return;

  event_log_info (hashcat_ctx, "%" PRIu64 "", status_ctx->words_base);
}

static void main_potfile_remove_parse_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Comparing hashes with potfile entries...");
}

static void main_potfile_remove_parse_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Compared hashes with potfile entries...");
}

static void main_potfile_hash_show (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp != NULL) return; // cracked hash was not written to an outfile

  fwrite (buf, len,          1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);
}

static void main_potfile_hash_left (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp != NULL) return; // cracked hash was not written to an outfile

  fwrite (buf, len,          1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);
}

static void main_potfile_num_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  const hashes_t       *hashes       = hashcat_ctx->hashes;

  if (user_options->quiet == true) return;

  const int potfile_remove_cracks = hashes->digests_done;

  if (potfile_remove_cracks > 0)
  {
    if (potfile_remove_cracks == 1)
    {
      event_log_info (hashcat_ctx, "INFO: Removed 1 hash found in potfile.");
      event_log_info (hashcat_ctx, NULL);
    }
    else
    {
      event_log_info (hashcat_ctx, "INFO: Removed %d hashes found in potfile.", potfile_remove_cracks);
      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_potfile_all_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info (hashcat_ctx, "INFO: All hashes found in potfile! Use --show to display them.");
  event_log_info (hashcat_ctx, NULL);
}

static void main_outerloop_mainscreen (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const bitmap_ctx_t   *bitmap_ctx   = hashcat_ctx->bitmap_ctx;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  /**
   * In benchmark-mode, inform user which algorithm is checked
   */

  if (user_options->benchmark == true)
  {
    if (user_options->machine_readable == false)
    {
      char *hash_type = strhashtype (hashconfig->hash_mode); // not a bug

      event_log_info (hashcat_ctx, "Hashtype: %s", hash_type);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  if (user_options->quiet == true) return;

  event_log_info (hashcat_ctx, "Hashes: %u digests; %u unique digests, %u unique salts", hashes->hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);
  event_log_info (hashcat_ctx, "Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_ctx->bitmap_bits, bitmap_ctx->bitmap_nums, bitmap_ctx->bitmap_mask, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_shift1, bitmap_ctx->bitmap_shift2);

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    event_log_info (hashcat_ctx, "Rules: %u", straight_ctx->kernel_rules_cnt);
  }

  if (user_options->quiet == false) event_log_info (hashcat_ctx, NULL);

  if (hashconfig->opti_type)
  {
    event_log_info (hashcat_ctx, "Applicable optimizers:");

    for (u32 i = 0; i < 32; i++)
    {
      const u32 opti_bit = 1u << i;

      if (hashconfig->opti_type & opti_bit) event_log_info (hashcat_ctx, "* %s", stroptitype (opti_bit));
    }
  }

  event_log_info (hashcat_ctx, NULL);

  /**
   * Watchdog and Temperature balance
   */

  if (hwmon_ctx->enabled == false && user_options->gpu_temp_disable == false)
  {
    event_log_info (hashcat_ctx, "Watchdog: Hardware monitoring interface not found on your system.");
  }

  if (hwmon_ctx->enabled == true && user_options->gpu_temp_abort > 0)
  {
    event_log_info (hashcat_ctx, "Watchdog: Temperature abort trigger set to %uc", user_options->gpu_temp_abort);
  }
  else
  {
    event_log_info (hashcat_ctx, "Watchdog: Temperature abort trigger disabled.");
  }

  if (hwmon_ctx->enabled == true && user_options->gpu_temp_retain > 0)
  {
    event_log_info (hashcat_ctx, "Watchdog: Temperature retain trigger set to %uc", user_options->gpu_temp_retain);
  }
  else
  {
    event_log_info (hashcat_ctx, "Watchdog: Temperature retain trigger disabled.");
  }

  event_log_info (hashcat_ctx, NULL);

  #if defined (DEBUG)
  if (user_options->benchmark == true) event_log_info (hashcat_ctx, "Hashmode: %d", hashconfig->hash_mode);
  #endif
}

static void main_opencl_session_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initializing device kernels and memory...");
}

static void main_opencl_session_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Initialized device kernels and memory...");
}

static void main_weak_hash_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Checking for weak hashes...");
}

static void main_weak_hash_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Checked for weak hashes...");
}

static void main_weak_hash_all_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info (hashcat_ctx, "INFO: All hashes found during weak hashes check! Use --show to display them.");
  event_log_info (hashcat_ctx, NULL);
}

static void main_bitmap_init_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Generating bitmap tables...");
}

static void main_bitmap_init_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Generated bitmap tables...");
}

static void main_set_kernel_power_final (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  clear_prompt ();

  event_log_advice (hashcat_ctx, "Approaching final keyspace - workload adjusted.");
  event_log_advice (hashcat_ctx, NULL);

  send_prompt ();
}

static void main_monitor_throttle1 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  u32 *device_id = (u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    send_prompt ();
  }
}

static void main_monitor_throttle2 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  u32 *device_id = (u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    send_prompt ();
  }
}

static void main_monitor_throttle3 (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  u32 *device_id = (u32 *) buf;

  event_log_warning (hashcat_ctx, "Driver temperature threshold met on GPU #%u. Expect reduced performance.", *device_id + 1);
  event_log_warning (hashcat_ctx, NULL);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    send_prompt ();
  }
}

static void main_monitor_performance_hint (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  if (user_options->workload_profile < 3)
  {
    event_log_advice (hashcat_ctx, "Cracking performance lower than expected? Append -w 3 to the commandline.");
    event_log_advice (hashcat_ctx, NULL);
  }
  else
  {
    event_log_advice (hashcat_ctx, "Cracking performance lower than expected?");
    event_log_advice (hashcat_ctx, NULL);
    event_log_advice (hashcat_ctx, "* Update your OpenCL runtime / driver the right way:");
    event_log_advice (hashcat_ctx, "  https://hashcat.net/faq/wrongdriver");
    event_log_advice (hashcat_ctx, NULL);
    event_log_advice (hashcat_ctx, "* Create more work items to make use of your parallelization power:");
    event_log_advice (hashcat_ctx, "  https://hashcat.net/faq/morework");
    event_log_advice (hashcat_ctx, NULL);
  }

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    send_prompt ();
  }
}

static void main_monitor_temp_abort (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  u32 *device_id = (u32 *) buf;

  event_log_error (hashcat_ctx, "Temperature limit on GPU #%u reached, aborting...", *device_id + 1);
}

static void main_monitor_runtime_limit (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    clear_prompt ();
  }

  event_log_warning (hashcat_ctx, "Runtime limit reached, aborting...");
}

static void main_monitor_status_refresh (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  const status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  if (status_ctx->accessible == false) return;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (user_options->quiet == false)
    {
      //clear_prompt ();

      event_log_info (hashcat_ctx, NULL);
      event_log_info (hashcat_ctx, NULL);
    }
  }

  status_display (hashcat_ctx);

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, NULL);

      send_prompt ();
    }
  }

  if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    if (user_options->quiet == false)
    {
      event_log_info (hashcat_ctx, NULL);
    }
  }
}

static void main_wordlist_cache_hit (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  cache_hit_t *cache_hit = (cache_hit_t *) buf;

  event_log_info (hashcat_ctx, "Dictionary cache hit:");
  event_log_info (hashcat_ctx, "* Filename..: %s", cache_hit->dictfile);
  event_log_info (hashcat_ctx, "* Passwords.: %" PRIu64, cache_hit->cached_cnt);
  event_log_info (hashcat_ctx, "* Bytes.....: %" PRId64, cache_hit->stat.st_size);
  event_log_info (hashcat_ctx, "* Keyspace..: %" PRIu64, cache_hit->keyspace);
  event_log_info (hashcat_ctx, NULL);
}

static void main_wordlist_cache_generate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  cache_generate_t *cache_generate = (cache_generate_t *) buf;

  if (cache_generate->percent < 100)
  {
    event_log_info_nn (hashcat_ctx, "Dictionary cache building %s: %" PRIu64 " bytes (%.2f%%)", cache_generate->dictfile, cache_generate->comp, cache_generate->percent);
  }
  else
  {
    char *runtime = (char *) malloc (HCBUFSIZ_TINY);

    #if defined (_WIN)
    __time64_t runtime_sec = cache_generate->runtime;
    #else
    time_t runtime_sec = cache_generate->runtime;
    #endif

    struct tm *tmp;

    #if defined (_WIN)
    tmp = _gmtime64 (&runtime_sec);
    #else
    struct tm tm;

    tmp = gmtime_r (&runtime_sec, &tm);
    #endif

    format_timer_display (tmp, runtime, HCBUFSIZ_TINY);

    event_log_info (hashcat_ctx, "Dictionary cache built:");
    event_log_info (hashcat_ctx, "* Filename..: %s", cache_generate->dictfile);
    event_log_info (hashcat_ctx, "* Passwords.: %" PRIu64, cache_generate->cnt2);
    event_log_info (hashcat_ctx, "* Bytes.....: %" PRId64, cache_generate->comp);
    event_log_info (hashcat_ctx, "* Keyspace..: %" PRIu64, cache_generate->cnt);
    event_log_info (hashcat_ctx, "* Runtime...: %s", runtime);
    event_log_info (hashcat_ctx, NULL);

    hcfree (runtime);
  }
}

static void main_hashlist_count_lines_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  char *hashfile = (char *) buf;

  event_log_info_nn (hashcat_ctx, "Counting lines in %s...", hashfile);
}

static void main_hashlist_count_lines_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  char *hashfile = (char *) buf;

  event_log_info_nn (hashcat_ctx, "Counted lines in %s...", hashfile);
}

static void main_hashlist_parse_hash (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  hashlist_parse_t *hashlist_parse = (hashlist_parse_t *) buf;

  const u32 hashes_cnt   = hashlist_parse->hashes_cnt;
  const u32 hashes_avail = hashlist_parse->hashes_avail;

  if (hashes_cnt < hashes_avail)
  {
    event_log_info_nn (hashcat_ctx, "Parsing Hashes: %u/%u (%0.2f%%)...", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100.0);
  }
  else
  {
    event_log_info_nn (hashcat_ctx, "Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, 100.0);
  }
}

static void main_hashlist_sort_hash_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorting hashes...");
}

static void main_hashlist_sort_hash_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorted hashes...");
}

static void main_hashlist_unique_hash_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Removing duplicate hashes...");
}

static void main_hashlist_unique_hash_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Removed duplicate hashes...");
}

static void main_hashlist_sort_salt_pre (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorting salts...");
}

static void main_hashlist_sort_salt_post (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return;

  event_log_info_nn (hashcat_ctx, "Sorted salts...");
}

static void event (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  switch (id)
  {
    case EVENT_BITMAP_INIT_POST:          main_bitmap_init_post          (hashcat_ctx, buf, len); break;
    case EVENT_BITMAP_INIT_PRE:           main_bitmap_init_pre           (hashcat_ctx, buf, len); break;
    case EVENT_CALCULATED_WORDS_BASE:     main_calculated_words_base     (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_FINISHED:          main_cracker_finished          (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_HASH_CRACKED:      main_cracker_hash_cracked      (hashcat_ctx, buf, len); break;
    case EVENT_CRACKER_STARTING:          main_cracker_starting          (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_COUNT_LINES_POST: main_hashlist_count_lines_post (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_COUNT_LINES_PRE:  main_hashlist_count_lines_pre  (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_PARSE_HASH:       main_hashlist_parse_hash       (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_HASH_POST:   main_hashlist_sort_hash_post   (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_HASH_PRE:    main_hashlist_sort_hash_pre    (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_SALT_POST:   main_hashlist_sort_salt_post   (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_SORT_SALT_PRE:    main_hashlist_sort_salt_pre    (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_UNIQUE_HASH_POST: main_hashlist_unique_hash_post (hashcat_ctx, buf, len); break;
    case EVENT_HASHLIST_UNIQUE_HASH_PRE:  main_hashlist_unique_hash_pre  (hashcat_ctx, buf, len); break;
    case EVENT_LOG_ERROR:                 main_log_error                 (hashcat_ctx, buf, len); break;
    case EVENT_LOG_INFO:                  main_log_info                  (hashcat_ctx, buf, len); break;
    case EVENT_LOG_WARNING:               main_log_warning               (hashcat_ctx, buf, len); break;
    case EVENT_LOG_ADVICE:                main_log_advice                (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_RUNTIME_LIMIT:     main_monitor_runtime_limit     (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_STATUS_REFRESH:    main_monitor_status_refresh    (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_TEMP_ABORT:        main_monitor_temp_abort        (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE1:         main_monitor_throttle1         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE2:         main_monitor_throttle2         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_THROTTLE3:         main_monitor_throttle3         (hashcat_ctx, buf, len); break;
    case EVENT_MONITOR_PERFORMANCE_HINT:  main_monitor_performance_hint  (hashcat_ctx, buf, len); break;
    case EVENT_OPENCL_SESSION_POST:       main_opencl_session_post       (hashcat_ctx, buf, len); break;
    case EVENT_OPENCL_SESSION_PRE:        main_opencl_session_pre        (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_FINISHED:        main_outerloop_finished        (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_MAINSCREEN:      main_outerloop_mainscreen      (hashcat_ctx, buf, len); break;
    case EVENT_OUTERLOOP_STARTING:        main_outerloop_starting        (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_ALL_CRACKED:       main_potfile_all_cracked       (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_HASH_LEFT:         main_potfile_hash_left         (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_HASH_SHOW:         main_potfile_hash_show         (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_NUM_CRACKED:       main_potfile_num_cracked       (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_REMOVE_PARSE_POST: main_potfile_remove_parse_post (hashcat_ctx, buf, len); break;
    case EVENT_POTFILE_REMOVE_PARSE_PRE:  main_potfile_remove_parse_pre  (hashcat_ctx, buf, len); break;
    case EVENT_SET_KERNEL_POWER_FINAL:    main_set_kernel_power_final    (hashcat_ctx, buf, len); break;
    case EVENT_WEAK_HASH_POST:            main_weak_hash_post            (hashcat_ctx, buf, len); break;
    case EVENT_WEAK_HASH_PRE:             main_weak_hash_pre             (hashcat_ctx, buf, len); break;
    case EVENT_WEAK_HASH_ALL_CRACKED:     main_weak_hash_all_cracked     (hashcat_ctx, buf, len); break;
    case EVENT_WORDLIST_CACHE_GENERATE:   main_wordlist_cache_generate   (hashcat_ctx, buf, len); break;
    case EVENT_WORDLIST_CACHE_HIT:        main_wordlist_cache_hit        (hashcat_ctx, buf, len); break;
  }
}

int main (int argc, char **argv)
{
  // this increases the size on windows dox boxes

  setup_console ();

  const time_t proc_start = time (NULL);

  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  const int rc_hashcat_init = hashcat_init (hashcat_ctx, event);

  if (rc_hashcat_init == -1) return -1;

  // install and shared folder need to be set to recognize "make install" use

  const char *install_folder = NULL;
  const char *shared_folder  = NULL;

  #if defined (INSTALL_FOLDER)
  install_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  shared_folder = SHARED_FOLDER;
  #endif

  // initialize the user options with some defaults (you can override them later)

  const int rc_options_init = user_options_init (hashcat_ctx);

  if (rc_options_init == -1) return -1;

  // parse commandline parameters and check them

  const int rc_options_getopt = user_options_getopt (hashcat_ctx, argc, argv);

  if (rc_options_getopt == -1) return -1;

  const int rc_options_sanity = user_options_sanity (hashcat_ctx);

  if (rc_options_sanity == -1) return -1;

  // some early exits

  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->version == true)
  {
    printf ("%s\n", VERSION_TAG);

    return 0;
  }

  if (user_options->usage == true)
  {
    usage_big_print (PROGNAME);

    return 0;
  }

  // init a hashcat session; this initializes opencl devices, hwmon, etc

  welcome_screen (hashcat_ctx, VERSION_TAG);

  const int rc_session_init = hashcat_session_init (hashcat_ctx, install_folder, shared_folder, argc, argv, COMPTIME);

  int rc_final = -1;

  if (rc_session_init == 0)
  {
    if (user_options->opencl_info == true)
    {
      // if this is just opencl_info, no need to execute some real cracking session

      opencl_info (hashcat_ctx);

      rc_final = 0;
    }
    else
    {
      // now execute hashcat

      opencl_info_compact (hashcat_ctx);

      rc_final = hashcat_session_execute (hashcat_ctx);
    }
  }

  // finish the hashcat session, this shuts down opencl devices, hwmon, etc

  hashcat_session_destroy (hashcat_ctx);

  // finished with hashcat, clean up

  const time_t proc_stop = time (NULL);

  goodbye_screen (hashcat_ctx, proc_start, proc_stop);

  hashcat_destroy (hashcat_ctx);

  free (hashcat_ctx);

  return rc_final;
}
