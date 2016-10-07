/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "common.h"
#include "types.h"
#include "user_options.h"
#include "usage.h"
#include "hashcat.h"

#define RUN_AS_COMMANDLINE

#if defined (RUN_AS_COMMANDLINE)

#include "memory.h"
#include "terminal.h"
#include "logging.h"
#include "logfile.h"
#include "thread.h"
#include "status.h"
#include "interface.h"

static int event_welcome_screen (hashcat_ctx_t *hashcat_ctx)
{
  // sets dos window size (windows only)

  setup_console ();

  // Inform user things getting started

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  welcome_screen (hashcat_ctx, status_ctx->proc_start, VERSION_TAG);

  return 0;
}

static int event_goodbye_screen (hashcat_ctx_t *hashcat_ctx)
{
  // Inform user we're done

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  goodbye_screen (hashcat_ctx, status_ctx->proc_start, status_ctx->proc_stop);

  return 0;
}

static int event_logfile_top_initialize (hashcat_ctx_t *hashcat_ctx)
{
  const logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  // logfile init

  const int rc_logfile_init = logfile_init (hashcat_ctx);

  if (rc_logfile_init == -1) return -1;

  logfile_generate_topid (hashcat_ctx);

  logfile_top_msg ("START");

  // add all user options to logfile in case we want to debug some user session

  user_options_logger (hashcat_ctx);

  return 0;
}

static int event_logfile_top_finalize (hashcat_ctx_t *hashcat_ctx)
{
  const logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  logfile_top_msg ("STOP");

  logfile_destroy (hashcat_ctx);

  return 0;
}

static int event_logfile_sub_initialize (hashcat_ctx_t *hashcat_ctx)
{
  const logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  logfile_generate_subid (hashcat_ctx);

  logfile_sub_msg ("START");

  return 0;
}

static int event_logfile_sub_finalize (hashcat_ctx_t *hashcat_ctx)
{
  const logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  logfile_sub_msg ("STOP");

  return 0;
}

static int event_outerloop_starting (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  /**
   * keypress thread
   */

  hashcat_user->outer_threads_cnt = 0;

  hashcat_user->outer_threads = (hc_thread_t *) mycalloc (2, sizeof (hc_thread_t));

  status_ctx->shutdown_outer = false;

  if (user_options->keyspace == false && user_options->benchmark == false && user_options->stdout_flag == false)
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      // see thread_keypress() how to access status information

      hc_thread_create (hashcat_user->outer_threads[hashcat_user->outer_threads_cnt], thread_keypress, hashcat_ctx);

      hashcat_user->outer_threads_cnt++;
    }
  }

  return 0;
}

static int event_outerloop_finished (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_user_t *hashcat_user = hashcat_ctx->hashcat_user;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  // wait for outer threads

  status_ctx->shutdown_outer = true;

  for (int thread_idx = 0; thread_idx < hashcat_user->outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &hashcat_user->outer_threads[thread_idx]);
  }

  myfree (hashcat_user->outer_threads);

  hashcat_user->outer_threads_cnt = 0;

  return 0;
}

static int event_cracker_starting (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->quiet == true) return 0;

  // Tell the user we're about to start

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if ((user_options->quiet == false) && (user_options->status == false) && (user_options->benchmark == false))
    {
       send_prompt ();
    }
  }
  else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    log_info ("Starting attack in stdin mode...");
    log_info ("");
  }

  return 0;
}

static int event_cracker_finished (hashcat_ctx_t *hashcat_ctx)
{
  const logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  logfile_sub_var_uint ("status-after-work", status_ctx->devices_status);

  return 0;
}

static int event_cracker_final_stats (hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  // print final status

  if (user_options->benchmark == true)
  {
    status_benchmark (hashcat_ctx);

    if (user_options->machine_readable == false)
    {
      log_info ("");
    }
  }
  else
  {
    if (user_options->quiet == false)
    {
      clear_prompt ();

      if (hashes->digests_saved != hashes->digests_done) log_info ("");

      status_display (hashcat_ctx);

      log_info ("");
    }
    else
    {
      if (user_options->status == true)
      {
        status_display (hashcat_ctx);

        log_info ("");
      }
    }
  }

  return 0;
}

static int event_cracker_hash_cracked (hashcat_ctx_t *hashcat_ctx)
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (hashes == NULL) hashes = NULL;
  if (user_options == NULL) user_options = NULL;

  return 0;
}

static int event_calculated_words_base (hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->keyspace == true)
  {
    log_info ("%" PRIu64 "", status_ctx->words_base);
  }

  return 0;
}

static int event_potfile_remove_parse (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return 0;

  log_info_nn ("Comparing hashes with potfile entries...");

  return 0;
}

static int event_potfile_num_cracked (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  const hashes_t       *hashes       = hashcat_ctx->hashes;

  if (user_options->quiet == true) return 0;

  const int potfile_remove_cracks = hashes->digests_done;

  if (potfile_remove_cracks > 0)
  {
    if (potfile_remove_cracks == 1)
    {
      log_info ("INFO: Removed 1 hash found in potfile");
      log_info ("");
    }
    else
    {
      log_info ("INFO: Removed %d hashes found in potfile", potfile_remove_cracks);
      log_info ("");
    }
  }

  return 0;
}

static int event_potfile_all_cracked (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return 0;

  log_info ("INFO: All hashes found in potfile! You can use --show to display them.");
  log_info ("");
  log_info ("INFO: No more hashes left to crack, exiting...");
  log_info ("");

  return 0;
}

static int event_outerloop_mainscreen (hashcat_ctx_t *hashcat_ctx)
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

      log_info ("Hashtype: %s", hash_type);
      log_info ("");
    }
  }

  if (user_options->quiet == true) return 0;

  log_info ("Hashes: %u digests; %u unique digests, %u unique salts", hashes->hashes_cnt_orig, hashes->digests_cnt, hashes->salts_cnt);

  log_info ("Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_ctx->bitmap_bits, bitmap_ctx->bitmap_nums, bitmap_ctx->bitmap_mask, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_shift1, bitmap_ctx->bitmap_shift2);

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    log_info ("Rules: %u", straight_ctx->kernel_rules_cnt);
  }

  if (user_options->quiet == false) log_info ("");

  if (hashconfig->opti_type)
  {
    log_info ("Applicable Optimizers:");

    for (u32 i = 0; i < 32; i++)
    {
      const u32 opti_bit = 1u << i;

      if (hashconfig->opti_type & opti_bit) log_info ("* %s", stroptitype (opti_bit));
    }
  }

  log_info ("");

  /**
   * Watchdog and Temperature balance
   */

  if (hwmon_ctx->enabled == false && user_options->gpu_temp_disable == false)
  {
    log_info ("Watchdog: Hardware Monitoring Interface not found on your system");
  }

  if (hwmon_ctx->enabled == true && user_options->gpu_temp_abort > 0)
  {
    log_info ("Watchdog: Temperature abort trigger set to %uc", user_options->gpu_temp_abort);
  }
  else
  {
    log_info ("Watchdog: Temperature abort trigger disabled");
  }

  if (hwmon_ctx->enabled == true && user_options->gpu_temp_retain > 0)
  {
    log_info ("Watchdog: Temperature retain trigger set to %uc", user_options->gpu_temp_retain);
  }
  else
  {
    log_info ("Watchdog: Temperature retain trigger disabled");
  }

  log_info ("");

  #if defined (DEBUG)
  if (user_options->benchmark == true) log_info ("Hashmode: %d", hashconfig->hash_mode);
  #endif

  return 0;
}

static int event_opencl_session_pre (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return 0;

  log_info_nn ("Initializing device kernels and memory...");

  return 0;
}

static int event_opencl_session_post (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return 0;

  log_info_nn ("");

  return 0;
}

static int event_outerloop_weak_hash (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->quiet == true) return 0;

  log_info_nn ("Checking for weak hashes...");

  return 0;
}

int event (hashcat_ctx_t *hashcat_ctx, const u32 event)
{
  int rc = 0;

  switch (event)
  {
    case EVENT_WELCOME_SCREEN:         rc = event_welcome_screen         (hashcat_ctx); break;
    case EVENT_GOODBYE_SCREEN:         rc = event_goodbye_screen         (hashcat_ctx); break;
    case EVENT_LOGFILE_TOP_INITIALIZE: rc = event_logfile_top_initialize (hashcat_ctx); break;
    case EVENT_LOGFILE_TOP_FINALIZE:   rc = event_logfile_top_finalize   (hashcat_ctx); break;
    case EVENT_LOGFILE_SUB_INITIALIZE: rc = event_logfile_sub_initialize (hashcat_ctx); break;
    case EVENT_LOGFILE_SUB_FINALIZE:   rc = event_logfile_sub_finalize   (hashcat_ctx); break;
    case EVENT_OUTERLOOP_STARTING:     rc = event_outerloop_starting     (hashcat_ctx); break;
    case EVENT_OUTERLOOP_FINISHED:     rc = event_outerloop_finished     (hashcat_ctx); break;
    case EVENT_OUTERLOOP_MAINSCREEN:   rc = event_outerloop_mainscreen   (hashcat_ctx); break;
    case EVENT_OUTERLOOP_WEAK_HASH:    rc = event_outerloop_weak_hash    (hashcat_ctx); break;
    case EVENT_CRACKER_STARTING:       rc = event_cracker_starting       (hashcat_ctx); break;
    case EVENT_CRACKER_FINISHED:       rc = event_cracker_finished       (hashcat_ctx); break;
    case EVENT_CRACKER_FINAL_STATS:    rc = event_cracker_final_stats    (hashcat_ctx); break;
    case EVENT_CRACKER_HASH_CRACKED:   rc = event_cracker_hash_cracked   (hashcat_ctx); break;
    case EVENT_CALCULATED_WORDS_BASE:  rc = event_calculated_words_base  (hashcat_ctx); break;
    case EVENT_POTFILE_REMOVE_PARSE:   rc = event_potfile_remove_parse   (hashcat_ctx); break;
    case EVENT_POTFILE_NUM_CRACKED:    rc = event_potfile_num_cracked    (hashcat_ctx); break;
    case EVENT_POTFILE_ALL_CRACKED:    rc = event_potfile_all_cracked    (hashcat_ctx); break;
    case EVENT_OPENCL_SESSION_PRE:     rc = event_opencl_session_pre     (hashcat_ctx); break;
    case EVENT_OPENCL_SESSION_POST:    rc = event_opencl_session_post    (hashcat_ctx); break;
  }

  return rc;
}

#else

int event (hashcat_ctx_t *hashcat_ctx, const u32 event)
{
  if (hashcat_ctx == NULL) hashcat_ctx = NULL;

  int rc = 0;

  switch (event)
  {
  }

  return rc;
}

#endif

int main (int argc, char **argv)
{
  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  hashcat_ctx_init (hashcat_ctx, event);

  // initialize the session via getops for commandline use or
  // alternatively you can set the user_options directly

  #if defined (RUN_AS_COMMANDLINE)

  // install and shared folder need to be set to recognize "make install" use

  char *install_folder = NULL;
  char *shared_folder  = NULL;

  #if defined (INSTALL_FOLDER)
  install_folder = INSTALL_FOLDER;
  #endif

  #if defined (SHARED_FOLDER)
  shared_folder = SHARED_FOLDER;
  #endif

  // initialize the user options with some defaults (you can override them later)

  user_options_init (hashcat_ctx);

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

  // now run hashcat

  const int rc_hashcat = hashcat (hashcat_ctx, install_folder, shared_folder, argc, argv, COMPTIME);

  #else

  // this is a bit ugly, but it's the example you're looking for

  char *hash = "8743b52063cd84097a65d1633f5c74f5";
  char *mask = "?l?l?l?l?l?l?l";

  char *hc_argv[] = { hash, mask, NULL };

  // initialize the user options with some defaults (you can override them later)

  user_options_init (hashcat_ctx);

  // your own stuff

  user_options_t *user_options = hashcat_ctx->user_options;

  user_options->hc_argv           = hc_argv;
  user_options->hc_argc           = 2;
  user_options->quiet             = true;
  user_options->potfile_disable   = true;
  user_options->attack_mode       = ATTACK_MODE_BF; // this is -a 3
  user_options->hash_mode         = 0;              // MD5
  user_options->workload_profile  = 3;

  // now run hashcat

  const int rc_hashcat = hashcat (hashcat_ctx, NULL, NULL, 0, NULL, 0);

  #endif

  // finished with hashcat, clean up

  hashcat_ctx_destroy (hashcat_ctx);

  free (hashcat_ctx);

  return rc_hashcat;
}
