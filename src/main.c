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
#include "hashcat.h"
#include "memory.h"   // commandline only
#include "terminal.h" // commandline only
#include "usage.h"    // commandline only
#include "logging.h"  // commandline only
#include "logfile.h"  // commandline only
#include "thread.h"   // commandline only
#include "status.h"   // commandline only

#define RUN_AS_COMMANDLINE true

#if (RUN_AS_COMMANDLINE == true)

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
  hashcat_user_t       *hashcat_user       = hashcat_ctx->hashcat_user;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

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
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // Tell the user we're about to start

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if ((user_options->quiet == false) && (user_options->status == false) && (user_options->benchmark == false))
    {
      if (user_options->quiet == false) send_prompt ();
    }
  }
  else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
  {
    if (user_options->quiet == false) log_info ("Starting attack in stdin mode...");
    if (user_options->quiet == false) log_info ("");
  }

  return 0;
}

static int event_cracker_finished (hashcat_ctx_t *hashcat_ctx)
{
  logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  logfile_sub_var_uint ("status-after-work", status_ctx->devices_status);

  return 0;
}

static int event_cracker_final_stats (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes       = hashcat_ctx->hashes;
  user_options_t *user_options = hashcat_ctx->user_options;

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
  hashes_t       *hashes       = hashcat_ctx->hashes;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (hashes == NULL) hashes = NULL;
  if (user_options == NULL) user_options = NULL;

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
    case EVENT_CRACKER_STARTING:       rc = event_cracker_starting       (hashcat_ctx); break;
    case EVENT_CRACKER_FINISHED:       rc = event_cracker_finished       (hashcat_ctx); break;
    case EVENT_CRACKER_FINAL_STATS:    rc = event_cracker_final_stats    (hashcat_ctx); break;
    case EVENT_CRACKER_HASH_CRACKED:   rc = event_cracker_hash_cracked   (hashcat_ctx); break;
  }

  return rc;
}

#else

int event (hashcat_ctx_t *hashcat_ctx, const u32 event)
{
  switch (event)
  {
  }
}

#endif

int main (int argc, char **argv)
{
  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  hashcat_ctx_init (hashcat_ctx, event);

  // initialize the session via getops for commandline use or
  // alternatively you can set the user_options directly

  int rc_hashcat = 0;

  bool run_as_commandline = RUN_AS_COMMANDLINE;

  if (run_as_commandline == true)
  {
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

    rc_hashcat = hashcat (hashcat_ctx, install_folder, shared_folder, argc, argv, COMPTIME);
  }
  else
  {
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

    rc_hashcat = hashcat (hashcat_ctx, NULL, NULL, 0, NULL, 0);
  }

  // finished with hashcat, clean up

  hashcat_ctx_destroy (hashcat_ctx);

  free (hashcat_ctx);

  return rc_hashcat;
}
