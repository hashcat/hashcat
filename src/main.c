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
#include "terminal.h" // commandline only
#include "usage.h"    // commandline only

#define RUN_AS_COMMANDLINE true

int main (int argc, char **argv)
{
  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  hashcat_ctx_init (hashcat_ctx);

  // initialize the user options with some defaults (you can override them)

  user_options_t *user_options = hashcat_ctx->user_options;

  user_options_init (user_options);

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

    // sets dos window size (windows only)

    const int rc_console = setup_console ();

    if (rc_console == -1) return -1;

    // parse commandline parameters and check them

    const int rc_options_getopt = user_options_getopt (user_options, argc, argv);

    if (rc_options_getopt == -1) return -1;

    const int rc_options_sanity = user_options_sanity (user_options);

    if (rc_options_sanity == -1) return -1;

    // some early exits

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

    // Inform user things getting started

    time_t proc_start;

    time (&proc_start);

    welcome_screen (user_options, proc_start, VERSION_TAG);

    // now run hashcat

    rc_hashcat = hashcat (hashcat_ctx, install_folder, shared_folder, argc, argv, COMPTIME);

    // Inform user we're done

    time_t proc_stop;

    time (&proc_stop);

    goodbye_screen (user_options, proc_start, proc_stop);
  }
  else
  {
    // this is a bit ugly, but it's the example you're looking for

    char *hash = "8743b52063cd84097a65d1633f5c74f5";
    char *mask = "?l?l?l?l?l?l?l";

    char *hc_argv[] = { hash, mask, NULL };

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