/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdio.h>
#include <assert.h>

#include "common.h"
#include "types.h"
#include "memory.h"
#include "user_options.h"
#include "hashcat.h"

static void main_cracker_hash_cracked (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const void *buf, MAYBE_UNUSED const size_t len)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp != NULL) return; // cracked hash was not written to an outfile

  fwrite (buf, len,          1, stdout);
  fwrite (EOL, strlen (EOL), 1, stdout);
}

void event (const u32 id, hashcat_ctx_t *hashcat_ctx, const void *buf, const size_t len)
{
  switch (id)
  {
    case EVENT_CRACKER_HASH_CRACKED: main_cracker_hash_cracked (hashcat_ctx, buf, len); break;
  }
}

int main ()
{
  // hashcat main context

  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  assert (hashcat_ctx);

  const int rc_hashcat_init = hashcat_init (hashcat_ctx, event);

  if (rc_hashcat_init == -1) return -1;

  // this is a bit ugly, but it's the example you're looking for

  char *hash = "8743b52063cd84097a65d1633f5c74f5";
  char *mask = "?l?l?l?l?l?l?l";

  char *hc_argv[] = { hash, mask, NULL };

  // initialize the user options with some defaults (you can override them later)

  const int rc_options_init = user_options_init (hashcat_ctx);

  if (rc_options_init == -1) return -1;

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

  const int rc_hashcat = hashcat_session_run (hashcat_ctx, NULL, NULL, 0, NULL, 0);

  if (rc_hashcat == 0)
  {
    hashcat_status_t hashcat_status;

    const int rc = hashcat_get_status (hashcat_ctx, &hashcat_status);

    printf ("Session: %s\n", hashcat_status.session);
    printf ("Status: %s\n",  hashcat_status.status);

    if (rc == 0)
    {
      printf ("%d\n", hashcat_status.device_info_cnt);

    }

  }
  else if (rc_hashcat == -1)
  {
    char *msg = hashcat_get_log (hashcat_ctx);

    fprintf (stderr, "%s\n", msg);
  }

  hashcat_destroy (hashcat_ctx);

  free (hashcat_ctx);

  return 0;
}
