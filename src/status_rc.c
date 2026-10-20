/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What an exit -1 becomes: -2 when the attack command is wrong, -12 when a file it names is unusable.
// 0 means nothing was recorded, which is also what a zero-filled status_ctx holds.
//
// It has a translation unit to itself because the wordlist feed calls the setter. Under SHARED=0 a
// plugin links the core as an archive, and a reference pulls in the member that answers it, so a
// setter in status.c would pull all of status.c into the feed.

#include "common.h"
#include "types.h"
#include "status_rc.h"

// The first code is kept. A later call that names the other one leaves the run with more than one
// cause, which -1 reports. Anything other than -2 and -12 is not this function's to record.

HC_PLUGIN_API void status_set_rc_error (hashcat_ctx_t *hashcat_ctx, const rc_final_t rc_error)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // mask_css_parse () is reached by callers that build only part of a context, the mask fuzzer one of them

  if (status_ctx == NULL) return;

  if ((rc_error != RC_FINAL_ERROR_COMMAND) && (rc_error != RC_FINAL_ERROR_TASK)) return;

  if (status_ctx->rc_error == RC_FINAL_OK)
  {
    status_ctx->rc_error = rc_error;
  }
  else if (status_ctx->rc_error != rc_error)
  {
    status_ctx->rc_error = RC_FINAL_ERROR;
  }
}

HC_API rc_final_t status_get_rc_error (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  const rc_final_t rc_error = status_ctx->rc_error;

  return rc_error;
}

void status_clear_rc_error (hashcat_ctx_t *hashcat_ctx)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  status_ctx->rc_error = RC_FINAL_OK;
}
