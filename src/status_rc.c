/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// What an exit -1 becomes: -2 when the attack command is wrong, -12 when a file it names is unusable,
// -13 when a bridge or the plugin behind it failed.
// 0 means nothing was recorded, which is also what a zero-filled status_ctx holds.
//
// It has a translation unit to itself because the wordlist feed calls the setter. Under SHARED=0 a
// plugin links the core as an archive, and a reference pulls in the member that answers it, so a
// setter in status.c would pull all of status.c into the feed.

#include "common.h"
#include "types.h"
#include "status_rc.h"
#include "thread.h"

// The first code is kept. A later call that names a different one leaves the run with more than one
// cause, which -1 reports. Anything other than -2, -12 and -13 is not this function's to record.

HC_PLUGIN_API void status_set_rc_error (hashcat_ctx_t *hashcat_ctx, const rc_final_t rc_error)
{
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // mask_css_parse () is reached by callers that build only part of a context, the mask fuzzer one of them

  if (status_ctx == NULL) return;

  if ((rc_error != RC_FINAL_ERROR_COMMAND) && (rc_error != RC_FINAL_ERROR_TASK) && (rc_error != RC_FINAL_ERROR_BRIDGE)) return;

  if (status_ctx->rc_error == RC_FINAL_OK)
  {
    status_ctx->rc_error = rc_error;
  }
  else if (status_ctx->rc_error != rc_error)
  {
    status_ctx->rc_error = RC_FINAL_ERROR;
  }
}

HC_PLUGIN_API bool status_abort_with_error (hashcat_ctx_t *hashcat_ctx, const rc_final_t rc_error)
{
  status_ctx_t *status_ctx = NULL;

  status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx == NULL) return false;
  if ((rc_error != RC_FINAL_ERROR_COMMAND) && (rc_error != RC_FINAL_ERROR_TASK) && (rc_error != RC_FINAL_ERROR_BRIDGE)) return false;

  hc_thread_mutex_lock (status_ctx->mux_display);

  if (status_ctx->devices_status == STATUS_CRACKED)
  {
    hc_thread_mutex_unlock (status_ctx->mux_display);

    return false;
  }

  const bool first = (status_ctx->rc_error == RC_FINAL_OK);

  status_set_rc_error (hashcat_ctx, rc_error);

  status_ctx->run_main_level1   = false;
  status_ctx->run_main_level2   = false;
  status_ctx->run_main_level3   = false;
  status_ctx->run_thread_level1 = false;
  status_ctx->run_thread_level2 = false;
  status_ctx->devices_status    = STATUS_ERROR;

  hc_thread_mutex_unlock (status_ctx->mux_display);

  return first;
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
