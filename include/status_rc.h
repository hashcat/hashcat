/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_STATUS_RC_H
#define HC_STATUS_RC_H

HC_PLUGIN_API void status_set_rc_error   (hashcat_ctx_t *hashcat_ctx, const rc_final_t rc_error);

// Returns true for the first error that stops the session. A completed crack is kept.
HC_PLUGIN_API bool status_abort_with_error (hashcat_ctx_t *hashcat_ctx, const rc_final_t rc_error);

HC_API rc_final_t  status_get_rc_error   (const hashcat_ctx_t *hashcat_ctx);
void               status_clear_rc_error (hashcat_ctx_t *hashcat_ctx);

#endif // HC_STATUS_RC_H
