/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASHCAT_H
#define _HASHCAT_H

int   hashcat_init               (hashcat_ctx_t *hashcat_ctx, void (*event) (const u32, struct hashcat_ctx *, const void *, const size_t));
void  hashcat_destroy            (hashcat_ctx_t *hashcat_ctx);

int   hashcat_session_init       (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, int argc, char **argv, const int comptime);
int   hashcat_session_execute    (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_pause      (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_resume     (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_bypass     (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_checkpoint (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_finish     (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_quit       (hashcat_ctx_t *hashcat_ctx);
int   hashcat_session_destroy    (hashcat_ctx_t *hashcat_ctx);

char *hashcat_get_log            (hashcat_ctx_t *hashcat_ctx);
int   hashcat_get_status         (hashcat_ctx_t *hashcat_ctx, hashcat_status_t *hashcat_status);

#endif // _HASHCAT_H
