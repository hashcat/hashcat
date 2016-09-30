/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OUTFILE_CHECK_H
#define _OUTFILE_CHECK_H

#include <unistd.h>
#include <errno.h>

#define OUTFILES_DIR "outfiles"

void *thread_outfile_remove (void *p);

int outcheck_ctx_init (outcheck_ctx_t *outcheck_ctx, const user_options_t *user_options, const folder_config_t *folder_config);
void outcheck_ctx_destroy (outcheck_ctx_t *outcheck_ctx);

#endif // _OUTFILE_CHECK_H
