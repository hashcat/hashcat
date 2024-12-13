/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_OUTFILE_CHECK_H
#define HC_OUTFILE_CHECK_H

#include <unistd.h>
#include <errno.h>

#define OUTFILES_DIR "outfiles"

HC_API_CALL void *thread_outfile_remove (void *p);

int  outcheck_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void outcheck_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_OUTFILE_CHECK_H
