/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_LOCKING_H
#define HC_LOCKING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#if defined (_WIN)
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

int hc_lockfile   (HCFILE *fp);
int hc_unlockfile (HCFILE *fp);

// The same two calls for a caller that has nowhere to hand a failure back to. They warn through
// event_log_error () and carry on, and they warn once per file rather than once per attempt. The
// flag belongs to the caller rather than to the HCFILE. src/locking.c says why.

void hc_lockfile_warn   (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *filename, bool *warned);
void hc_unlockfile_warn (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *filename, bool *warned);

#endif // HC_LOCKING_H
