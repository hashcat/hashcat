/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_RESTORE_H
#define HC_RESTORE_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#if defined (_WIN)
#include <windows.h>
#include <psapi.h>
#endif // _WIN

// What a restore point means changed, so a file written by an older hashcat cannot be resumed by
// this one. Under -a 8 the point used to be a count of the words one device had seen rather than a
// position in the keyspace, which is short by exactly --skip. Resuming that as a position walks back
// into the range the user asked to skip and tests it.
//
// The minimum moves with it. A version that is written and never checked is decoration, and the
// failure it would let through is silent.

#define RESTORE_VERSION_MIN 720
#define RESTORE_VERSION_CUR 720

int cycle_restore (hashcat_ctx_t *hashcat_ctx);

void unlink_restore (hashcat_ctx_t *hashcat_ctx);

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv);

void restore_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_RESTORE_H
