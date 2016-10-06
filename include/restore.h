/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _RESTORE_H
#define _RESTORE_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#if defined (_POSIX)
#include <sys/types.h>
#include <sys/stat.h>
#endif // _POSIX

#if defined (_WIN)
#include <windows.h>
#include <psapi.h>
#endif // _WIN

#define RESTORE_VERSION_MIN 320
#define RESTORE_VERSION_CUR 320

u64 get_lowest_words_done (hashcat_ctx_t *hashcat_ctx);

void init_restore (hashcat_ctx_t *hashcat_ctx);

void read_restore (hashcat_ctx_t *hashcat_ctx);

void write_restore (hashcat_ctx_t *hashcat_ctx);

void cycle_restore (hashcat_ctx_t *hashcat_ctx);

void unlink_restore (hashcat_ctx_t *hashcat_ctx);

void stop_at_checkpoint (hashcat_ctx_t *hashcat_ctx);

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv);

void restore_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _RESTORE_H
