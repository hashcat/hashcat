/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _RESTORE_H
#define _RESTORE_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#if defined (__unix__)
#include <sys/types.h>
#include <sys/stat.h>
#endif // __unix__

#if defined (__WIN32__)
#include <windows.h>
#include <psapi.h>
#endif // __WIN32__

#define RESTORE_VERSION_MIN 340
#define RESTORE_VERSION_CUR 340

int cycle_restore (hashcat_ctx_t *hashcat_ctx);

void unlink_restore (hashcat_ctx_t *hashcat_ctx);

int restore_ctx_init (hashcat_ctx_t *hashcat_ctx, int argc, char **argv);

void restore_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // _RESTORE_H
