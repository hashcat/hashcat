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

u64 get_lowest_words_done (const restore_ctx_t *restore_ctx, const opencl_ctx_t *opencl_ctx);

void init_restore (restore_ctx_t *restore_ctx);

void read_restore (restore_ctx_t *restore_ctx);

void write_restore (restore_ctx_t *restore_ctx, opencl_ctx_t *opencl_ctx);

void cycle_restore (restore_ctx_t *restore_ctx, opencl_ctx_t *opencl_ctx);

void unlink_restore (restore_ctx_t *restore_ctx, status_ctx_t *status_ctx);

void stop_at_checkpoint (restore_ctx_t *restore_ctx, status_ctx_t *status_ctx);

int restore_ctx_init (restore_ctx_t *restore_ctx, user_options_t *user_options, const folder_config_t *folder_config, int argc, char **argv);

void restore_ctx_destroy (restore_ctx_t *restore_ctx);

#endif // _RESTORE_H
