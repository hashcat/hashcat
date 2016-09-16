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

#define RESTORE             0
#define RESTORE_TIMER       60
#define RESTORE_DISABLE     0

#define RESTORE_VERSION_MIN 320
#define RESTORE_VERSION_CUR 320

#define SKIP                0
#define LIMIT               0
#define KEYSPACE            0

u64 get_lowest_words_done (opencl_ctx_t *opencl_ctx);

restore_data_t *init_restore (int argc, char **argv);

void read_restore (const char *eff_restore_file, restore_data_t *rd);

void write_restore (opencl_ctx_t *opencl_ctx, const char *new_restore_file, restore_data_t *rd);

void cycle_restore (opencl_ctx_t *opencl_ctx);

void check_checkpoint (opencl_ctx_t *opencl_ctx);

void stop_at_checkpoint (opencl_ctx_t *opencl_ctx);

#endif // _RESTORE_H
