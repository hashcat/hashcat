/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _DICTSTAT_H
#define _DICTSTAT_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <search.h>

#define MAX_DICTSTAT 10000

typedef struct
{
  u64 cnt;

  #if defined (_POSIX)
  struct stat stat;
  #endif

  #if defined (_WIN)
  struct __stat64 stat;
  #endif

} dictstat_t;

typedef struct
{
  char *filename;

  dictstat_t *base;

  #if defined (_POSIX)
  size_t cnt;
  #else
  uint   cnt;
  #endif

} dictstat_ctx_t;

int sort_by_dictstat (const void *s1, const void *s2);

void dictstat_init    (dictstat_ctx_t *dictstat_ctx, char *profile_dir);
void dictstat_destroy (dictstat_ctx_t *dictstat_ctx);
void dictstat_read    (dictstat_ctx_t *dictstat_ctx);
int  dictstat_write   (dictstat_ctx_t *dictstat_ctx);
u64  dictstat_find    (dictstat_ctx_t *dictstat_ctx, dictstat_t *d);
void dictstat_append  (dictstat_ctx_t *dictstat_ctx, dictstat_t *d);

#endif // _DICTSTAT_H
