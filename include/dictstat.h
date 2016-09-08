/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _DICTSTAT_H
#define _DICTSTAT_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

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

int sort_by_dictstat (const void *s1, const void *s2);

#endif // _DICTSTAT_H
