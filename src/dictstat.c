/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "dictstat.h"

int sort_by_dictstat (const void *s1, const void *s2)
{
  dictstat_t *d1 = (dictstat_t *) s1;
  dictstat_t *d2 = (dictstat_t *) s2;

  #if defined (__linux__)
  d2->stat.st_atim = d1->stat.st_atim;
  #else
  d2->stat.st_atime = d1->stat.st_atime;
  #endif

  return memcmp (&d1->stat, &d2->stat, sizeof (struct stat));
}
