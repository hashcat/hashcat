/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "induct.h"

int sort_by_mtime (const void *p1, const void *p2)
{
  const char **f1 = (const char **) p1;
  const char **f2 = (const char **) p2;

  struct stat s1; stat (*f1, &s1);
  struct stat s2; stat (*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}
