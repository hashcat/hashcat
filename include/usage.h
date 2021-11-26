/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _USAGE_H
#define _USAGE_H

#include <stdio.h>
#include <string.h>

#if defined (_WIN)
// for getch()
#include <conio.h>
#endif

typedef struct usage_sort
{
  u32   hash_mode;
  char *hash_name;
  u32   hash_category;

} usage_sort_t;

void usage_mini_print (const char *progname);
void usage_big_print  (hashcat_ctx_t *hashcat_ctx);
int sort_by_usage (const void *p1, const void *p2);

#endif // _USAGE_H
