/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MEMORY_H
#define HC_MEMORY_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MSG_ENOMEM "Insufficient memory available"

void *hccalloc  (const size_t nmemb, const size_t sz);
void *hcmalloc  (const size_t sz);
void *hcrealloc (void *ptr, const size_t oldsz, const size_t addsz);
char *hcstrdup  (const char *s);
void  hcfree    (void *ptr);

#endif // HC_MEMORY_H
