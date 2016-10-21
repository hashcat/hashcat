/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _MEMORY_H
#define _MEMORY_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MSG_ENOMEM "Insufficient memory available"

#define VERIFY_PTR(v) if ((v) == NULL) return -1;

void *hccalloc  (hashcat_ctx_t *hashcat_ctx, const size_t nmemb, const size_t sz);
void *hcmalloc  (hashcat_ctx_t *hashcat_ctx, const size_t sz);
void *hcrealloc (hashcat_ctx_t *hashcat_ctx, void *ptr, const size_t oldsz, const size_t addsz);
char *hcstrdup  (hashcat_ctx_t *hashcat_ctx, const char *s);
void  hcfree    (void *ptr);

#endif // _MEMORY_H
