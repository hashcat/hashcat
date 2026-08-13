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

HC_API void *hccalloc                (const size_t nmemb, const size_t sz);
HC_API void *hcmalloc                (const size_t sz);
HC_API void *hcrealloc               (void *ptr, const size_t oldsz, const size_t addsz);
HC_API char *hcstrdup                (const char *s);
HC_API void  hcfree                  (void *ptr);

HC_PLUGIN_API void *hc_alloc_aligned        (size_t alignment, size_t size);
HC_PLUGIN_API void  hc_free_aligned         (void **ptr);

HC_PLUGIN_API void *hcmalloc_bridge_aligned (const size_t sz, const int align);
HC_PLUGIN_API void  hcfree_bridge_aligned   (void *ptr);

#endif // HC_MEMORY_H
