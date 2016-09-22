/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BITMAP_H
#define _BITMAP_H

#include <string.h>

int sort_by_bitmap (const void *s1, const void *s2);

void bitmap_ctx_init (bitmap_ctx_t *bitmap_ctx, const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes);
void bitmap_ctx_destroy (bitmap_ctx_t *bitmap_ctx);

#endif // _BITMAP_H
