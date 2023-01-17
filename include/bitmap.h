/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef BITMAP_H
#define BITMAP_H

#include <string.h>

int  bitmap_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void bitmap_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // BITMAP_H
