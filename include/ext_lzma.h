/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_LZMA_H
#define _EXT_LZMA_H

#include <LzmaDec.h>
#include <Lzma2Dec.h>

#include "minizip/unzip.h"

int hc_lzma1_decompress (const unsigned char *in, SizeT *in_len, unsigned char *out, SizeT *out_len, const char *props);
int hc_lzma2_decompress (const unsigned char *in, SizeT *in_len, unsigned char *out, SizeT *out_len, const char *props);

void *hc_lzma_alloc (MAYBE_UNUSED ISzAllocPtr p, size_t size);
void  hc_lzma_free  (MAYBE_UNUSED ISzAllocPtr p, void *address);

#endif // _EXT_LZMA_H
