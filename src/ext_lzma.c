/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "ext_lzma.h"

void *hc_lzma_alloc (MAYBE_UNUSED ISzAllocPtr p, size_t size)
{
  return hcmalloc (size);
}

void hc_lzma_free (MAYBE_UNUSED ISzAllocPtr p, void *address)
{
  hcfree (address);
}

int hc_lzma1_decompress (const unsigned char *in, SizeT *in_len, unsigned char *out, SizeT *out_len, const char *props)
{
  ISzAlloc hc_lzma_mem_alloc = {hc_lzma_alloc, hc_lzma_free};

  ELzmaStatus status;

  // parameters to LzmaDecode (): unsigned char *dest, size_t *destLen, const unsigned char *src,
  // size_t *srcLen, const unsigned char *props, size_t propsSize, ELzmaFinishMode finishMode, ELzmaStatus status, ISzAlloc *alloc

  return LzmaDecode (out, out_len, in, in_len, (const Byte *) props, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &hc_lzma_mem_alloc);
}

int hc_lzma2_decompress (const unsigned char *in, SizeT *in_len, unsigned char *out, SizeT *out_len, const char *props)
{
  ISzAlloc hc_lzma_mem_alloc = {hc_lzma_alloc, hc_lzma_free};

  ELzmaStatus status;

  // parameters to Lzma2Decode (): unsigned char *dest, size_t *destLen, const unsigned char *src,
  // size_t *srcLen, const unsigned char props, ELzmaFinishMode finishMode, ELzmaStatus status, ISzAlloc *alloc

  return Lzma2Decode (out, out_len, in, in_len, (Byte) props[0], LZMA_FINISH_ANY, &status, &hc_lzma_mem_alloc);
}
