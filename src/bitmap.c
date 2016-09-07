/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "bitmap.h"

int sort_by_bitmap (const void *p1, const void *p2)
{
  const bitmap_result_t *b1 = (const bitmap_result_t *) p1;
  const bitmap_result_t *b2 = (const bitmap_result_t *) p2;

  return b1->collisions - b2->collisions;
}

uint generate_bitmaps (const uint digests_cnt, const uint dgst_size, const uint dgst_shifts, char *digests_buf_ptr, const uint dgst_pos0, const uint dgst_pos1, const uint dgst_pos2, const uint dgst_pos3, const uint bitmap_mask, const uint bitmap_size, uint *bitmap_a, uint *bitmap_b, uint *bitmap_c, uint *bitmap_d, const u64 collisions_max)
{
  u64 collisions = 0;

  memset (bitmap_a, 0, bitmap_size);
  memset (bitmap_b, 0, bitmap_size);
  memset (bitmap_c, 0, bitmap_size);
  memset (bitmap_d, 0, bitmap_size);

  for (uint i = 0; i < digests_cnt; i++)
  {
    uint *digest_ptr = (uint *) digests_buf_ptr;

    digests_buf_ptr += dgst_size;

    const uint val0 = 1u << (digest_ptr[dgst_pos0] & 0x1f);
    const uint val1 = 1u << (digest_ptr[dgst_pos1] & 0x1f);
    const uint val2 = 1u << (digest_ptr[dgst_pos2] & 0x1f);
    const uint val3 = 1u << (digest_ptr[dgst_pos3] & 0x1f);

    const uint idx0 = (digest_ptr[dgst_pos0] >> dgst_shifts) & bitmap_mask;
    const uint idx1 = (digest_ptr[dgst_pos1] >> dgst_shifts) & bitmap_mask;
    const uint idx2 = (digest_ptr[dgst_pos2] >> dgst_shifts) & bitmap_mask;
    const uint idx3 = (digest_ptr[dgst_pos3] >> dgst_shifts) & bitmap_mask;

    if (bitmap_a[idx0] & val0) collisions++;
    if (bitmap_b[idx1] & val1) collisions++;
    if (bitmap_c[idx2] & val2) collisions++;
    if (bitmap_d[idx3] & val3) collisions++;

    bitmap_a[idx0] |= val0;
    bitmap_b[idx1] |= val1;
    bitmap_c[idx2] |= val2;
    bitmap_d[idx3] |= val3;

    if (collisions >= collisions_max) return 0x7fffffff;
  }

  return collisions;
}
