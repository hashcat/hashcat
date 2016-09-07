/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _BITMAP_H
#define _BITMAP_H

#include <string.h>

#define BITMAP_MIN 16
#define BITMAP_MAX 24

typedef struct
{
  uint bitmap_shift;
  uint collisions;

} bitmap_result_t;

int sort_by_bitmap (const void *s1, const void *s2);

uint generate_bitmaps (const uint digests_cnt, const uint dgst_size, const uint dgst_shifts, char *digests_buf_ptr, const uint dgst_pos0, const uint dgst_pos1, const uint dgst_pos2, const uint dgst_pos3, const uint bitmap_mask, const uint bitmap_size, uint *bitmap_a, uint *bitmap_b, uint *bitmap_c, uint *bitmap_d, const u64 collisions_max);

#endif // _BITMAP_H
