/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

/**
 * pure scalar functions
 */

inline int hash_comp (const u32 d1[4], __global u32 *d2)
{
  if (d1[3] > d2[DGST_R3]) return ( 1);
  if (d1[3] < d2[DGST_R3]) return (-1);
  if (d1[2] > d2[DGST_R2]) return ( 1);
  if (d1[2] < d2[DGST_R2]) return (-1);
  if (d1[1] > d2[DGST_R1]) return ( 1);
  if (d1[1] < d2[DGST_R1]) return (-1);
  if (d1[0] > d2[DGST_R0]) return ( 1);
  if (d1[0] < d2[DGST_R0]) return (-1);

  return (0);
}

inline int find_hash (const u32 digest[4], const u32 digests_cnt, __global digest_t *digests_buf)
{
  for (u32 l = 0, r = digests_cnt; r; r >>= 1)
  {
    const u32 m = r >> 1;

    const u32 c = l + m;

    const int cmp = hash_comp (digest, digests_buf[c].digest_buf);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return (c);
  }

  return (-1);
}

inline u32 check_bitmap (__global u32 *bitmap, const u32 bitmap_mask, const u32 bitmap_shift, const u32 digest)
{
  return (bitmap[(digest >> bitmap_shift) & bitmap_mask] & (1 << (digest & 0x1f)));
}

inline u32 check (const u32 digest[2], __global u32 *bitmap_s1_a, __global u32 *bitmap_s1_b, __global u32 *bitmap_s1_c, __global u32 *bitmap_s1_d, __global u32 *bitmap_s2_a, __global u32 *bitmap_s2_b, __global u32 *bitmap_s2_c, __global u32 *bitmap_s2_d, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2)
{
  if (check_bitmap (bitmap_s1_a, bitmap_mask, bitmap_shift1, digest[0]) == 0) return (0);
  if (check_bitmap (bitmap_s1_b, bitmap_mask, bitmap_shift1, digest[1]) == 0) return (0);
  if (check_bitmap (bitmap_s1_c, bitmap_mask, bitmap_shift1, digest[2]) == 0) return (0);
  if (check_bitmap (bitmap_s1_d, bitmap_mask, bitmap_shift1, digest[3]) == 0) return (0);

  if (check_bitmap (bitmap_s2_a, bitmap_mask, bitmap_shift2, digest[0]) == 0) return (0);
  if (check_bitmap (bitmap_s2_b, bitmap_mask, bitmap_shift2, digest[1]) == 0) return (0);
  if (check_bitmap (bitmap_s2_c, bitmap_mask, bitmap_shift2, digest[2]) == 0) return (0);
  if (check_bitmap (bitmap_s2_d, bitmap_mask, bitmap_shift2, digest[3]) == 0) return (0);

  return (1);
}

inline void mark_hash (__global plain_t *plains_buf, __global u32 *d_result, const int salt_pos, const int digest_pos, const int hash_pos, const u32 gid, const u32 il_pos)
{
  const u32 idx = atomic_inc (d_result);

  plains_buf[idx].salt_pos    = salt_pos;
  plains_buf[idx].digest_pos  = digest_pos; // relative
  plains_buf[idx].hash_pos    = hash_pos;   // absolute
  plains_buf[idx].gidvid      = gid;
  plains_buf[idx].il_pos      = il_pos;
}

/**
 * vector functions
 */

inline void truncate_block (u32x w[4], const u32 len)
{
  switch (len)
  {
    case  0:  w[0] &= 0;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  1:  w[0] &= 0x000000FF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  2:  w[0] &= 0x0000FFFF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  3:  w[0] &= 0x00FFFFFF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  4:  w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  5:  w[1] &= 0x000000FF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  6:  w[1] &= 0x0000FFFF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  7:  w[1] &= 0x00FFFFFF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  8:  w[2] &= 0;
              w[3] &= 0;
              break;
    case  9:  w[2] &= 0x000000FF;
              w[3] &= 0;
              break;
    case 10:  w[2] &= 0x0000FFFF;
              w[3] &= 0;
              break;
    case 11:  w[2] &= 0x00FFFFFF;
              w[3] &= 0;
              break;
    case 12:  w[3] &= 0;
              break;
    case 13:  w[3] &= 0x000000FF;
              break;
    case 14:  w[3] &= 0x0000FFFF;
              break;
    case 15:  w[3] &= 0x00FFFFFF;
              break;
  }
}

inline void make_unicode (const u32x in[4], u32x out1[4], u32x out2[4])
{
  #ifdef IS_NV
  out2[3] = __byte_perm (in[3], 0, 0x7372);
  out2[2] = __byte_perm (in[3], 0, 0x7170);
  out2[1] = __byte_perm (in[2], 0, 0x7372);
  out2[0] = __byte_perm (in[2], 0, 0x7170);
  out1[3] = __byte_perm (in[1], 0, 0x7372);
  out1[2] = __byte_perm (in[1], 0, 0x7170);
  out1[1] = __byte_perm (in[0], 0, 0x7372);
  out1[0] = __byte_perm (in[0], 0, 0x7170);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  out2[3]  = ((in[3] >> 8) & 0x00FF0000) | ((in[3] >> 16) & 0x000000FF);
  out2[2]  = ((in[3] << 8) & 0x00FF0000) | ((in[3] >>  0) & 0x000000FF);
  out2[1]  = ((in[2] >> 8) & 0x00FF0000) | ((in[2] >> 16) & 0x000000FF);
  out2[0]  = ((in[2] << 8) & 0x00FF0000) | ((in[2] >>  0) & 0x000000FF);
  out1[3]  = ((in[1] >> 8) & 0x00FF0000) | ((in[1] >> 16) & 0x000000FF);
  out1[2]  = ((in[1] << 8) & 0x00FF0000) | ((in[1] >>  0) & 0x000000FF);
  out1[1]  = ((in[0] >> 8) & 0x00FF0000) | ((in[0] >> 16) & 0x000000FF);
  out1[0]  = ((in[0] << 8) & 0x00FF0000) | ((in[0] >>  0) & 0x000000FF);
  #endif
}

inline void undo_unicode (const u32x in1[4], const u32x in2[4], u32x out[4])
{
  #ifdef IS_NV
  out[0] = __byte_perm (in1[0], in1[1], 0x6420);
  out[1] = __byte_perm (in1[2], in1[3], 0x6420);
  out[2] = __byte_perm (in2[0], in2[1], 0x6420);
  out[3] = __byte_perm (in2[2], in2[3], 0x6420);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  out[0] = ((in1[0] & 0x000000ff) >>  0) | ((in1[0] & 0x00ff0000) >>  8)
         | ((in1[1] & 0x000000ff) << 16) | ((in1[1] & 0x00ff0000) <<  8);
  out[1] = ((in1[2] & 0x000000ff) >>  0) | ((in1[2] & 0x00ff0000) >>  8)
         | ((in1[3] & 0x000000ff) << 16) | ((in1[3] & 0x00ff0000) <<  8);
  out[2] = ((in2[0] & 0x000000ff) >>  0) | ((in2[0] & 0x00ff0000) >>  8)
         | ((in2[1] & 0x000000ff) << 16) | ((in2[1] & 0x00ff0000) <<  8);
  out[3] = ((in2[2] & 0x000000ff) >>  0) | ((in2[2] & 0x00ff0000) >>  8)
         | ((in2[3] & 0x000000ff) << 16) | ((in2[3] & 0x00ff0000) <<  8);
  #endif
}

inline void append_0x01_1x4 (u32x w0[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0]  = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_2x4 (u32x w0[4], u32x w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_3x4 (u32x w0[4], u32x w1[4], u32x w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;

    case 32:
      w2[0] = 0x01;
      break;

    case 33:
      w2[0] = w2[0] | 0x0100;
      break;

    case 34:
      w2[0] = w2[0] | 0x010000;
      break;

    case 35:
      w2[0] = w2[0] | 0x01000000;
      break;

    case 36:
      w2[1] = 0x01;
      break;

    case 37:
      w2[1] = w2[1] | 0x0100;
      break;

    case 38:
      w2[1] = w2[1] | 0x010000;
      break;

    case 39:
      w2[1] = w2[1] | 0x01000000;
      break;

    case 40:
      w2[2] = 0x01;
      break;

    case 41:
      w2[2] = w2[2] | 0x0100;
      break;

    case 42:
      w2[2] = w2[2] | 0x010000;
      break;

    case 43:
      w2[2] = w2[2] | 0x01000000;
      break;

    case 44:
      w2[3] = 0x01;
      break;

    case 45:
      w2[3] = w2[3] | 0x0100;
      break;

    case 46:
      w2[3] = w2[3] | 0x010000;
      break;

    case 47:
      w2[3] = w2[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_4x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;

    case 32:
      w2[0] = 0x01;
      break;

    case 33:
      w2[0] = w2[0] | 0x0100;
      break;

    case 34:
      w2[0] = w2[0] | 0x010000;
      break;

    case 35:
      w2[0] = w2[0] | 0x01000000;
      break;

    case 36:
      w2[1] = 0x01;
      break;

    case 37:
      w2[1] = w2[1] | 0x0100;
      break;

    case 38:
      w2[1] = w2[1] | 0x010000;
      break;

    case 39:
      w2[1] = w2[1] | 0x01000000;
      break;

    case 40:
      w2[2] = 0x01;
      break;

    case 41:
      w2[2] = w2[2] | 0x0100;
      break;

    case 42:
      w2[2] = w2[2] | 0x010000;
      break;

    case 43:
      w2[2] = w2[2] | 0x01000000;
      break;

    case 44:
      w2[3] = 0x01;
      break;

    case 45:
      w2[3] = w2[3] | 0x0100;
      break;

    case 46:
      w2[3] = w2[3] | 0x010000;
      break;

    case 47:
      w2[3] = w2[3] | 0x01000000;
      break;

    case 48:
      w3[0] = 0x01;
      break;

    case 49:
      w3[0] = w3[0] | 0x0100;
      break;

    case 50:
      w3[0] = w3[0] | 0x010000;
      break;

    case 51:
      w3[0] = w3[0] | 0x01000000;
      break;

    case 52:
      w3[1] = 0x01;
      break;

    case 53:
      w3[1] = w3[1] | 0x0100;
      break;

    case 54:
      w3[1] = w3[1] | 0x010000;
      break;

    case 55:
      w3[1] = w3[1] | 0x01000000;
      break;

    case 56:
      w3[2] = 0x01;
      break;

    case 57:
      w3[2] = w3[2] | 0x0100;
      break;

    case 58:
      w3[2] = w3[2] | 0x010000;
      break;

    case 59:
      w3[2] = w3[2] | 0x01000000;
      break;

    case 60:
      w3[3] = 0x01;
      break;

    case 61:
      w3[3] = w3[3] | 0x0100;
      break;

    case 62:
      w3[3] = w3[3] | 0x010000;
      break;

    case 63:
      w3[3] = w3[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_8x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x w4[4], u32x w5[4], u32x w6[4], u32x w7[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;

    case 32:
      w2[0] = 0x01;
      break;

    case 33:
      w2[0] = w2[0] | 0x0100;
      break;

    case 34:
      w2[0] = w2[0] | 0x010000;
      break;

    case 35:
      w2[0] = w2[0] | 0x01000000;
      break;

    case 36:
      w2[1] = 0x01;
      break;

    case 37:
      w2[1] = w2[1] | 0x0100;
      break;

    case 38:
      w2[1] = w2[1] | 0x010000;
      break;

    case 39:
      w2[1] = w2[1] | 0x01000000;
      break;

    case 40:
      w2[2] = 0x01;
      break;

    case 41:
      w2[2] = w2[2] | 0x0100;
      break;

    case 42:
      w2[2] = w2[2] | 0x010000;
      break;

    case 43:
      w2[2] = w2[2] | 0x01000000;
      break;

    case 44:
      w2[3] = 0x01;
      break;

    case 45:
      w2[3] = w2[3] | 0x0100;
      break;

    case 46:
      w2[3] = w2[3] | 0x010000;
      break;

    case 47:
      w2[3] = w2[3] | 0x01000000;
      break;

    case 48:
      w3[0] = 0x01;
      break;

    case 49:
      w3[0] = w3[0] | 0x0100;
      break;

    case 50:
      w3[0] = w3[0] | 0x010000;
      break;

    case 51:
      w3[0] = w3[0] | 0x01000000;
      break;

    case 52:
      w3[1] = 0x01;
      break;

    case 53:
      w3[1] = w3[1] | 0x0100;
      break;

    case 54:
      w3[1] = w3[1] | 0x010000;
      break;

    case 55:
      w3[1] = w3[1] | 0x01000000;
      break;

    case 56:
      w3[2] = 0x01;
      break;

    case 57:
      w3[2] = w3[2] | 0x0100;
      break;

    case 58:
      w3[2] = w3[2] | 0x010000;
      break;

    case 59:
      w3[2] = w3[2] | 0x01000000;
      break;

    case 60:
      w3[3] = 0x01;
      break;

    case 61:
      w3[3] = w3[3] | 0x0100;
      break;

    case 62:
      w3[3] = w3[3] | 0x010000;
      break;

    case 63:
      w3[3] = w3[3] | 0x01000000;
      break;

    case 64:
      w4[0] = 0x01;
      break;

    case 65:
      w4[0] = w4[0] | 0x0100;
      break;

    case 66:
      w4[0] = w4[0] | 0x010000;
      break;

    case 67:
      w4[0] = w4[0] | 0x01000000;
      break;

    case 68:
      w4[1] = 0x01;
      break;

    case 69:
      w4[1] = w4[1] | 0x0100;
      break;

    case 70:
      w4[1] = w4[1] | 0x010000;
      break;

    case 71:
      w4[1] = w4[1] | 0x01000000;
      break;

    case 72:
      w4[2] = 0x01;
      break;

    case 73:
      w4[2] = w4[2] | 0x0100;
      break;

    case 74:
      w4[2] = w4[2] | 0x010000;
      break;

    case 75:
      w4[2] = w4[2] | 0x01000000;
      break;

    case 76:
      w4[3] = 0x01;
      break;

    case 77:
      w4[3] = w4[3] | 0x0100;
      break;

    case 78:
      w4[3] = w4[3] | 0x010000;
      break;

    case 79:
      w4[3] = w4[3] | 0x01000000;
      break;

    case 80:
      w5[0] = 0x01;
      break;

    case 81:
      w5[0] = w5[0] | 0x0100;
      break;

    case 82:
      w5[0] = w5[0] | 0x010000;
      break;

    case 83:
      w5[0] = w5[0] | 0x01000000;
      break;

    case 84:
      w5[1] = 0x01;
      break;

    case 85:
      w5[1] = w5[1] | 0x0100;
      break;

    case 86:
      w5[1] = w5[1] | 0x010000;
      break;

    case 87:
      w5[1] = w5[1] | 0x01000000;
      break;

    case 88:
      w5[2] = 0x01;
      break;

    case 89:
      w5[2] = w5[2] | 0x0100;
      break;

    case 90:
      w5[2] = w5[2] | 0x010000;
      break;

    case 91:
      w5[2] = w5[2] | 0x01000000;
      break;

    case 92:
      w5[3] = 0x01;
      break;

    case 93:
      w5[3] = w5[3] | 0x0100;
      break;

    case 94:
      w5[3] = w5[3] | 0x010000;
      break;

    case 95:
      w5[3] = w5[3] | 0x01000000;
      break;

    case 96:
      w6[0] = 0x01;
      break;

    case 97:
      w6[0] = w6[0] | 0x0100;
      break;

    case 98:
      w6[0] = w6[0] | 0x010000;
      break;

    case 99:
      w6[0] = w6[0] | 0x01000000;
      break;

    case 100:
      w6[1] = 0x01;
      break;

    case 101:
      w6[1] = w6[1] | 0x0100;
      break;

    case 102:
      w6[1] = w6[1] | 0x010000;
      break;

    case 103:
      w6[1] = w6[1] | 0x01000000;
      break;

    case 104:
      w6[2] = 0x01;
      break;

    case 105:
      w6[2] = w6[2] | 0x0100;
      break;

    case 106:
      w6[2] = w6[2] | 0x010000;
      break;

    case 107:
      w6[2] = w6[2] | 0x01000000;
      break;

    case 108:
      w6[3] = 0x01;
      break;

    case 109:
      w6[3] = w6[3] | 0x0100;
      break;

    case 110:
      w6[3] = w6[3] | 0x010000;
      break;

    case 111:
      w6[3] = w6[3] | 0x01000000;
      break;

    case 112:
      w7[0] = 0x01;
      break;

    case 113:
      w7[0] = w7[0] | 0x0100;
      break;

    case 114:
      w7[0] = w7[0] | 0x010000;
      break;

    case 115:
      w7[0] = w7[0] | 0x01000000;
      break;

    case 116:
      w7[1] = 0x01;
      break;

    case 117:
      w7[1] = w7[1] | 0x0100;
      break;

    case 118:
      w7[1] = w7[1] | 0x010000;
      break;

    case 119:
      w7[1] = w7[1] | 0x01000000;
      break;

    case 120:
      w7[2] = 0x01;
      break;

    case 121:
      w7[2] = w7[2] | 0x0100;
      break;

    case 122:
      w7[2] = w7[2] | 0x010000;
      break;

    case 123:
      w7[2] = w7[2] | 0x01000000;
      break;

    case 124:
      w7[3] = 0x01;
      break;

    case 125:
      w7[3] = w7[3] | 0x0100;
      break;

    case 126:
      w7[3] = w7[3] | 0x010000;
      break;

    case 127:
      w7[3] = w7[3] | 0x01000000;
      break;
  }
}

inline void append_0x02_1x4 (u32x w0[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0]  = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;
  }
}

inline void append_0x02_2x4 (u32x w0[4], u32x w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;
  }
}

inline void append_0x02_3x4 (u32x w0[4], u32x w1[4], u32x w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;

    case 32:
      w2[0] = 0x02;
      break;

    case 33:
      w2[0] = w2[0] | 0x0200;
      break;

    case 34:
      w2[0] = w2[0] | 0x020000;
      break;

    case 35:
      w2[0] = w2[0] | 0x02000000;
      break;

    case 36:
      w2[1] = 0x02;
      break;

    case 37:
      w2[1] = w2[1] | 0x0200;
      break;

    case 38:
      w2[1] = w2[1] | 0x020000;
      break;

    case 39:
      w2[1] = w2[1] | 0x02000000;
      break;

    case 40:
      w2[2] = 0x02;
      break;

    case 41:
      w2[2] = w2[2] | 0x0200;
      break;

    case 42:
      w2[2] = w2[2] | 0x020000;
      break;

    case 43:
      w2[2] = w2[2] | 0x02000000;
      break;

    case 44:
      w2[3] = 0x02;
      break;

    case 45:
      w2[3] = w2[3] | 0x0200;
      break;

    case 46:
      w2[3] = w2[3] | 0x020000;
      break;

    case 47:
      w2[3] = w2[3] | 0x02000000;
      break;
  }
}

inline void append_0x02_4x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;

    case 32:
      w2[0] = 0x02;
      break;

    case 33:
      w2[0] = w2[0] | 0x0200;
      break;

    case 34:
      w2[0] = w2[0] | 0x020000;
      break;

    case 35:
      w2[0] = w2[0] | 0x02000000;
      break;

    case 36:
      w2[1] = 0x02;
      break;

    case 37:
      w2[1] = w2[1] | 0x0200;
      break;

    case 38:
      w2[1] = w2[1] | 0x020000;
      break;

    case 39:
      w2[1] = w2[1] | 0x02000000;
      break;

    case 40:
      w2[2] = 0x02;
      break;

    case 41:
      w2[2] = w2[2] | 0x0200;
      break;

    case 42:
      w2[2] = w2[2] | 0x020000;
      break;

    case 43:
      w2[2] = w2[2] | 0x02000000;
      break;

    case 44:
      w2[3] = 0x02;
      break;

    case 45:
      w2[3] = w2[3] | 0x0200;
      break;

    case 46:
      w2[3] = w2[3] | 0x020000;
      break;

    case 47:
      w2[3] = w2[3] | 0x02000000;
      break;

    case 48:
      w3[0] = 0x02;
      break;

    case 49:
      w3[0] = w3[0] | 0x0200;
      break;

    case 50:
      w3[0] = w3[0] | 0x020000;
      break;

    case 51:
      w3[0] = w3[0] | 0x02000000;
      break;

    case 52:
      w3[1] = 0x02;
      break;

    case 53:
      w3[1] = w3[1] | 0x0200;
      break;

    case 54:
      w3[1] = w3[1] | 0x020000;
      break;

    case 55:
      w3[1] = w3[1] | 0x02000000;
      break;

    case 56:
      w3[2] = 0x02;
      break;

    case 57:
      w3[2] = w3[2] | 0x0200;
      break;

    case 58:
      w3[2] = w3[2] | 0x020000;
      break;

    case 59:
      w3[2] = w3[2] | 0x02000000;
      break;

    case 60:
      w3[3] = 0x02;
      break;

    case 61:
      w3[3] = w3[3] | 0x0200;
      break;

    case 62:
      w3[3] = w3[3] | 0x020000;
      break;

    case 63:
      w3[3] = w3[3] | 0x02000000;
      break;
  }
}

inline void append_0x02_8x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x w4[4], u32x w5[4], u32x w6[4], u32x w7[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;

    case 32:
      w2[0] = 0x02;
      break;

    case 33:
      w2[0] = w2[0] | 0x0200;
      break;

    case 34:
      w2[0] = w2[0] | 0x020000;
      break;

    case 35:
      w2[0] = w2[0] | 0x02000000;
      break;

    case 36:
      w2[1] = 0x02;
      break;

    case 37:
      w2[1] = w2[1] | 0x0200;
      break;

    case 38:
      w2[1] = w2[1] | 0x020000;
      break;

    case 39:
      w2[1] = w2[1] | 0x02000000;
      break;

    case 40:
      w2[2] = 0x02;
      break;

    case 41:
      w2[2] = w2[2] | 0x0200;
      break;

    case 42:
      w2[2] = w2[2] | 0x020000;
      break;

    case 43:
      w2[2] = w2[2] | 0x02000000;
      break;

    case 44:
      w2[3] = 0x02;
      break;

    case 45:
      w2[3] = w2[3] | 0x0200;
      break;

    case 46:
      w2[3] = w2[3] | 0x020000;
      break;

    case 47:
      w2[3] = w2[3] | 0x02000000;
      break;

    case 48:
      w3[0] = 0x02;
      break;

    case 49:
      w3[0] = w3[0] | 0x0200;
      break;

    case 50:
      w3[0] = w3[0] | 0x020000;
      break;

    case 51:
      w3[0] = w3[0] | 0x02000000;
      break;

    case 52:
      w3[1] = 0x02;
      break;

    case 53:
      w3[1] = w3[1] | 0x0200;
      break;

    case 54:
      w3[1] = w3[1] | 0x020000;
      break;

    case 55:
      w3[1] = w3[1] | 0x02000000;
      break;

    case 56:
      w3[2] = 0x02;
      break;

    case 57:
      w3[2] = w3[2] | 0x0200;
      break;

    case 58:
      w3[2] = w3[2] | 0x020000;
      break;

    case 59:
      w3[2] = w3[2] | 0x02000000;
      break;

    case 60:
      w3[3] = 0x02;
      break;

    case 61:
      w3[3] = w3[3] | 0x0200;
      break;

    case 62:
      w3[3] = w3[3] | 0x020000;
      break;

    case 63:
      w3[3] = w3[3] | 0x02000000;
      break;

    case 64:
      w4[0] = 0x02;
      break;

    case 65:
      w4[0] = w4[0] | 0x0200;
      break;

    case 66:
      w4[0] = w4[0] | 0x020000;
      break;

    case 67:
      w4[0] = w4[0] | 0x02000000;
      break;

    case 68:
      w4[1] = 0x02;
      break;

    case 69:
      w4[1] = w4[1] | 0x0200;
      break;

    case 70:
      w4[1] = w4[1] | 0x020000;
      break;

    case 71:
      w4[1] = w4[1] | 0x02000000;
      break;

    case 72:
      w4[2] = 0x02;
      break;

    case 73:
      w4[2] = w4[2] | 0x0200;
      break;

    case 74:
      w4[2] = w4[2] | 0x020000;
      break;

    case 75:
      w4[2] = w4[2] | 0x02000000;
      break;

    case 76:
      w4[3] = 0x02;
      break;

    case 77:
      w4[3] = w4[3] | 0x0200;
      break;

    case 78:
      w4[3] = w4[3] | 0x020000;
      break;

    case 79:
      w4[3] = w4[3] | 0x02000000;
      break;

    case 80:
      w5[0] = 0x02;
      break;

    case 81:
      w5[0] = w5[0] | 0x0200;
      break;

    case 82:
      w5[0] = w5[0] | 0x020000;
      break;

    case 83:
      w5[0] = w5[0] | 0x02000000;
      break;

    case 84:
      w5[1] = 0x02;
      break;

    case 85:
      w5[1] = w5[1] | 0x0200;
      break;

    case 86:
      w5[1] = w5[1] | 0x020000;
      break;

    case 87:
      w5[1] = w5[1] | 0x02000000;
      break;

    case 88:
      w5[2] = 0x02;
      break;

    case 89:
      w5[2] = w5[2] | 0x0200;
      break;

    case 90:
      w5[2] = w5[2] | 0x020000;
      break;

    case 91:
      w5[2] = w5[2] | 0x02000000;
      break;

    case 92:
      w5[3] = 0x02;
      break;

    case 93:
      w5[3] = w5[3] | 0x0200;
      break;

    case 94:
      w5[3] = w5[3] | 0x020000;
      break;

    case 95:
      w5[3] = w5[3] | 0x02000000;
      break;

    case 96:
      w6[0] = 0x02;
      break;

    case 97:
      w6[0] = w6[0] | 0x0200;
      break;

    case 98:
      w6[0] = w6[0] | 0x020000;
      break;

    case 99:
      w6[0] = w6[0] | 0x02000000;
      break;

    case 100:
      w6[1] = 0x02;
      break;

    case 101:
      w6[1] = w6[1] | 0x0200;
      break;

    case 102:
      w6[1] = w6[1] | 0x020000;
      break;

    case 103:
      w6[1] = w6[1] | 0x02000000;
      break;

    case 104:
      w6[2] = 0x02;
      break;

    case 105:
      w6[2] = w6[2] | 0x0200;
      break;

    case 106:
      w6[2] = w6[2] | 0x020000;
      break;

    case 107:
      w6[2] = w6[2] | 0x02000000;
      break;

    case 108:
      w6[3] = 0x02;
      break;

    case 109:
      w6[3] = w6[3] | 0x0200;
      break;

    case 110:
      w6[3] = w6[3] | 0x020000;
      break;

    case 111:
      w6[3] = w6[3] | 0x02000000;
      break;

    case 112:
      w7[0] = 0x02;
      break;

    case 113:
      w7[0] = w7[0] | 0x0200;
      break;

    case 114:
      w7[0] = w7[0] | 0x020000;
      break;

    case 115:
      w7[0] = w7[0] | 0x02000000;
      break;

    case 116:
      w7[1] = 0x02;
      break;

    case 117:
      w7[1] = w7[1] | 0x0200;
      break;

    case 118:
      w7[1] = w7[1] | 0x020000;
      break;

    case 119:
      w7[1] = w7[1] | 0x02000000;
      break;

    case 120:
      w7[2] = 0x02;
      break;

    case 121:
      w7[2] = w7[2] | 0x0200;
      break;

    case 122:
      w7[2] = w7[2] | 0x020000;
      break;

    case 123:
      w7[2] = w7[2] | 0x02000000;
      break;

    case 124:
      w7[3] = 0x02;
      break;

    case 125:
      w7[3] = w7[3] | 0x0200;
      break;

    case 126:
      w7[3] = w7[3] | 0x020000;
      break;

    case 127:
      w7[3] = w7[3] | 0x02000000;
      break;
  }
}

inline void append_0x80_1x4 (u32x w0[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0]  = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_2x4 (u32x w0[4], u32x w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_3x4 (u32x w0[4], u32x w1[4], u32x w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;

    case 32:
      w2[0] = 0x80;
      break;

    case 33:
      w2[0] = w2[0] | 0x8000;
      break;

    case 34:
      w2[0] = w2[0] | 0x800000;
      break;

    case 35:
      w2[0] = w2[0] | 0x80000000;
      break;

    case 36:
      w2[1] = 0x80;
      break;

    case 37:
      w2[1] = w2[1] | 0x8000;
      break;

    case 38:
      w2[1] = w2[1] | 0x800000;
      break;

    case 39:
      w2[1] = w2[1] | 0x80000000;
      break;

    case 40:
      w2[2] = 0x80;
      break;

    case 41:
      w2[2] = w2[2] | 0x8000;
      break;

    case 42:
      w2[2] = w2[2] | 0x800000;
      break;

    case 43:
      w2[2] = w2[2] | 0x80000000;
      break;

    case 44:
      w2[3] = 0x80;
      break;

    case 45:
      w2[3] = w2[3] | 0x8000;
      break;

    case 46:
      w2[3] = w2[3] | 0x800000;
      break;

    case 47:
      w2[3] = w2[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_4x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;

    case 32:
      w2[0] = 0x80;
      break;

    case 33:
      w2[0] = w2[0] | 0x8000;
      break;

    case 34:
      w2[0] = w2[0] | 0x800000;
      break;

    case 35:
      w2[0] = w2[0] | 0x80000000;
      break;

    case 36:
      w2[1] = 0x80;
      break;

    case 37:
      w2[1] = w2[1] | 0x8000;
      break;

    case 38:
      w2[1] = w2[1] | 0x800000;
      break;

    case 39:
      w2[1] = w2[1] | 0x80000000;
      break;

    case 40:
      w2[2] = 0x80;
      break;

    case 41:
      w2[2] = w2[2] | 0x8000;
      break;

    case 42:
      w2[2] = w2[2] | 0x800000;
      break;

    case 43:
      w2[2] = w2[2] | 0x80000000;
      break;

    case 44:
      w2[3] = 0x80;
      break;

    case 45:
      w2[3] = w2[3] | 0x8000;
      break;

    case 46:
      w2[3] = w2[3] | 0x800000;
      break;

    case 47:
      w2[3] = w2[3] | 0x80000000;
      break;

    case 48:
      w3[0] = 0x80;
      break;

    case 49:
      w3[0] = w3[0] | 0x8000;
      break;

    case 50:
      w3[0] = w3[0] | 0x800000;
      break;

    case 51:
      w3[0] = w3[0] | 0x80000000;
      break;

    case 52:
      w3[1] = 0x80;
      break;

    case 53:
      w3[1] = w3[1] | 0x8000;
      break;

    case 54:
      w3[1] = w3[1] | 0x800000;
      break;

    case 55:
      w3[1] = w3[1] | 0x80000000;
      break;

    case 56:
      w3[2] = 0x80;
      break;

    case 57:
      w3[2] = w3[2] | 0x8000;
      break;

    case 58:
      w3[2] = w3[2] | 0x800000;
      break;

    case 59:
      w3[2] = w3[2] | 0x80000000;
      break;

    case 60:
      w3[3] = 0x80;
      break;

    case 61:
      w3[3] = w3[3] | 0x8000;
      break;

    case 62:
      w3[3] = w3[3] | 0x800000;
      break;

    case 63:
      w3[3] = w3[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_8x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x w4[4], u32x w5[4], u32x w6[4], u32x w7[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;

    case 32:
      w2[0] = 0x80;
      break;

    case 33:
      w2[0] = w2[0] | 0x8000;
      break;

    case 34:
      w2[0] = w2[0] | 0x800000;
      break;

    case 35:
      w2[0] = w2[0] | 0x80000000;
      break;

    case 36:
      w2[1] = 0x80;
      break;

    case 37:
      w2[1] = w2[1] | 0x8000;
      break;

    case 38:
      w2[1] = w2[1] | 0x800000;
      break;

    case 39:
      w2[1] = w2[1] | 0x80000000;
      break;

    case 40:
      w2[2] = 0x80;
      break;

    case 41:
      w2[2] = w2[2] | 0x8000;
      break;

    case 42:
      w2[2] = w2[2] | 0x800000;
      break;

    case 43:
      w2[2] = w2[2] | 0x80000000;
      break;

    case 44:
      w2[3] = 0x80;
      break;

    case 45:
      w2[3] = w2[3] | 0x8000;
      break;

    case 46:
      w2[3] = w2[3] | 0x800000;
      break;

    case 47:
      w2[3] = w2[3] | 0x80000000;
      break;

    case 48:
      w3[0] = 0x80;
      break;

    case 49:
      w3[0] = w3[0] | 0x8000;
      break;

    case 50:
      w3[0] = w3[0] | 0x800000;
      break;

    case 51:
      w3[0] = w3[0] | 0x80000000;
      break;

    case 52:
      w3[1] = 0x80;
      break;

    case 53:
      w3[1] = w3[1] | 0x8000;
      break;

    case 54:
      w3[1] = w3[1] | 0x800000;
      break;

    case 55:
      w3[1] = w3[1] | 0x80000000;
      break;

    case 56:
      w3[2] = 0x80;
      break;

    case 57:
      w3[2] = w3[2] | 0x8000;
      break;

    case 58:
      w3[2] = w3[2] | 0x800000;
      break;

    case 59:
      w3[2] = w3[2] | 0x80000000;
      break;

    case 60:
      w3[3] = 0x80;
      break;

    case 61:
      w3[3] = w3[3] | 0x8000;
      break;

    case 62:
      w3[3] = w3[3] | 0x800000;
      break;

    case 63:
      w3[3] = w3[3] | 0x80000000;
      break;

    case 64:
      w4[0] = 0x80;
      break;

    case 65:
      w4[0] = w4[0] | 0x8000;
      break;

    case 66:
      w4[0] = w4[0] | 0x800000;
      break;

    case 67:
      w4[0] = w4[0] | 0x80000000;
      break;

    case 68:
      w4[1] = 0x80;
      break;

    case 69:
      w4[1] = w4[1] | 0x8000;
      break;

    case 70:
      w4[1] = w4[1] | 0x800000;
      break;

    case 71:
      w4[1] = w4[1] | 0x80000000;
      break;

    case 72:
      w4[2] = 0x80;
      break;

    case 73:
      w4[2] = w4[2] | 0x8000;
      break;

    case 74:
      w4[2] = w4[2] | 0x800000;
      break;

    case 75:
      w4[2] = w4[2] | 0x80000000;
      break;

    case 76:
      w4[3] = 0x80;
      break;

    case 77:
      w4[3] = w4[3] | 0x8000;
      break;

    case 78:
      w4[3] = w4[3] | 0x800000;
      break;

    case 79:
      w4[3] = w4[3] | 0x80000000;
      break;

    case 80:
      w5[0] = 0x80;
      break;

    case 81:
      w5[0] = w5[0] | 0x8000;
      break;

    case 82:
      w5[0] = w5[0] | 0x800000;
      break;

    case 83:
      w5[0] = w5[0] | 0x80000000;
      break;

    case 84:
      w5[1] = 0x80;
      break;

    case 85:
      w5[1] = w5[1] | 0x8000;
      break;

    case 86:
      w5[1] = w5[1] | 0x800000;
      break;

    case 87:
      w5[1] = w5[1] | 0x80000000;
      break;

    case 88:
      w5[2] = 0x80;
      break;

    case 89:
      w5[2] = w5[2] | 0x8000;
      break;

    case 90:
      w5[2] = w5[2] | 0x800000;
      break;

    case 91:
      w5[2] = w5[2] | 0x80000000;
      break;

    case 92:
      w5[3] = 0x80;
      break;

    case 93:
      w5[3] = w5[3] | 0x8000;
      break;

    case 94:
      w5[3] = w5[3] | 0x800000;
      break;

    case 95:
      w5[3] = w5[3] | 0x80000000;
      break;

    case 96:
      w6[0] = 0x80;
      break;

    case 97:
      w6[0] = w6[0] | 0x8000;
      break;

    case 98:
      w6[0] = w6[0] | 0x800000;
      break;

    case 99:
      w6[0] = w6[0] | 0x80000000;
      break;

    case 100:
      w6[1] = 0x80;
      break;

    case 101:
      w6[1] = w6[1] | 0x8000;
      break;

    case 102:
      w6[1] = w6[1] | 0x800000;
      break;

    case 103:
      w6[1] = w6[1] | 0x80000000;
      break;

    case 104:
      w6[2] = 0x80;
      break;

    case 105:
      w6[2] = w6[2] | 0x8000;
      break;

    case 106:
      w6[2] = w6[2] | 0x800000;
      break;

    case 107:
      w6[2] = w6[2] | 0x80000000;
      break;

    case 108:
      w6[3] = 0x80;
      break;

    case 109:
      w6[3] = w6[3] | 0x8000;
      break;

    case 110:
      w6[3] = w6[3] | 0x800000;
      break;

    case 111:
      w6[3] = w6[3] | 0x80000000;
      break;

    case 112:
      w7[0] = 0x80;
      break;

    case 113:
      w7[0] = w7[0] | 0x8000;
      break;

    case 114:
      w7[0] = w7[0] | 0x800000;
      break;

    case 115:
      w7[0] = w7[0] | 0x80000000;
      break;

    case 116:
      w7[1] = 0x80;
      break;

    case 117:
      w7[1] = w7[1] | 0x8000;
      break;

    case 118:
      w7[1] = w7[1] | 0x800000;
      break;

    case 119:
      w7[1] = w7[1] | 0x80000000;
      break;

    case 120:
      w7[2] = 0x80;
      break;

    case 121:
      w7[2] = w7[2] | 0x8000;
      break;

    case 122:
      w7[2] = w7[2] | 0x800000;
      break;

    case 123:
      w7[2] = w7[2] | 0x80000000;
      break;

    case 124:
      w7[3] = 0x80;
      break;

    case 125:
      w7[3] = w7[3] | 0x8000;
      break;

    case 126:
      w7[3] = w7[3] | 0x800000;
      break;

    case 127:
      w7[3] = w7[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_1x16 (u32x w[16], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w[ 0] = 0x80;
      break;

    case 1:
      w[ 0] = w[ 0] | 0x8000;
      break;

    case 2:
      w[ 0] = w[ 0] | 0x800000;
      break;

    case 3:
      w[ 0] = w[ 0] | 0x80000000;
      break;

    case 4:
      w[ 1] = 0x80;
      break;

    case 5:
      w[ 1] = w[ 1] | 0x8000;
      break;

    case 6:
      w[ 1] = w[ 1] | 0x800000;
      break;

    case 7:
      w[ 1] = w[ 1] | 0x80000000;
      break;

    case 8:
      w[ 2] = 0x80;
      break;

    case 9:
      w[ 2] = w[ 2] | 0x8000;
      break;

    case 10:
      w[ 2] = w[ 2] | 0x800000;
      break;

    case 11:
      w[ 2] = w[ 2] | 0x80000000;
      break;

    case 12:
      w[ 3] = 0x80;
      break;

    case 13:
      w[ 3] = w[ 3] | 0x8000;
      break;

    case 14:
      w[ 3] = w[ 3] | 0x800000;
      break;

    case 15:
      w[ 3] = w[ 3] | 0x80000000;
      break;

    case 16:
      w[ 4] = 0x80;
      break;

    case 17:
      w[ 4] = w[ 4] | 0x8000;
      break;

    case 18:
      w[ 4] = w[ 4] | 0x800000;
      break;

    case 19:
      w[ 4] = w[ 4] | 0x80000000;
      break;

    case 20:
      w[ 5] = 0x80;
      break;

    case 21:
      w[ 5] = w[ 5] | 0x8000;
      break;

    case 22:
      w[ 5] = w[ 5] | 0x800000;
      break;

    case 23:
      w[ 5] = w[ 5] | 0x80000000;
      break;

    case 24:
      w[ 6] = 0x80;
      break;

    case 25:
      w[ 6] = w[ 6] | 0x8000;
      break;

    case 26:
      w[ 6] = w[ 6] | 0x800000;
      break;

    case 27:
      w[ 6] = w[ 6] | 0x80000000;
      break;

    case 28:
      w[ 7] = 0x80;
      break;

    case 29:
      w[ 7] = w[ 7] | 0x8000;
      break;

    case 30:
      w[ 7] = w[ 7] | 0x800000;
      break;

    case 31:
      w[ 7] = w[ 7] | 0x80000000;
      break;

    case 32:
      w[ 8] = 0x80;
      break;

    case 33:
      w[ 8] = w[ 8] | 0x8000;
      break;

    case 34:
      w[ 8] = w[ 8] | 0x800000;
      break;

    case 35:
      w[ 8] = w[ 8] | 0x80000000;
      break;

    case 36:
      w[ 9] = 0x80;
      break;

    case 37:
      w[ 9] = w[ 9] | 0x8000;
      break;

    case 38:
      w[ 9] = w[ 9] | 0x800000;
      break;

    case 39:
      w[ 9] = w[ 9] | 0x80000000;
      break;

    case 40:
      w[10] = 0x80;
      break;

    case 41:
      w[10] = w[10] | 0x8000;
      break;

    case 42:
      w[10] = w[10] | 0x800000;
      break;

    case 43:
      w[10] = w[10] | 0x80000000;
      break;

    case 44:
      w[11] = 0x80;
      break;

    case 45:
      w[11] = w[11] | 0x8000;
      break;

    case 46:
      w[11] = w[11] | 0x800000;
      break;

    case 47:
      w[11] = w[11] | 0x80000000;
      break;

    case 48:
      w[12] = 0x80;
      break;

    case 49:
      w[12] = w[12] | 0x8000;
      break;

    case 50:
      w[12] = w[12] | 0x800000;
      break;

    case 51:
      w[12] = w[12] | 0x80000000;
      break;

    case 52:
      w[13] = 0x80;
      break;

    case 53:
      w[13] = w[13] | 0x8000;
      break;

    case 54:
      w[13] = w[13] | 0x800000;
      break;

    case 55:
      w[13] = w[13] | 0x80000000;
      break;

    case 56:
      w[14] = 0x80;
      break;

    case 57:
      w[14] = w[14] | 0x8000;
      break;

    case 58:
      w[14] = w[14] | 0x800000;
      break;

    case 59:
      w[14] = w[14] | 0x80000000;
      break;

    case 60:
      w[15] = 0x80;
      break;

    case 61:
      w[15] = w[15] | 0x8000;
      break;

    case 62:
      w[15] = w[15] | 0x800000;
      break;

    case 63:
      w[15] = w[15] | 0x80000000;
      break;
  }
}

inline void switch_buffer_by_offset_le (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  #if defined IS_AMD || defined IS_GENERIC
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset;

  switch (offset / 4)
  {
    case 0:
      w3[2] = amd_bytealign (    0, w3[1], offset_minus_4);
      w3[1] = amd_bytealign (w3[1], w3[0], offset_minus_4);
      w3[0] = amd_bytealign (w3[0], w2[3], offset_minus_4);
      w2[3] = amd_bytealign (w2[3], w2[2], offset_minus_4);
      w2[2] = amd_bytealign (w2[2], w2[1], offset_minus_4);
      w2[1] = amd_bytealign (w2[1], w2[0], offset_minus_4);
      w2[0] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w1[3] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w1[2] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w1[1] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w1[0] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w0[3] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w0[2] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w0[1] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w0[0] = amd_bytealign (w0[0],     0, offset_minus_4);

      if (offset_mod_4 == 0)
      {
        w0[0] = w0[1];
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 1:
      w3[2] = amd_bytealign (    0, w3[0], offset_minus_4);
      w3[1] = amd_bytealign (w3[0], w2[3], offset_minus_4);
      w3[0] = amd_bytealign (w2[3], w2[2], offset_minus_4);
      w2[3] = amd_bytealign (w2[2], w2[1], offset_minus_4);
      w2[2] = amd_bytealign (w2[1], w2[0], offset_minus_4);
      w2[1] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w2[0] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w1[3] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w1[2] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w1[1] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w1[0] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w0[3] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w0[2] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w0[1] = amd_bytealign (w0[0],     0, offset_minus_4);
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 2:
      w3[2] = amd_bytealign (    0, w2[3], offset_minus_4);
      w3[1] = amd_bytealign (w2[3], w2[2], offset_minus_4);
      w3[0] = amd_bytealign (w2[2], w2[1], offset_minus_4);
      w2[3] = amd_bytealign (w2[1], w2[0], offset_minus_4);
      w2[2] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w2[1] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w2[0] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w1[3] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w1[2] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w1[1] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w1[0] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w0[3] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w0[2] = amd_bytealign (w0[0],     0, offset_minus_4);
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 3:
      w3[2] = amd_bytealign (    0, w2[2], offset_minus_4);
      w3[1] = amd_bytealign (w2[2], w2[1], offset_minus_4);
      w3[0] = amd_bytealign (w2[1], w2[0], offset_minus_4);
      w2[3] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w2[2] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w2[1] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w2[0] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w1[3] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w1[2] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w1[1] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w1[0] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w0[3] = amd_bytealign (w0[0],     0, offset_minus_4);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 4:
      w3[2] = amd_bytealign (    0, w2[1], offset_minus_4);
      w3[1] = amd_bytealign (w2[1], w2[0], offset_minus_4);
      w3[0] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w2[3] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w2[2] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w2[1] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w2[0] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w1[3] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w1[2] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w1[1] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w1[0] = amd_bytealign (w0[0],     0, offset_minus_4);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 5:
      w3[2] = amd_bytealign (    0, w2[0], offset_minus_4);
      w3[1] = amd_bytealign (w2[0], w1[3], offset_minus_4);
      w3[0] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w2[3] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w2[2] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w2[1] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w2[0] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w1[3] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w1[2] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w1[1] = amd_bytealign (w0[0],     0, offset_minus_4);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 6:
      w3[2] = amd_bytealign (    0, w1[3], offset_minus_4);
      w3[1] = amd_bytealign (w1[3], w1[2], offset_minus_4);
      w3[0] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w2[3] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w2[2] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w2[1] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w2[0] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w1[3] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w1[2] = amd_bytealign (w0[0],     0, offset_minus_4);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 7:
      w3[2] = amd_bytealign (    0, w1[2], offset_minus_4);
      w3[1] = amd_bytealign (w1[2], w1[1], offset_minus_4);
      w3[0] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w2[3] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w2[2] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w2[1] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w2[0] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w1[3] = amd_bytealign (w0[0],     0, offset_minus_4);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 8:
      w3[2] = amd_bytealign (    0, w1[1], offset_minus_4);
      w3[1] = amd_bytealign (w1[1], w1[0], offset_minus_4);
      w3[0] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w2[3] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w2[2] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w2[1] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w2[0] = amd_bytealign (w0[0],     0, offset_minus_4);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 9:
      w3[2] = amd_bytealign (    0, w1[0], offset_minus_4);
      w3[1] = amd_bytealign (w1[0], w0[3], offset_minus_4);
      w3[0] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w2[3] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w2[2] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w2[1] = amd_bytealign (w0[0],     0, offset_minus_4);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 10:
      w3[2] = amd_bytealign (    0, w0[3], offset_minus_4);
      w3[1] = amd_bytealign (w0[3], w0[2], offset_minus_4);
      w3[0] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w2[3] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w2[2] = amd_bytealign (w0[0],     0, offset_minus_4);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 11:
      w3[2] = amd_bytealign (    0, w0[2], offset_minus_4);
      w3[1] = amd_bytealign (w0[2], w0[1], offset_minus_4);
      w3[0] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w2[3] = amd_bytealign (w0[0],     0, offset_minus_4);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 12:
      w3[2] = amd_bytealign (    0, w0[1], offset_minus_4);
      w3[1] = amd_bytealign (w0[1], w0[0], offset_minus_4);
      w3[0] = amd_bytealign (w0[0],     0, offset_minus_4);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 13:
      w3[2] = amd_bytealign (    0, w0[0], offset_minus_4);
      w3[1] = amd_bytealign (w0[0],     0, offset_minus_4);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (offset % 4);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w3[1] = __byte_perm (w3[0], w3[1], selector);
      w3[0] = __byte_perm (w2[3], w3[0], selector);
      w2[3] = __byte_perm (w2[2], w2[3], selector);
      w2[2] = __byte_perm (w2[1], w2[2], selector);
      w2[1] = __byte_perm (w2[0], w2[1], selector);
      w2[0] = __byte_perm (w1[3], w2[0], selector);
      w1[3] = __byte_perm (w1[2], w1[3], selector);
      w1[2] = __byte_perm (w1[1], w1[2], selector);
      w1[1] = __byte_perm (w1[0], w1[1], selector);
      w1[0] = __byte_perm (w0[3], w1[0], selector);
      w0[3] = __byte_perm (w0[2], w0[3], selector);
      w0[2] = __byte_perm (w0[1], w0[2], selector);
      w0[1] = __byte_perm (w0[0], w0[1], selector);
      w0[0] = __byte_perm (    0, w0[0], selector);

      break;

    case 1:
      w3[1] = __byte_perm (w2[3], w3[0], selector);
      w3[0] = __byte_perm (w2[2], w2[3], selector);
      w2[3] = __byte_perm (w2[1], w2[2], selector);
      w2[2] = __byte_perm (w2[0], w2[1], selector);
      w2[1] = __byte_perm (w1[3], w2[0], selector);
      w2[0] = __byte_perm (w1[2], w1[3], selector);
      w1[3] = __byte_perm (w1[1], w1[2], selector);
      w1[2] = __byte_perm (w1[0], w1[1], selector);
      w1[1] = __byte_perm (w0[3], w1[0], selector);
      w1[0] = __byte_perm (w0[2], w0[3], selector);
      w0[3] = __byte_perm (w0[1], w0[2], selector);
      w0[2] = __byte_perm (w0[0], w0[1], selector);
      w0[1] = __byte_perm (    0, w0[0], selector);
      w0[0] = 0;

      break;

    case 2:
      w3[1] = __byte_perm (w2[2], w2[3], selector);
      w3[0] = __byte_perm (w2[1], w2[2], selector);
      w2[3] = __byte_perm (w2[0], w2[1], selector);
      w2[2] = __byte_perm (w1[3], w2[0], selector);
      w2[1] = __byte_perm (w1[2], w1[3], selector);
      w2[0] = __byte_perm (w1[1], w1[2], selector);
      w1[3] = __byte_perm (w1[0], w1[1], selector);
      w1[2] = __byte_perm (w0[3], w1[0], selector);
      w1[1] = __byte_perm (w0[2], w0[3], selector);
      w1[0] = __byte_perm (w0[1], w0[2], selector);
      w0[3] = __byte_perm (w0[0], w0[1], selector);
      w0[2] = __byte_perm (    0, w0[0], selector);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 3:
      w3[1] = __byte_perm (w2[1], w2[2], selector);
      w3[0] = __byte_perm (w2[0], w2[1], selector);
      w2[3] = __byte_perm (w1[3], w2[0], selector);
      w2[2] = __byte_perm (w1[2], w1[3], selector);
      w2[1] = __byte_perm (w1[1], w1[2], selector);
      w2[0] = __byte_perm (w1[0], w1[1], selector);
      w1[3] = __byte_perm (w0[3], w1[0], selector);
      w1[2] = __byte_perm (w0[2], w0[3], selector);
      w1[1] = __byte_perm (w0[1], w0[2], selector);
      w1[0] = __byte_perm (w0[0], w0[1], selector);
      w0[3] = __byte_perm (    0, w0[0], selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 4:
      w3[1] = __byte_perm (w2[0], w2[1], selector);
      w3[0] = __byte_perm (w1[3], w2[0], selector);
      w2[3] = __byte_perm (w1[2], w1[3], selector);
      w2[2] = __byte_perm (w1[1], w1[2], selector);
      w2[1] = __byte_perm (w1[0], w1[1], selector);
      w2[0] = __byte_perm (w0[3], w1[0], selector);
      w1[3] = __byte_perm (w0[2], w0[3], selector);
      w1[2] = __byte_perm (w0[1], w0[2], selector);
      w1[1] = __byte_perm (w0[0], w0[1], selector);
      w1[0] = __byte_perm (    0, w0[0], selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 5:
      w3[1] = __byte_perm (w1[3], w2[0], selector);
      w3[0] = __byte_perm (w1[2], w1[3], selector);
      w2[3] = __byte_perm (w1[1], w1[2], selector);
      w2[2] = __byte_perm (w1[0], w1[1], selector);
      w2[1] = __byte_perm (w0[3], w1[0], selector);
      w2[0] = __byte_perm (w0[2], w0[3], selector);
      w1[3] = __byte_perm (w0[1], w0[2], selector);
      w1[2] = __byte_perm (w0[0], w0[1], selector);
      w1[1] = __byte_perm (    0, w0[0], selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 6:
      w3[1] = __byte_perm (w1[2], w1[3], selector);
      w3[0] = __byte_perm (w1[1], w1[2], selector);
      w2[3] = __byte_perm (w1[0], w1[1], selector);
      w2[2] = __byte_perm (w0[3], w1[0], selector);
      w2[1] = __byte_perm (w0[2], w0[3], selector);
      w2[0] = __byte_perm (w0[1], w0[2], selector);
      w1[3] = __byte_perm (w0[0], w0[1], selector);
      w1[2] = __byte_perm (    0, w0[0], selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 7:
      w3[1] = __byte_perm (w1[1], w1[2], selector);
      w3[0] = __byte_perm (w1[0], w1[1], selector);
      w2[3] = __byte_perm (w0[3], w1[0], selector);
      w2[2] = __byte_perm (w0[2], w0[3], selector);
      w2[1] = __byte_perm (w0[1], w0[2], selector);
      w2[0] = __byte_perm (w0[0], w0[1], selector);
      w1[3] = __byte_perm (    0, w0[0], selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 8:
      w3[1] = __byte_perm (w1[0], w1[1], selector);
      w3[0] = __byte_perm (w0[3], w1[0], selector);
      w2[3] = __byte_perm (w0[2], w0[3], selector);
      w2[2] = __byte_perm (w0[1], w0[2], selector);
      w2[1] = __byte_perm (w0[0], w0[1], selector);
      w2[0] = __byte_perm (    0, w0[0], selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 9:
      w3[1] = __byte_perm (w0[3], w1[0], selector);
      w3[0] = __byte_perm (w0[2], w0[3], selector);
      w2[3] = __byte_perm (w0[1], w0[2], selector);
      w2[2] = __byte_perm (w0[0], w0[1], selector);
      w2[1] = __byte_perm (    0, w0[0], selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      w3[1] = __byte_perm (w0[2], w0[3], selector);
      w3[0] = __byte_perm (w0[1], w0[2], selector);
      w2[3] = __byte_perm (w0[0], w0[1], selector);
      w2[2] = __byte_perm (    0, w0[0], selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      w3[1] = __byte_perm (w0[1], w0[2], selector);
      w3[0] = __byte_perm (w0[0], w0[1], selector);
      w2[3] = __byte_perm (    0, w0[0], selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      w3[1] = __byte_perm (w0[0], w0[1], selector);
      w3[0] = __byte_perm (    0, w0[0], selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      w3[1] = __byte_perm (    0, w0[0], selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif
}

inline void switch_buffer_by_offset_be (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  #if defined IS_AMD || defined IS_GENERIC
  switch (offset / 4)
  {
    case 0:
      w3[2] = amd_bytealign (w3[1],     0, offset);
      w3[1] = amd_bytealign (w3[0], w3[1], offset);
      w3[0] = amd_bytealign (w2[3], w3[0], offset);
      w2[3] = amd_bytealign (w2[2], w2[3], offset);
      w2[2] = amd_bytealign (w2[1], w2[2], offset);
      w2[1] = amd_bytealign (w2[0], w2[1], offset);
      w2[0] = amd_bytealign (w1[3], w2[0], offset);
      w1[3] = amd_bytealign (w1[2], w1[3], offset);
      w1[2] = amd_bytealign (w1[1], w1[2], offset);
      w1[1] = amd_bytealign (w1[0], w1[1], offset);
      w1[0] = amd_bytealign (w0[3], w1[0], offset);
      w0[3] = amd_bytealign (w0[2], w0[3], offset);
      w0[2] = amd_bytealign (w0[1], w0[2], offset);
      w0[1] = amd_bytealign (w0[0], w0[1], offset);
      w0[0] = amd_bytealign (    0, w0[0], offset);
      break;

    case 1:
      w3[2] = amd_bytealign (w3[0],     0, offset);
      w3[1] = amd_bytealign (w2[3], w3[0], offset);
      w3[0] = amd_bytealign (w2[2], w2[3], offset);
      w2[3] = amd_bytealign (w2[1], w2[2], offset);
      w2[2] = amd_bytealign (w2[0], w2[1], offset);
      w2[1] = amd_bytealign (w1[3], w2[0], offset);
      w2[0] = amd_bytealign (w1[2], w1[3], offset);
      w1[3] = amd_bytealign (w1[1], w1[2], offset);
      w1[2] = amd_bytealign (w1[0], w1[1], offset);
      w1[1] = amd_bytealign (w0[3], w1[0], offset);
      w1[0] = amd_bytealign (w0[2], w0[3], offset);
      w0[3] = amd_bytealign (w0[1], w0[2], offset);
      w0[2] = amd_bytealign (w0[0], w0[1], offset);
      w0[1] = amd_bytealign (    0, w0[0], offset);
      w0[0] = 0;
      break;

    case 2:
      w3[2] = amd_bytealign (w2[3],     0, offset);
      w3[1] = amd_bytealign (w2[2], w2[3], offset);
      w3[0] = amd_bytealign (w2[1], w2[2], offset);
      w2[3] = amd_bytealign (w2[0], w2[1], offset);
      w2[2] = amd_bytealign (w1[3], w2[0], offset);
      w2[1] = amd_bytealign (w1[2], w1[3], offset);
      w2[0] = amd_bytealign (w1[1], w1[2], offset);
      w1[3] = amd_bytealign (w1[0], w1[1], offset);
      w1[2] = amd_bytealign (w0[3], w1[0], offset);
      w1[1] = amd_bytealign (w0[2], w0[3], offset);
      w1[0] = amd_bytealign (w0[1], w0[2], offset);
      w0[3] = amd_bytealign (w0[0], w0[1], offset);
      w0[2] = amd_bytealign (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w3[2] = amd_bytealign (w2[2],     0, offset);
      w3[1] = amd_bytealign (w2[1], w2[2], offset);
      w3[0] = amd_bytealign (w2[0], w2[1], offset);
      w2[3] = amd_bytealign (w1[3], w2[0], offset);
      w2[2] = amd_bytealign (w1[2], w1[3], offset);
      w2[1] = amd_bytealign (w1[1], w1[2], offset);
      w2[0] = amd_bytealign (w1[0], w1[1], offset);
      w1[3] = amd_bytealign (w0[3], w1[0], offset);
      w1[2] = amd_bytealign (w0[2], w0[3], offset);
      w1[1] = amd_bytealign (w0[1], w0[2], offset);
      w1[0] = amd_bytealign (w0[0], w0[1], offset);
      w0[3] = amd_bytealign (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 4:
      w3[2] = amd_bytealign (w2[1],     0, offset);
      w3[1] = amd_bytealign (w2[0], w2[1], offset);
      w3[0] = amd_bytealign (w1[3], w2[0], offset);
      w2[3] = amd_bytealign (w1[2], w1[3], offset);
      w2[2] = amd_bytealign (w1[1], w1[2], offset);
      w2[1] = amd_bytealign (w1[0], w1[1], offset);
      w2[0] = amd_bytealign (w0[3], w1[0], offset);
      w1[3] = amd_bytealign (w0[2], w0[3], offset);
      w1[2] = amd_bytealign (w0[1], w0[2], offset);
      w1[1] = amd_bytealign (w0[0], w0[1], offset);
      w1[0] = amd_bytealign (    0, w0[0], offset);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 5:
      w3[2] = amd_bytealign (w2[0],     0, offset);
      w3[1] = amd_bytealign (w1[3], w2[0], offset);
      w3[0] = amd_bytealign (w1[2], w1[3], offset);
      w2[3] = amd_bytealign (w1[1], w1[2], offset);
      w2[2] = amd_bytealign (w1[0], w1[1], offset);
      w2[1] = amd_bytealign (w0[3], w1[0], offset);
      w2[0] = amd_bytealign (w0[2], w0[3], offset);
      w1[3] = amd_bytealign (w0[1], w0[2], offset);
      w1[2] = amd_bytealign (w0[0], w0[1], offset);
      w1[1] = amd_bytealign (    0, w0[0], offset);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 6:
      w3[2] = amd_bytealign (w1[3],     0, offset);
      w3[1] = amd_bytealign (w1[2], w1[3], offset);
      w3[0] = amd_bytealign (w1[1], w1[2], offset);
      w2[3] = amd_bytealign (w1[0], w1[1], offset);
      w2[2] = amd_bytealign (w0[3], w1[0], offset);
      w2[1] = amd_bytealign (w0[2], w0[3], offset);
      w2[0] = amd_bytealign (w0[1], w0[2], offset);
      w1[3] = amd_bytealign (w0[0], w0[1], offset);
      w1[2] = amd_bytealign (    0, w0[0], offset);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 7:
      w3[2] = amd_bytealign (w1[2],     0, offset);
      w3[1] = amd_bytealign (w1[1], w1[2], offset);
      w3[0] = amd_bytealign (w1[0], w1[1], offset);
      w2[3] = amd_bytealign (w0[3], w1[0], offset);
      w2[2] = amd_bytealign (w0[2], w0[3], offset);
      w2[1] = amd_bytealign (w0[1], w0[2], offset);
      w2[0] = amd_bytealign (w0[0], w0[1], offset);
      w1[3] = amd_bytealign (    0, w0[0], offset);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 8:
      w3[2] = amd_bytealign (w1[1],     0, offset);
      w3[1] = amd_bytealign (w1[0], w1[1], offset);
      w3[0] = amd_bytealign (w0[3], w1[0], offset);
      w2[3] = amd_bytealign (w0[2], w0[3], offset);
      w2[2] = amd_bytealign (w0[1], w0[2], offset);
      w2[1] = amd_bytealign (w0[0], w0[1], offset);
      w2[0] = amd_bytealign (    0, w0[0], offset);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 9:
      w3[2] = amd_bytealign (w1[0],     0, offset);
      w3[1] = amd_bytealign (w0[3], w1[0], offset);
      w3[0] = amd_bytealign (w0[2], w0[3], offset);
      w2[3] = amd_bytealign (w0[1], w0[2], offset);
      w2[2] = amd_bytealign (w0[0], w0[1], offset);
      w2[1] = amd_bytealign (    0, w0[0], offset);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 10:
      w3[2] = amd_bytealign (w0[3],     0, offset);
      w3[1] = amd_bytealign (w0[2], w0[3], offset);
      w3[0] = amd_bytealign (w0[1], w0[2], offset);
      w2[3] = amd_bytealign (w0[0], w0[1], offset);
      w2[2] = amd_bytealign (    0, w0[0], offset);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 11:
      w3[2] = amd_bytealign (w0[2],     0, offset);
      w3[1] = amd_bytealign (w0[1], w0[2], offset);
      w3[0] = amd_bytealign (w0[0], w0[1], offset);
      w2[3] = amd_bytealign (    0, w0[0], offset);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 12:
      w3[2] = amd_bytealign (w0[1],     0, offset);
      w3[1] = amd_bytealign (w0[0], w0[1], offset);
      w3[0] = amd_bytealign (    0, w0[0], offset);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 13:
      w3[2] = amd_bytealign (w0[0],     0, offset);
      w3[1] = amd_bytealign (    0, w0[0], offset);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w3[1] = __byte_perm (w3[1], w3[0], selector);
      w3[0] = __byte_perm (w3[0], w2[3], selector);
      w2[3] = __byte_perm (w2[3], w2[2], selector);
      w2[2] = __byte_perm (w2[2], w2[1], selector);
      w2[1] = __byte_perm (w2[1], w2[0], selector);
      w2[0] = __byte_perm (w2[0], w1[3], selector);
      w1[3] = __byte_perm (w1[3], w1[2], selector);
      w1[2] = __byte_perm (w1[2], w1[1], selector);
      w1[1] = __byte_perm (w1[1], w1[0], selector);
      w1[0] = __byte_perm (w1[0], w0[3], selector);
      w0[3] = __byte_perm (w0[3], w0[2], selector);
      w0[2] = __byte_perm (w0[2], w0[1], selector);
      w0[1] = __byte_perm (w0[1], w0[0], selector);
      w0[0] = __byte_perm (w0[0],     0, selector);
      break;

    case 1:
      w3[1] = __byte_perm (w3[0], w2[3], selector);
      w3[0] = __byte_perm (w2[3], w2[2], selector);
      w2[3] = __byte_perm (w2[2], w2[1], selector);
      w2[2] = __byte_perm (w2[1], w2[0], selector);
      w2[1] = __byte_perm (w2[0], w1[3], selector);
      w2[0] = __byte_perm (w1[3], w1[2], selector);
      w1[3] = __byte_perm (w1[2], w1[1], selector);
      w1[2] = __byte_perm (w1[1], w1[0], selector);
      w1[1] = __byte_perm (w1[0], w0[3], selector);
      w1[0] = __byte_perm (w0[3], w0[2], selector);
      w0[3] = __byte_perm (w0[2], w0[1], selector);
      w0[2] = __byte_perm (w0[1], w0[0], selector);
      w0[1] = __byte_perm (w0[0],     0, selector);
      w0[0] = 0;
      break;

    case 2:
      w3[1] = __byte_perm (w2[3], w2[2], selector);
      w3[0] = __byte_perm (w2[2], w2[1], selector);
      w2[3] = __byte_perm (w2[1], w2[0], selector);
      w2[2] = __byte_perm (w2[0], w1[3], selector);
      w2[1] = __byte_perm (w1[3], w1[2], selector);
      w2[0] = __byte_perm (w1[2], w1[1], selector);
      w1[3] = __byte_perm (w1[1], w1[0], selector);
      w1[2] = __byte_perm (w1[0], w0[3], selector);
      w1[1] = __byte_perm (w0[3], w0[2], selector);
      w1[0] = __byte_perm (w0[2], w0[1], selector);
      w0[3] = __byte_perm (w0[1], w0[0], selector);
      w0[2] = __byte_perm (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w3[1] = __byte_perm (w2[2], w2[1], selector);
      w3[0] = __byte_perm (w2[1], w2[0], selector);
      w2[3] = __byte_perm (w2[0], w1[3], selector);
      w2[2] = __byte_perm (w1[3], w1[2], selector);
      w2[1] = __byte_perm (w1[2], w1[1], selector);
      w2[0] = __byte_perm (w1[1], w1[0], selector);
      w1[3] = __byte_perm (w1[0], w0[3], selector);
      w1[2] = __byte_perm (w0[3], w0[2], selector);
      w1[1] = __byte_perm (w0[2], w0[1], selector);
      w1[0] = __byte_perm (w0[1], w0[0], selector);
      w0[3] = __byte_perm (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 4:
      w3[1] = __byte_perm (w2[1], w2[0], selector);
      w3[0] = __byte_perm (w2[0], w1[3], selector);
      w2[3] = __byte_perm (w1[3], w1[2], selector);
      w2[2] = __byte_perm (w1[2], w1[1], selector);
      w2[1] = __byte_perm (w1[1], w1[0], selector);
      w2[0] = __byte_perm (w1[0], w0[3], selector);
      w1[3] = __byte_perm (w0[3], w0[2], selector);
      w1[2] = __byte_perm (w0[2], w0[1], selector);
      w1[1] = __byte_perm (w0[1], w0[0], selector);
      w1[0] = __byte_perm (w0[0],     0, selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 5:
      w3[1] = __byte_perm (w2[0], w1[3], selector);
      w3[0] = __byte_perm (w1[3], w1[2], selector);
      w2[3] = __byte_perm (w1[2], w1[1], selector);
      w2[2] = __byte_perm (w1[1], w1[0], selector);
      w2[1] = __byte_perm (w1[0], w0[3], selector);
      w2[0] = __byte_perm (w0[3], w0[2], selector);
      w1[3] = __byte_perm (w0[2], w0[1], selector);
      w1[2] = __byte_perm (w0[1], w0[0], selector);
      w1[1] = __byte_perm (w0[0],     0, selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 6:
      w3[1] = __byte_perm (w1[3], w1[2], selector);
      w3[0] = __byte_perm (w1[2], w1[1], selector);
      w2[3] = __byte_perm (w1[1], w1[0], selector);
      w2[2] = __byte_perm (w1[0], w0[3], selector);
      w2[1] = __byte_perm (w0[3], w0[2], selector);
      w2[0] = __byte_perm (w0[2], w0[1], selector);
      w1[3] = __byte_perm (w0[1], w0[0], selector);
      w1[2] = __byte_perm (w0[0],     0, selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 7:
      w3[1] = __byte_perm (w1[2], w1[1], selector);
      w3[0] = __byte_perm (w1[1], w1[0], selector);
      w2[3] = __byte_perm (w1[0], w0[3], selector);
      w2[2] = __byte_perm (w0[3], w0[2], selector);
      w2[1] = __byte_perm (w0[2], w0[1], selector);
      w2[0] = __byte_perm (w0[1], w0[0], selector);
      w1[3] = __byte_perm (w0[0],     0, selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 8:
      w3[1] = __byte_perm (w1[1], w1[0], selector);
      w3[0] = __byte_perm (w1[0], w0[3], selector);
      w2[3] = __byte_perm (w0[3], w0[2], selector);
      w2[2] = __byte_perm (w0[2], w0[1], selector);
      w2[1] = __byte_perm (w0[1], w0[0], selector);
      w2[0] = __byte_perm (w0[0],     0, selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 9:
      w3[1] = __byte_perm (w1[0], w0[3], selector);
      w3[0] = __byte_perm (w0[3], w0[2], selector);
      w2[3] = __byte_perm (w0[2], w0[1], selector);
      w2[2] = __byte_perm (w0[1], w0[0], selector);
      w2[1] = __byte_perm (w0[0],     0, selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 10:
      w3[1] = __byte_perm (w0[3], w0[2], selector);
      w3[0] = __byte_perm (w0[2], w0[1], selector);
      w2[3] = __byte_perm (w0[1], w0[0], selector);
      w2[2] = __byte_perm (w0[0],     0, selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 11:
      w3[1] = __byte_perm (w0[2], w0[1], selector);
      w3[0] = __byte_perm (w0[1], w0[0], selector);
      w2[3] = __byte_perm (w0[0],     0, selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 12:
      w3[1] = __byte_perm (w0[1], w0[0], selector);
      w3[0] = __byte_perm (w0[0],     0, selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 13:
      w3[1] = __byte_perm (w0[0],     0, selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif
}

inline void overwrite_at_le (u32x sw[16], const u32x w0, const u32 salt_len)
{
  #if defined cl_amd_media_ops
  switch (salt_len)
  {
    case  0:  sw[0] = w0;
              break;
    case  1:  sw[0] = amd_bytealign (w0, sw[0] << 24, 3);
              sw[1] = amd_bytealign (sw[1] >>  8, w0, 3);
              break;
    case  2:  sw[0] = amd_bytealign (w0, sw[0] << 16, 2);
              sw[1] = amd_bytealign (sw[1] >> 16, w0, 2);
              break;
    case  3:  sw[0] = amd_bytealign (w0, sw[0] <<  8, 1);
              sw[1] = amd_bytealign (sw[1] >> 24, w0, 1);
              break;
    case  4:  sw[1] = w0;
              break;
    case  5:  sw[1] = amd_bytealign (w0, sw[1] << 24, 3);
              sw[2] = amd_bytealign (sw[2] >>  8, w0, 3);
              break;
    case  6:  sw[1] = amd_bytealign (w0, sw[1] << 16, 2);
              sw[2] = amd_bytealign (sw[2] >> 16, w0, 2);
              break;
    case  7:  sw[1] = amd_bytealign (w0, sw[1] <<  8, 1);
              sw[2] = amd_bytealign (sw[2] >> 24, w0, 1);
              break;
    case  8:  sw[2] = w0;
              break;
    case  9:  sw[2] = amd_bytealign (w0, sw[2] << 24, 3);
              sw[3] = amd_bytealign (sw[3] >>  8, w0, 3);
              break;
    case 10:  sw[2] = amd_bytealign (w0, sw[2] << 16, 2);
              sw[3] = amd_bytealign (sw[3] >> 16, w0, 2);
              break;
    case 11:  sw[2] = amd_bytealign (w0, sw[2] <<  8, 1);
              sw[3] = amd_bytealign (sw[3] >> 24, w0, 1);
              break;
    case 12:  sw[3] = w0;
              break;
    case 13:  sw[3] = amd_bytealign (w0, sw[3] << 24, 3);
              sw[4] = amd_bytealign (sw[4] >>  8, w0, 3);
              break;
    case 14:  sw[3] = amd_bytealign (w0, sw[3] << 16, 2);
              sw[4] = amd_bytealign (sw[4] >> 16, w0, 2);
              break;
    case 15:  sw[3] = amd_bytealign (w0, sw[3] <<  8, 1);
              sw[4] = amd_bytealign (sw[4] >> 24, w0, 1);
              break;
    case 16:  sw[4] = w0;
              break;
    case 17:  sw[4] = amd_bytealign (w0, sw[4] << 24, 3);
              sw[5] = amd_bytealign (sw[5] >>  8, w0, 3);
              break;
    case 18:  sw[4] = amd_bytealign (w0, sw[4] << 16, 2);
              sw[5] = amd_bytealign (sw[5] >> 16, w0, 2);
              break;
    case 19:  sw[4] = amd_bytealign (w0, sw[4] <<  8, 1);
              sw[5] = amd_bytealign (sw[5] >> 24, w0, 1);
              break;
    case 20:  sw[5] = w0;
              break;
    case 21:  sw[5] = amd_bytealign (w0, sw[5] << 24, 3);
              sw[6] = amd_bytealign (sw[6] >>  8, w0, 3);
              break;
    case 22:  sw[5] = amd_bytealign (w0, sw[5] << 16, 2);
              sw[6] = amd_bytealign (sw[6] >> 16, w0, 2);
              break;
    case 23:  sw[5] = amd_bytealign (w0, sw[5] <<  8, 1);
              sw[6] = amd_bytealign (sw[6] >> 24, w0, 1);
              break;
    case 24:  sw[6] = w0;
              break;
    case 25:  sw[6] = amd_bytealign (w0, sw[6] << 24, 3);
              sw[7] = amd_bytealign (sw[7] >>  8, w0, 3);
              break;
    case 26:  sw[6] = amd_bytealign (w0, sw[6] << 16, 2);
              sw[7] = amd_bytealign (sw[7] >> 16, w0, 2);
              break;
    case 27:  sw[6] = amd_bytealign (w0, sw[6] <<  8, 1);
              sw[7] = amd_bytealign (sw[7] >> 24, w0, 1);
              break;
    case 28:  sw[7] = w0;
              break;
    case 29:  sw[7] = amd_bytealign (w0, sw[7] << 24, 3);
              sw[8] = amd_bytealign (sw[8] >>  8, w0, 3);
              break;
    case 30:  sw[7] = amd_bytealign (w0, sw[7] << 16, 2);
              sw[8] = amd_bytealign (sw[8] >> 16, w0, 2);
              break;
    case 31:  sw[7] = amd_bytealign (w0, sw[7] <<  8, 1);
              sw[8] = amd_bytealign (sw[8] >> 24, w0, 1);
              break;
  }
  #else
  switch (salt_len)
  {
    case  0:  sw[0] =  w0;
              break;
    case  1:  sw[0] = (sw[0] & 0x000000ff) | (w0 <<  8);
              sw[1] = (sw[1] & 0xffffff00) | (w0 >> 24);
              break;
    case  2:  sw[0] = (sw[0] & 0x0000ffff) | (w0 << 16);
              sw[1] = (sw[1] & 0xffff0000) | (w0 >> 16);
              break;
    case  3:  sw[0] = (sw[0] & 0x00ffffff) | (w0 << 24);
              sw[1] = (sw[1] & 0xff000000) | (w0 >>  8);
              break;
    case  4:  sw[1] =  w0;
              break;
    case  5:  sw[1] = (sw[1] & 0x000000ff) | (w0 <<  8);
              sw[2] = (sw[2] & 0xffffff00) | (w0 >> 24);
              break;
    case  6:  sw[1] = (sw[1] & 0x0000ffff) | (w0 << 16);
              sw[2] = (sw[2] & 0xffff0000) | (w0 >> 16);
              break;
    case  7:  sw[1] = (sw[1] & 0x00ffffff) | (w0 << 24);
              sw[2] = (sw[2] & 0xff000000) | (w0 >>  8);
              break;
    case  8:  sw[2] =  w0;
              break;
    case  9:  sw[2] = (sw[2] & 0x000000ff) | (w0 <<  8);
              sw[3] = (sw[3] & 0xffffff00) | (w0 >> 24);
              break;
    case 10:  sw[2] = (sw[2] & 0x0000ffff) | (w0 << 16);
              sw[3] = (sw[3] & 0xffff0000) | (w0 >> 16);
              break;
    case 11:  sw[2] = (sw[2] & 0x00ffffff) | (w0 << 24);
              sw[3] = (sw[3] & 0xff000000) | (w0 >>  8);
              break;
    case 12:  sw[3] =  w0;
              break;
    case 13:  sw[3] = (sw[3] & 0x000000ff) | (w0 <<  8);
              sw[4] = (sw[4] & 0xffffff00) | (w0 >> 24);
              break;
    case 14:  sw[3] = (sw[3] & 0x0000ffff) | (w0 << 16);
              sw[4] = (sw[4] & 0xffff0000) | (w0 >> 16);
              break;
    case 15:  sw[3] = (sw[3] & 0x00ffffff) | (w0 << 24);
              sw[4] = (sw[4] & 0xff000000) | (w0 >>  8);
              break;
    case 16:  sw[4] =  w0;
              break;
    case 17:  sw[4] = (sw[4] & 0x000000ff) | (w0 <<  8);
              sw[5] = (sw[5] & 0xffffff00) | (w0 >> 24);
              break;
    case 18:  sw[4] = (sw[4] & 0x0000ffff) | (w0 << 16);
              sw[5] = (sw[5] & 0xffff0000) | (w0 >> 16);
              break;
    case 19:  sw[4] = (sw[4] & 0x00ffffff) | (w0 << 24);
              sw[5] = (sw[5] & 0xff000000) | (w0 >>  8);
              break;
    case 20:  sw[5] =  w0;
              break;
    case 21:  sw[5] = (sw[5] & 0x000000ff) | (w0 <<  8);
              sw[6] = (sw[6] & 0xffffff00) | (w0 >> 24);
              break;
    case 22:  sw[5] = (sw[5] & 0x0000ffff) | (w0 << 16);
              sw[6] = (sw[6] & 0xffff0000) | (w0 >> 16);
              break;
    case 23:  sw[5] = (sw[5] & 0x00ffffff) | (w0 << 24);
              sw[6] = (sw[6] & 0xff000000) | (w0 >>  8);
              break;
    case 24:  sw[6] =  w0;
              break;
    case 25:  sw[6] = (sw[6] & 0x000000ff) | (w0 <<  8);
              sw[7] = (sw[7] & 0xffffff00) | (w0 >> 24);
              break;
    case 26:  sw[6] = (sw[6] & 0x0000ffff) | (w0 << 16);
              sw[7] = (sw[7] & 0xffff0000) | (w0 >> 16);
              break;
    case 27:  sw[6] = (sw[6] & 0x00ffffff) | (w0 << 24);
              sw[7] = (sw[7] & 0xff000000) | (w0 >>  8);
              break;
    case 28:  sw[7] =  w0;
              break;
    case 29:  sw[7] = (sw[7] & 0x000000ff) | (w0 <<  8);
              sw[8] = (sw[8] & 0xffffff00) | (w0 >> 24);
              break;
    case 30:  sw[7] = (sw[7] & 0x0000ffff) | (w0 << 16);
              sw[8] = (sw[8] & 0xffff0000) | (w0 >> 16);
              break;
    case 31:  sw[7] = (sw[7] & 0x00ffffff) | (w0 << 24);
              sw[8] = (sw[8] & 0xff000000) | (w0 >>  8);
              break;
  }
  #endif
}

inline void overwrite_at_be (u32x sw[16], const u32x w0, const u32 salt_len)
{
  // would be nice to have optimization based on amd_bytealign as with _le counterpart

  switch (salt_len)
  {
    case  0:  sw[0] =  w0;
              break;
    case  1:  sw[0] = (sw[0] & 0xff000000) | (w0 >>  8);
              sw[1] = (sw[1] & 0x00ffffff) | (w0 << 24);
              break;
    case  2:  sw[0] = (sw[0] & 0xffff0000) | (w0 >> 16);
              sw[1] = (sw[1] & 0x0000ffff) | (w0 << 16);
              break;
    case  3:  sw[0] = (sw[0] & 0xffffff00) | (w0 >> 24);
              sw[1] = (sw[1] & 0x000000ff) | (w0 <<  8);
              break;
    case  4:  sw[1] =  w0;
              break;
    case  5:  sw[1] = (sw[1] & 0xff000000) | (w0 >>  8);
              sw[2] = (sw[2] & 0x00ffffff) | (w0 << 24);
              break;
    case  6:  sw[1] = (sw[1] & 0xffff0000) | (w0 >> 16);
              sw[2] = (sw[2] & 0x0000ffff) | (w0 << 16);
              break;
    case  7:  sw[1] = (sw[1] & 0xffffff00) | (w0 >> 24);
              sw[2] = (sw[2] & 0x000000ff) | (w0 <<  8);
              break;
    case  8:  sw[2] =  w0;
              break;
    case  9:  sw[2] = (sw[2] & 0xff000000) | (w0 >>  8);
              sw[3] = (sw[3] & 0x00ffffff) | (w0 << 24);
              break;
    case 10:  sw[2] = (sw[2] & 0xffff0000) | (w0 >> 16);
              sw[3] = (sw[3] & 0x0000ffff) | (w0 << 16);
              break;
    case 11:  sw[2] = (sw[2] & 0xffffff00) | (w0 >> 24);
              sw[3] = (sw[3] & 0x000000ff) | (w0 <<  8);
              break;
    case 12:  sw[3] =  w0;
              break;
    case 13:  sw[3] = (sw[3] & 0xff000000) | (w0 >>  8);
              sw[4] = (sw[4] & 0x00ffffff) | (w0 << 24);
              break;
    case 14:  sw[3] = (sw[3] & 0xffff0000) | (w0 >> 16);
              sw[4] = (sw[4] & 0x0000ffff) | (w0 << 16);
              break;
    case 15:  sw[3] = (sw[3] & 0xffffff00) | (w0 >> 24);
              sw[4] = (sw[4] & 0x000000ff) | (w0 <<  8);
              break;
    case 16:  sw[4] =  w0;
              break;
    case 17:  sw[4] = (sw[4] & 0xff000000) | (w0 >>  8);
              sw[5] = (sw[5] & 0x00ffffff) | (w0 << 24);
              break;
    case 18:  sw[4] = (sw[4] & 0xffff0000) | (w0 >> 16);
              sw[5] = (sw[5] & 0x0000ffff) | (w0 << 16);
              break;
    case 19:  sw[4] = (sw[4] & 0xffffff00) | (w0 >> 24);
              sw[5] = (sw[5] & 0x000000ff) | (w0 <<  8);
              break;
    case 20:  sw[5] =  w0;
              break;
    case 21:  sw[5] = (sw[5] & 0xff000000) | (w0 >>  8);
              sw[6] = (sw[6] & 0x00ffffff) | (w0 << 24);
              break;
    case 22:  sw[5] = (sw[5] & 0xffff0000) | (w0 >> 16);
              sw[6] = (sw[6] & 0x0000ffff) | (w0 << 16);
              break;
    case 23:  sw[5] = (sw[5] & 0xffffff00) | (w0 >> 24);
              sw[6] = (sw[6] & 0x000000ff) | (w0 <<  8);
              break;
    case 24:  sw[6] =  w0;
              break;
    case 25:  sw[6] = (sw[6] & 0xff000000) | (w0 >>  8);
              sw[7] = (sw[7] & 0x00ffffff) | (w0 << 24);
              break;
    case 26:  sw[6] = (sw[6] & 0xffff0000) | (w0 >> 16);
              sw[7] = (sw[7] & 0x0000ffff) | (w0 << 16);
              break;
    case 27:  sw[6] = (sw[6] & 0xffffff00) | (w0 >> 24);
              sw[7] = (sw[7] & 0x000000ff) | (w0 <<  8);
              break;
    case 28:  sw[7] =  w0;
              break;
    case 29:  sw[7] = (sw[7] & 0xff000000) | (w0 >>  8);
              sw[8] = (sw[8] & 0x00ffffff) | (w0 << 24);
              break;
    case 30:  sw[7] = (sw[7] & 0xffff0000) | (w0 >> 16);
              sw[8] = (sw[8] & 0x0000ffff) | (w0 << 16);
              break;
    case 31:  sw[7] = (sw[7] & 0xffffff00) | (w0 >> 24);
              sw[8] = (sw[8] & 0x000000ff) | (w0 <<  8);
              break;
  }
}

inline void overwrite_at_le_4x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32x wx, const u32 salt_len)
{
  #if defined cl_amd_media_ops
  switch (salt_len)
  {
    case  0:  w0[0] = wx;
              break;
    case  1:  w0[0] = amd_bytealign (wx, w0[0] << 24, 3);
              w0[1] = amd_bytealign (w0[1] >>  8, wx, 3);
              break;
    case  2:  w0[0] = amd_bytealign (wx, w0[0] << 16, 2);
              w0[1] = amd_bytealign (w0[1] >> 16, wx, 2);
              break;
    case  3:  w0[0] = amd_bytealign (wx, w0[0] <<  8, 1);
              w0[1] = amd_bytealign (w0[1] >> 24, wx, 1);
              break;
    case  4:  w0[1] = wx;
              break;
    case  5:  w0[1] = amd_bytealign (wx, w0[1] << 24, 3);
              w0[2] = amd_bytealign (w0[2] >>  8, wx, 3);
              break;
    case  6:  w0[1] = amd_bytealign (wx, w0[1] << 16, 2);
              w0[2] = amd_bytealign (w0[2] >> 16, wx, 2);
              break;
    case  7:  w0[1] = amd_bytealign (wx, w0[1] <<  8, 1);
              w0[2] = amd_bytealign (w0[2] >> 24, wx, 1);
              break;
    case  8:  w0[2] = wx;
              break;
    case  9:  w0[2] = amd_bytealign (wx, w0[2] << 24, 3);
              w0[3] = amd_bytealign (w0[3] >>  8, wx, 3);
              break;
    case 10:  w0[2] = amd_bytealign (wx, w0[2] << 16, 2);
              w0[3] = amd_bytealign (w0[3] >> 16, wx, 2);
              break;
    case 11:  w0[2] = amd_bytealign (wx, w0[2] <<  8, 1);
              w0[3] = amd_bytealign (w0[3] >> 24, wx, 1);
              break;
    case 12:  w0[3] = wx;
              break;
    case 13:  w0[3] = amd_bytealign (wx, w0[3] << 24, 3);
              w1[0] = amd_bytealign (w1[0] >>  8, wx, 3);
              break;
    case 14:  w0[3] = amd_bytealign (wx, w0[3] << 16, 2);
              w1[0] = amd_bytealign (w1[0] >> 16, wx, 2);
              break;
    case 15:  w0[3] = amd_bytealign (wx, w0[3] <<  8, 1);
              w1[0] = amd_bytealign (w1[0] >> 24, wx, 1);
              break;
    case 16:  w1[0] = wx;
              break;
    case 17:  w1[0] = amd_bytealign (wx, w1[0] << 24, 3);
              w1[1] = amd_bytealign (w1[1] >>  8, wx, 3);
              break;
    case 18:  w1[0] = amd_bytealign (wx, w1[0] << 16, 2);
              w1[1] = amd_bytealign (w1[1] >> 16, wx, 2);
              break;
    case 19:  w1[0] = amd_bytealign (wx, w1[0] <<  8, 1);
              w1[1] = amd_bytealign (w1[1] >> 24, wx, 1);
              break;
    case 20:  w1[1] = wx;
              break;
    case 21:  w1[1] = amd_bytealign (wx, w1[1] << 24, 3);
              w1[2] = amd_bytealign (w1[2] >>  8, wx, 3);
              break;
    case 22:  w1[1] = amd_bytealign (wx, w1[1] << 16, 2);
              w1[2] = amd_bytealign (w1[2] >> 16, wx, 2);
              break;
    case 23:  w1[1] = amd_bytealign (wx, w1[1] <<  8, 1);
              w1[2] = amd_bytealign (w1[2] >> 24, wx, 1);
              break;
    case 24:  w1[2] = wx;
              break;
    case 25:  w1[2] = amd_bytealign (wx, w1[2] << 24, 3);
              w1[3] = amd_bytealign (w1[3] >>  8, wx, 3);
              break;
    case 26:  w1[2] = amd_bytealign (wx, w1[2] << 16, 2);
              w1[3] = amd_bytealign (w1[3] >> 16, wx, 2);
              break;
    case 27:  w1[2] = amd_bytealign (wx, w1[2] <<  8, 1);
              w1[3] = amd_bytealign (w1[3] >> 24, wx, 1);
              break;
    case 28:  w1[3] = wx;
              break;
    case 29:  w1[3] = amd_bytealign (wx, w1[3] << 24, 3);
              w2[0] = amd_bytealign (w2[0] >>  8, wx, 3);
              break;
    case 30:  w1[3] = amd_bytealign (wx, w1[3] << 16, 2);
              w2[0] = amd_bytealign (w2[0] >> 16, wx, 2);
              break;
    case 31:  w1[3] = amd_bytealign (wx, w1[3] <<  8, 1);
              w2[0] = amd_bytealign (w2[0] >> 24, wx, 1);
              break;
    case 32:  w2[0] = wx;
              break;
    case 33:  w2[0] = amd_bytealign (wx, w2[0] << 24, 3);
              w2[1] = amd_bytealign (w2[1] >>  8, wx, 3);
              break;
    case 34:  w2[0] = amd_bytealign (wx, w2[0] << 16, 2);
              w2[1] = amd_bytealign (w2[1] >> 16, wx, 2);
              break;
    case 35:  w2[0] = amd_bytealign (wx, w2[0] <<  8, 1);
              w2[1] = amd_bytealign (w2[1] >> 24, wx, 1);
              break;
    case 36:  w2[1] = wx;
              break;
    case 37:  w2[1] = amd_bytealign (wx, w2[1] << 24, 3);
              w2[2] = amd_bytealign (w2[2] >>  8, wx, 3);
              break;
    case 38:  w2[1] = amd_bytealign (wx, w2[1] << 16, 2);
              w2[2] = amd_bytealign (w2[2] >> 16, wx, 2);
              break;
    case 39:  w2[1] = amd_bytealign (wx, w2[1] <<  8, 1);
              w2[2] = amd_bytealign (w2[2] >> 24, wx, 1);
              break;
    case 40:  w2[2] = wx;
              break;
    case 41:  w2[2] = amd_bytealign (wx, w2[2] << 24, 3);
              w2[3] = amd_bytealign (w2[3] >>  8, wx, 3);
              break;
    case 42:  w2[2] = amd_bytealign (wx, w2[2] << 16, 2);
              w2[3] = amd_bytealign (w2[3] >> 16, wx, 2);
              break;
    case 43:  w2[2] = amd_bytealign (wx, w2[2] <<  8, 1);
              w2[3] = amd_bytealign (w2[3] >> 24, wx, 1);
              break;
    case 44:  w2[3] = wx;
              break;
    case 45:  w2[3] = amd_bytealign (wx, w2[3] << 24, 3);
              w3[0] = amd_bytealign (w3[0] >>  8, wx, 3);
              break;
    case 46:  w2[3] = amd_bytealign (wx, w2[3] << 16, 2);
              w3[0] = amd_bytealign (w3[0] >> 16, wx, 2);
              break;
    case 47:  w2[3] = amd_bytealign (wx, w2[3] <<  8, 1);
              w3[0] = amd_bytealign (w3[0] >> 24, wx, 1);
              break;
    case 48:  w3[0] = wx;
              break;
    case 49:  w3[0] = amd_bytealign (wx, w3[0] << 24, 3);
              w3[1] = amd_bytealign (w3[1] >>  8, wx, 3);
              break;
    case 50:  w3[0] = amd_bytealign (wx, w3[0] << 16, 2);
              w3[1] = amd_bytealign (w3[1] >> 16, wx, 2);
              break;
    case 51:  w3[0] = amd_bytealign (wx, w3[0] <<  8, 1);
              w3[1] = amd_bytealign (w3[1] >> 24, wx, 1);
              break;
    case 52:  w3[1] = wx;
              break;
    case 53:  w3[1] = amd_bytealign (wx, w3[1] << 24, 3);
              w3[2] = amd_bytealign (w3[2] >>  8, wx, 3);
              break;
    case 54:  w3[1] = amd_bytealign (wx, w3[1] << 16, 2);
              w3[2] = amd_bytealign (w3[2] >> 16, wx, 2);
              break;
    case 55:  w3[1] = amd_bytealign (wx, w3[1] <<  8, 1);
              w3[2] = amd_bytealign (w3[2] >> 24, wx, 1);
              break;
    case 56:  w3[2] = wx;
              break;
    case 57:  w3[2] = amd_bytealign (wx, w3[2] << 24, 3);
              w3[3] = amd_bytealign (w3[3] >>  8, wx, 3);
              break;
    case 58:  w3[2] = amd_bytealign (wx, w3[2] << 16, 2);
              w3[3] = amd_bytealign (w3[3] >> 16, wx, 2);
              break;
    case 59:  w3[2] = amd_bytealign (wx, w3[2] <<  8, 1);
              w3[3] = amd_bytealign (w3[3] >> 24, wx, 1);
              break;
    case 60:  w3[3] = wx;
              break;
    case 61:  w3[3] = amd_bytealign (wx, w3[3] << 24, 3);
              //w4[0] = amd_bytealign (w4[0] >>  8, wx, 3);
              break;
    case 62:  w3[3] = amd_bytealign (wx, w3[3] << 16, 2);
              //w4[0] = amd_bytealign (w4[0] >> 16, wx, 2);
              break;
    case 63:  w3[3] = amd_bytealign (wx, w3[3] <<  8, 1);
              //w4[0] = amd_bytealign (w4[0] >> 24, wx, 1);
              break;
  }
  #else
  switch (salt_len)
  {
    case  0:  w0[0] =  wx;
              break;
    case  1:  w0[0] = (w0[0] & 0x000000ff) | (wx <<  8);
              w0[1] = (w0[1] & 0xffffff00) | (wx >> 24);
              break;
    case  2:  w0[0] = (w0[0] & 0x0000ffff) | (wx << 16);
              w0[1] = (w0[1] & 0xffff0000) | (wx >> 16);
              break;
    case  3:  w0[0] = (w0[0] & 0x00ffffff) | (wx << 24);
              w0[1] = (w0[1] & 0xff000000) | (wx >>  8);
              break;
    case  4:  w0[1] =  wx;
              break;
    case  5:  w0[1] = (w0[1] & 0x000000ff) | (wx <<  8);
              w0[2] = (w0[2] & 0xffffff00) | (wx >> 24);
              break;
    case  6:  w0[1] = (w0[1] & 0x0000ffff) | (wx << 16);
              w0[2] = (w0[2] & 0xffff0000) | (wx >> 16);
              break;
    case  7:  w0[1] = (w0[1] & 0x00ffffff) | (wx << 24);
              w0[2] = (w0[2] & 0xff000000) | (wx >>  8);
              break;
    case  8:  w0[2] =  wx;
              break;
    case  9:  w0[2] = (w0[2] & 0x000000ff) | (wx <<  8);
              w0[3] = (w0[3] & 0xffffff00) | (wx >> 24);
              break;
    case 10:  w0[2] = (w0[2] & 0x0000ffff) | (wx << 16);
              w0[3] = (w0[3] & 0xffff0000) | (wx >> 16);
              break;
    case 11:  w0[2] = (w0[2] & 0x00ffffff) | (wx << 24);
              w0[3] = (w0[3] & 0xff000000) | (wx >>  8);
              break;
    case 12:  w0[3] =  wx;
              break;
    case 13:  w0[3] = (w0[3] & 0x000000ff) | (wx <<  8);
              w1[0] = (w1[0] & 0xffffff00) | (wx >> 24);
              break;
    case 14:  w0[3] = (w0[3] & 0x0000ffff) | (wx << 16);
              w1[0] = (w1[0] & 0xffff0000) | (wx >> 16);
              break;
    case 15:  w0[3] = (w0[3] & 0x00ffffff) | (wx << 24);
              w1[0] = (w1[0] & 0xff000000) | (wx >>  8);
              break;
    case 16:  w1[0] =  wx;
              break;
    case 17:  w1[0] = (w1[0] & 0x000000ff) | (wx <<  8);
              w1[1] = (w1[1] & 0xffffff00) | (wx >> 24);
              break;
    case 18:  w1[0] = (w1[0] & 0x0000ffff) | (wx << 16);
              w1[1] = (w1[1] & 0xffff0000) | (wx >> 16);
              break;
    case 19:  w1[0] = (w1[0] & 0x00ffffff) | (wx << 24);
              w1[1] = (w1[1] & 0xff000000) | (wx >>  8);
              break;
    case 20:  w1[1] =  wx;
              break;
    case 21:  w1[1] = (w1[1] & 0x000000ff) | (wx <<  8);
              w1[2] = (w1[2] & 0xffffff00) | (wx >> 24);
              break;
    case 22:  w1[1] = (w1[1] & 0x0000ffff) | (wx << 16);
              w1[2] = (w1[2] & 0xffff0000) | (wx >> 16);
              break;
    case 23:  w1[1] = (w1[1] & 0x00ffffff) | (wx << 24);
              w1[2] = (w1[2] & 0xff000000) | (wx >>  8);
              break;
    case 24:  w1[2] =  wx;
              break;
    case 25:  w1[2] = (w1[2] & 0x000000ff) | (wx <<  8);
              w1[3] = (w1[3] & 0xffffff00) | (wx >> 24);
              break;
    case 26:  w1[2] = (w1[2] & 0x0000ffff) | (wx << 16);
              w1[3] = (w1[3] & 0xffff0000) | (wx >> 16);
              break;
    case 27:  w1[2] = (w1[2] & 0x00ffffff) | (wx << 24);
              w1[3] = (w1[3] & 0xff000000) | (wx >>  8);
              break;
    case 28:  w1[3] =  wx;
              break;
    case 29:  w1[3] = (w1[3] & 0x000000ff) | (wx <<  8);
              w2[0] = (w2[0] & 0xffffff00) | (wx >> 24);
              break;
    case 30:  w1[3] = (w1[3] & 0x0000ffff) | (wx << 16);
              w2[0] = (w2[0] & 0xffff0000) | (wx >> 16);
              break;
    case 31:  w1[3] = (w1[3] & 0x00ffffff) | (wx << 24);
              w2[0] = (w2[0] & 0xff000000) | (wx >>  8);
              break;
    case 32:  w2[0] =  wx;
              break;
    case 33:  w2[0] = (w2[0] & 0x000000ff) | (wx <<  8);
              w2[1] = (w2[1] & 0xffffff00) | (wx >> 24);
              break;
    case 34:  w2[0] = (w2[0] & 0x0000ffff) | (wx << 16);
              w2[1] = (w2[1] & 0xffff0000) | (wx >> 16);
              break;
    case 35:  w2[0] = (w2[0] & 0x00ffffff) | (wx << 24);
              w2[1] = (w2[1] & 0xff000000) | (wx >>  8);
              break;
    case 36:  w2[1] =  wx;
              break;
    case 37:  w2[1] = (w2[1] & 0x000000ff) | (wx <<  8);
              w2[2] = (w2[2] & 0xffffff00) | (wx >> 24);
              break;
    case 38:  w2[1] = (w2[1] & 0x0000ffff) | (wx << 16);
              w2[2] = (w2[2] & 0xffff0000) | (wx >> 16);
              break;
    case 39:  w2[1] = (w2[1] & 0x00ffffff) | (wx << 24);
              w2[2] = (w2[2] & 0xff000000) | (wx >>  8);
              break;
    case 40:  w2[2] =  wx;
              break;
    case 41:  w2[2] = (w2[2] & 0x000000ff) | (wx <<  8);
              w2[3] = (w2[3] & 0xffffff00) | (wx >> 24);
              break;
    case 42:  w2[2] = (w2[2] & 0x0000ffff) | (wx << 16);
              w2[3] = (w2[3] & 0xffff0000) | (wx >> 16);
              break;
    case 43:  w2[2] = (w2[2] & 0x00ffffff) | (wx << 24);
              w2[3] = (w2[3] & 0xff000000) | (wx >>  8);
              break;
    case 44:  w2[3] =  wx;
              break;
    case 45:  w2[3] = (w2[3] & 0x000000ff) | (wx <<  8);
              w3[0] = (w3[0] & 0xffffff00) | (wx >> 24);
              break;
    case 46:  w2[3] = (w2[3] & 0x0000ffff) | (wx << 16);
              w3[0] = (w3[0] & 0xffff0000) | (wx >> 16);
              break;
    case 47:  w2[3] = (w2[3] & 0x00ffffff) | (wx << 24);
              w3[0] = (w3[0] & 0xff000000) | (wx >>  8);
              break;
    case 48:  w3[0] =  wx;
              break;
    case 49:  w3[0] = (w3[0] & 0x000000ff) | (wx <<  8);
              w3[1] = (w3[1] & 0xffffff00) | (wx >> 24);
              break;
    case 50:  w3[0] = (w3[0] & 0x0000ffff) | (wx << 16);
              w3[1] = (w3[1] & 0xffff0000) | (wx >> 16);
              break;
    case 51:  w3[0] = (w3[0] & 0x00ffffff) | (wx << 24);
              w3[1] = (w3[1] & 0xff000000) | (wx >>  8);
              break;
    case 52:  w3[1] =  wx;
              break;
    case 53:  w3[1] = (w3[1] & 0x000000ff) | (wx <<  8);
              w3[2] = (w3[2] & 0xffffff00) | (wx >> 24);
              break;
    case 54:  w3[1] = (w3[1] & 0x0000ffff) | (wx << 16);
              w3[2] = (w3[2] & 0xffff0000) | (wx >> 16);
              break;
    case 55:  w3[1] = (w3[1] & 0x00ffffff) | (wx << 24);
              w3[2] = (w3[2] & 0xff000000) | (wx >>  8);
              break;
    case 56:  w3[2] =  wx;
              break;
    case 57:  w3[2] = (w3[2] & 0x000000ff) | (wx <<  8);
              w3[3] = (w3[3] & 0xffffff00) | (wx >> 24);
              break;
    case 58:  w3[2] = (w3[2] & 0x0000ffff) | (wx << 16);
              w3[3] = (w3[3] & 0xffff0000) | (wx >> 16);
              break;
    case 59:  w3[2] = (w3[2] & 0x00ffffff) | (wx << 24);
              w3[3] = (w3[3] & 0xff000000) | (wx >>  8);
              break;
    case 60:  w3[3] =  wx;
              break;
    case 61:  w3[3] = (w3[3] & 0x000000ff) | (wx <<  8);
              //w4[0] = (w4[0] & 0xffffff00) | (wx >> 24);
              break;
    case 62:  w3[3] = (w3[3] & 0x0000ffff) | (wx << 16);
              //w4[0] = (w4[0] & 0xffff0000) | (wx >> 16);
              break;
    case 63:  w3[3] = (w3[3] & 0x00ffffff) | (wx << 24);
              //w4[0] = (w4[0] & 0xff000000) | (wx >>  8);
              break;
  }
  #endif
}

inline void overwrite_at_be_4x4 (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32x wx, const u32 salt_len)
{
  // would be nice to have optimization based on amd_bytealign as with _le counterpart

  switch (salt_len)
  {
    case  0:  w0[0] =  wx;
              break;
    case  1:  w0[0] = (w0[0] & 0xff000000) | (wx >>  8);
              w0[1] = (w0[1] & 0x00ffffff) | (wx << 24);
              break;
    case  2:  w0[0] = (w0[0] & 0xffff0000) | (wx >> 16);
              w0[1] = (w0[1] & 0x0000ffff) | (wx << 16);
              break;
    case  3:  w0[0] = (w0[0] & 0xffffff00) | (wx >> 24);
              w0[1] = (w0[1] & 0x000000ff) | (wx <<  8);
              break;
    case  4:  w0[1] =  wx;
              break;
    case  5:  w0[1] = (w0[1] & 0xff000000) | (wx >>  8);
              w0[2] = (w0[2] & 0x00ffffff) | (wx << 24);
              break;
    case  6:  w0[1] = (w0[1] & 0xffff0000) | (wx >> 16);
              w0[2] = (w0[2] & 0x0000ffff) | (wx << 16);
              break;
    case  7:  w0[1] = (w0[1] & 0xffffff00) | (wx >> 24);
              w0[2] = (w0[2] & 0x000000ff) | (wx <<  8);
              break;
    case  8:  w0[2] =  wx;
              break;
    case  9:  w0[2] = (w0[2] & 0xff000000) | (wx >>  8);
              w0[3] = (w0[3] & 0x00ffffff) | (wx << 24);
              break;
    case 10:  w0[2] = (w0[2] & 0xffff0000) | (wx >> 16);
              w0[3] = (w0[3] & 0x0000ffff) | (wx << 16);
              break;
    case 11:  w0[2] = (w0[2] & 0xffffff00) | (wx >> 24);
              w0[3] = (w0[3] & 0x000000ff) | (wx <<  8);
              break;
    case 12:  w0[3] =  wx;
              break;
    case 13:  w0[3] = (w0[3] & 0xff000000) | (wx >>  8);
              w1[0] = (w1[0] & 0x00ffffff) | (wx << 24);
              break;
    case 14:  w0[3] = (w0[3] & 0xffff0000) | (wx >> 16);
              w1[0] = (w1[0] & 0x0000ffff) | (wx << 16);
              break;
    case 15:  w0[3] = (w0[3] & 0xffffff00) | (wx >> 24);
              w1[0] = (w1[0] & 0x000000ff) | (wx <<  8);
              break;
    case 16:  w1[0] =  wx;
              break;
    case 17:  w1[0] = (w1[0] & 0xff000000) | (wx >>  8);
              w1[1] = (w1[1] & 0x00ffffff) | (wx << 24);
              break;
    case 18:  w1[0] = (w1[0] & 0xffff0000) | (wx >> 16);
              w1[1] = (w1[1] & 0x0000ffff) | (wx << 16);
              break;
    case 19:  w1[0] = (w1[0] & 0xffffff00) | (wx >> 24);
              w1[1] = (w1[1] & 0x000000ff) | (wx <<  8);
              break;
    case 20:  w1[1] =  wx;
              break;
    case 21:  w1[1] = (w1[1] & 0xff000000) | (wx >>  8);
              w1[2] = (w1[2] & 0x00ffffff) | (wx << 24);
              break;
    case 22:  w1[1] = (w1[1] & 0xffff0000) | (wx >> 16);
              w1[2] = (w1[2] & 0x0000ffff) | (wx << 16);
              break;
    case 23:  w1[1] = (w1[1] & 0xffffff00) | (wx >> 24);
              w1[2] = (w1[2] & 0x000000ff) | (wx <<  8);
              break;
    case 24:  w1[2] =  wx;
              break;
    case 25:  w1[2] = (w1[2] & 0xff000000) | (wx >>  8);
              w1[3] = (w1[3] & 0x00ffffff) | (wx << 24);
              break;
    case 26:  w1[2] = (w1[2] & 0xffff0000) | (wx >> 16);
              w1[3] = (w1[3] & 0x0000ffff) | (wx << 16);
              break;
    case 27:  w1[2] = (w1[2] & 0xffffff00) | (wx >> 24);
              w1[3] = (w1[3] & 0x000000ff) | (wx <<  8);
              break;
    case 28:  w1[3] =  wx;
              break;
    case 29:  w1[3] = (w1[3] & 0xff000000) | (wx >>  8);
              w2[0] = (w2[0] & 0x00ffffff) | (wx << 24);
              break;
    case 30:  w1[3] = (w1[3] & 0xffff0000) | (wx >> 16);
              w2[0] = (w2[0] & 0x0000ffff) | (wx << 16);
              break;
    case 31:  w1[3] = (w1[3] & 0xffffff00) | (wx >> 24);
              w2[0] = (w2[0] & 0x000000ff) | (wx <<  8);
              break;
    case 32:  w2[0] =  wx;
              break;
    case 33:  w2[0] = (w2[0] & 0xff000000) | (wx >>  8);
              w2[1] = (w2[1] & 0x00ffffff) | (wx << 24);
              break;
    case 34:  w2[0] = (w2[0] & 0xffff0000) | (wx >> 16);
              w2[1] = (w2[1] & 0x0000ffff) | (wx << 16);
              break;
    case 35:  w2[0] = (w2[0] & 0xffffff00) | (wx >> 24);
              w2[1] = (w2[1] & 0x000000ff) | (wx <<  8);
              break;
    case 36:  w2[1] =  wx;
              break;
    case 37:  w2[1] = (w2[1] & 0xff000000) | (wx >>  8);
              w2[2] = (w2[2] & 0x00ffffff) | (wx << 24);
              break;
    case 38:  w2[1] = (w2[1] & 0xffff0000) | (wx >> 16);
              w2[2] = (w2[2] & 0x0000ffff) | (wx << 16);
              break;
    case 39:  w2[1] = (w2[1] & 0xffffff00) | (wx >> 24);
              w2[2] = (w2[2] & 0x000000ff) | (wx <<  8);
              break;
    case 40:  w2[2] =  wx;
              break;
    case 41:  w2[2] = (w2[2] & 0xff000000) | (wx >>  8);
              w2[3] = (w2[3] & 0x00ffffff) | (wx << 24);
              break;
    case 42:  w2[2] = (w2[2] & 0xffff0000) | (wx >> 16);
              w2[3] = (w2[3] & 0x0000ffff) | (wx << 16);
              break;
    case 43:  w2[2] = (w2[2] & 0xffffff00) | (wx >> 24);
              w2[3] = (w2[3] & 0x000000ff) | (wx <<  8);
              break;
    case 44:  w2[3] =  wx;
              break;
    case 45:  w2[3] = (w2[3] & 0xff000000) | (wx >>  8);
              w3[0] = (w3[0] & 0x00ffffff) | (wx << 24);
              break;
    case 46:  w2[3] = (w2[3] & 0xffff0000) | (wx >> 16);
              w3[0] = (w3[0] & 0x0000ffff) | (wx << 16);
              break;
    case 47:  w2[3] = (w2[3] & 0xffffff00) | (wx >> 24);
              w3[0] = (w3[0] & 0x000000ff) | (wx <<  8);
              break;
    case 48:  w3[0] =  wx;
              break;
    case 49:  w3[0] = (w3[0] & 0xff000000) | (wx >>  8);
              w3[1] = (w3[1] & 0x00ffffff) | (wx << 24);
              break;
    case 50:  w3[0] = (w3[0] & 0xffff0000) | (wx >> 16);
              w3[1] = (w3[1] & 0x0000ffff) | (wx << 16);
              break;
    case 51:  w3[0] = (w3[0] & 0xffffff00) | (wx >> 24);
              w3[1] = (w3[1] & 0x000000ff) | (wx <<  8);
              break;
    case 52:  w3[1] =  wx;
              break;
    case 53:  w3[1] = (w3[1] & 0xff000000) | (wx >>  8);
              w3[2] = (w3[2] & 0x00ffffff) | (wx << 24);
              break;
    case 54:  w3[1] = (w3[1] & 0xffff0000) | (wx >> 16);
              w3[2] = (w3[2] & 0x0000ffff) | (wx << 16);
              break;
    case 55:  w3[1] = (w3[1] & 0xffffff00) | (wx >> 24);
              w3[2] = (w3[2] & 0x000000ff) | (wx <<  8);
              break;
    case 56:  w3[2] =  wx;
              break;
    case 57:  w3[2] = (w3[2] & 0xff000000) | (wx >>  8);
              w3[3] = (w3[3] & 0x00ffffff) | (wx << 24);
              break;
    case 58:  w3[2] = (w3[2] & 0xffff0000) | (wx >> 16);
              w3[3] = (w3[3] & 0x0000ffff) | (wx << 16);
              break;
    case 59:  w3[2] = (w3[2] & 0xffffff00) | (wx >> 24);
              w3[3] = (w3[3] & 0x000000ff) | (wx <<  8);
              break;
    case 60:  w3[3] =  wx;
              break;
    case 61:  w3[3] = (w3[3] & 0xff000000) | (wx >>  8);
              //w4[0] = (w4[0] & 0x00ffffff) | (wx << 24);
              break;
    case 62:  w3[3] = (w3[3] & 0xffff0000) | (wx >> 16);
              //w4[0] = (w4[0] & 0x0000ffff) | (wx << 16);
              break;
    case 63:  w3[3] = (w3[3] & 0xffffff00) | (wx >> 24);
              //w4[0] = (w4[0] & 0x000000ff) | (wx <<  8);
              break;
  }
}

/**
 * vector functions as scalar (for outer loop usage)
 */

inline void append_0x01_1x4_S (u32 w0[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0]  = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_2x4_S (u32 w0[4], u32 w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_3x4_S (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;

    case 32:
      w2[0] = 0x01;
      break;

    case 33:
      w2[0] = w2[0] | 0x0100;
      break;

    case 34:
      w2[0] = w2[0] | 0x010000;
      break;

    case 35:
      w2[0] = w2[0] | 0x01000000;
      break;

    case 36:
      w2[1] = 0x01;
      break;

    case 37:
      w2[1] = w2[1] | 0x0100;
      break;

    case 38:
      w2[1] = w2[1] | 0x010000;
      break;

    case 39:
      w2[1] = w2[1] | 0x01000000;
      break;

    case 40:
      w2[2] = 0x01;
      break;

    case 41:
      w2[2] = w2[2] | 0x0100;
      break;

    case 42:
      w2[2] = w2[2] | 0x010000;
      break;

    case 43:
      w2[2] = w2[2] | 0x01000000;
      break;

    case 44:
      w2[3] = 0x01;
      break;

    case 45:
      w2[3] = w2[3] | 0x0100;
      break;

    case 46:
      w2[3] = w2[3] | 0x010000;
      break;

    case 47:
      w2[3] = w2[3] | 0x01000000;
      break;
  }
}

inline void append_0x01_4x4_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x01;
      break;

    case 1:
      w0[0] = w0[0] | 0x0100;
      break;

    case 2:
      w0[0] = w0[0] | 0x010000;
      break;

    case 3:
      w0[0] = w0[0] | 0x01000000;
      break;

    case 4:
      w0[1] = 0x01;
      break;

    case 5:
      w0[1] = w0[1] | 0x0100;
      break;

    case 6:
      w0[1] = w0[1] | 0x010000;
      break;

    case 7:
      w0[1] = w0[1] | 0x01000000;
      break;

    case 8:
      w0[2] = 0x01;
      break;

    case 9:
      w0[2] = w0[2] | 0x0100;
      break;

    case 10:
      w0[2] = w0[2] | 0x010000;
      break;

    case 11:
      w0[2] = w0[2] | 0x01000000;
      break;

    case 12:
      w0[3] = 0x01;
      break;

    case 13:
      w0[3] = w0[3] | 0x0100;
      break;

    case 14:
      w0[3] = w0[3] | 0x010000;
      break;

    case 15:
      w0[3] = w0[3] | 0x01000000;
      break;

    case 16:
      w1[0] = 0x01;
      break;

    case 17:
      w1[0] = w1[0] | 0x0100;
      break;

    case 18:
      w1[0] = w1[0] | 0x010000;
      break;

    case 19:
      w1[0] = w1[0] | 0x01000000;
      break;

    case 20:
      w1[1] = 0x01;
      break;

    case 21:
      w1[1] = w1[1] | 0x0100;
      break;

    case 22:
      w1[1] = w1[1] | 0x010000;
      break;

    case 23:
      w1[1] = w1[1] | 0x01000000;
      break;

    case 24:
      w1[2] = 0x01;
      break;

    case 25:
      w1[2] = w1[2] | 0x0100;
      break;

    case 26:
      w1[2] = w1[2] | 0x010000;
      break;

    case 27:
      w1[2] = w1[2] | 0x01000000;
      break;

    case 28:
      w1[3] = 0x01;
      break;

    case 29:
      w1[3] = w1[3] | 0x0100;
      break;

    case 30:
      w1[3] = w1[3] | 0x010000;
      break;

    case 31:
      w1[3] = w1[3] | 0x01000000;
      break;

    case 32:
      w2[0] = 0x01;
      break;

    case 33:
      w2[0] = w2[0] | 0x0100;
      break;

    case 34:
      w2[0] = w2[0] | 0x010000;
      break;

    case 35:
      w2[0] = w2[0] | 0x01000000;
      break;

    case 36:
      w2[1] = 0x01;
      break;

    case 37:
      w2[1] = w2[1] | 0x0100;
      break;

    case 38:
      w2[1] = w2[1] | 0x010000;
      break;

    case 39:
      w2[1] = w2[1] | 0x01000000;
      break;

    case 40:
      w2[2] = 0x01;
      break;

    case 41:
      w2[2] = w2[2] | 0x0100;
      break;

    case 42:
      w2[2] = w2[2] | 0x010000;
      break;

    case 43:
      w2[2] = w2[2] | 0x01000000;
      break;

    case 44:
      w2[3] = 0x01;
      break;

    case 45:
      w2[3] = w2[3] | 0x0100;
      break;

    case 46:
      w2[3] = w2[3] | 0x010000;
      break;

    case 47:
      w2[3] = w2[3] | 0x01000000;
      break;

    case 48:
      w3[0] = 0x01;
      break;

    case 49:
      w3[0] = w3[0] | 0x0100;
      break;

    case 50:
      w3[0] = w3[0] | 0x010000;
      break;

    case 51:
      w3[0] = w3[0] | 0x01000000;
      break;

    case 52:
      w3[1] = 0x01;
      break;

    case 53:
      w3[1] = w3[1] | 0x0100;
      break;

    case 54:
      w3[1] = w3[1] | 0x010000;
      break;

    case 55:
      w3[1] = w3[1] | 0x01000000;
      break;

    case 56:
      w3[2] = 0x01;
      break;

    case 57:
      w3[2] = w3[2] | 0x0100;
      break;

    case 58:
      w3[2] = w3[2] | 0x010000;
      break;

    case 59:
      w3[2] = w3[2] | 0x01000000;
      break;

    case 60:
      w3[3] = 0x01;
      break;

    case 61:
      w3[3] = w3[3] | 0x0100;
      break;

    case 62:
      w3[3] = w3[3] | 0x010000;
      break;

    case 63:
      w3[3] = w3[3] | 0x01000000;
      break;
  }
}

inline void append_0x02_2x4_S (u32 w0[4], u32 w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;
  }
}

inline void append_0x02_3x4_S (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x02;
      break;

    case 1:
      w0[0] = w0[0] | 0x0200;
      break;

    case 2:
      w0[0] = w0[0] | 0x020000;
      break;

    case 3:
      w0[0] = w0[0] | 0x02000000;
      break;

    case 4:
      w0[1] = 0x02;
      break;

    case 5:
      w0[1] = w0[1] | 0x0200;
      break;

    case 6:
      w0[1] = w0[1] | 0x020000;
      break;

    case 7:
      w0[1] = w0[1] | 0x02000000;
      break;

    case 8:
      w0[2] = 0x02;
      break;

    case 9:
      w0[2] = w0[2] | 0x0200;
      break;

    case 10:
      w0[2] = w0[2] | 0x020000;
      break;

    case 11:
      w0[2] = w0[2] | 0x02000000;
      break;

    case 12:
      w0[3] = 0x02;
      break;

    case 13:
      w0[3] = w0[3] | 0x0200;
      break;

    case 14:
      w0[3] = w0[3] | 0x020000;
      break;

    case 15:
      w0[3] = w0[3] | 0x02000000;
      break;

    case 16:
      w1[0] = 0x02;
      break;

    case 17:
      w1[0] = w1[0] | 0x0200;
      break;

    case 18:
      w1[0] = w1[0] | 0x020000;
      break;

    case 19:
      w1[0] = w1[0] | 0x02000000;
      break;

    case 20:
      w1[1] = 0x02;
      break;

    case 21:
      w1[1] = w1[1] | 0x0200;
      break;

    case 22:
      w1[1] = w1[1] | 0x020000;
      break;

    case 23:
      w1[1] = w1[1] | 0x02000000;
      break;

    case 24:
      w1[2] = 0x02;
      break;

    case 25:
      w1[2] = w1[2] | 0x0200;
      break;

    case 26:
      w1[2] = w1[2] | 0x020000;
      break;

    case 27:
      w1[2] = w1[2] | 0x02000000;
      break;

    case 28:
      w1[3] = 0x02;
      break;

    case 29:
      w1[3] = w1[3] | 0x0200;
      break;

    case 30:
      w1[3] = w1[3] | 0x020000;
      break;

    case 31:
      w1[3] = w1[3] | 0x02000000;
      break;

    case 32:
      w2[0] = 0x02;
      break;

    case 33:
      w2[0] = w2[0] | 0x0200;
      break;

    case 34:
      w2[0] = w2[0] | 0x020000;
      break;

    case 35:
      w2[0] = w2[0] | 0x02000000;
      break;

    case 36:
      w2[1] = 0x02;
      break;

    case 37:
      w2[1] = w2[1] | 0x0200;
      break;

    case 38:
      w2[1] = w2[1] | 0x020000;
      break;

    case 39:
      w2[1] = w2[1] | 0x02000000;
      break;

    case 40:
      w2[2] = 0x02;
      break;

    case 41:
      w2[2] = w2[2] | 0x0200;
      break;

    case 42:
      w2[2] = w2[2] | 0x020000;
      break;

    case 43:
      w2[2] = w2[2] | 0x02000000;
      break;

    case 44:
      w2[3] = 0x02;
      break;

    case 45:
      w2[3] = w2[3] | 0x0200;
      break;

    case 46:
      w2[3] = w2[3] | 0x020000;
      break;

    case 47:
      w2[3] = w2[3] | 0x02000000;
      break;
  }
}

inline void append_0x80_1x4_S (u32 w0[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0]  = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_2x4_S (u32 w0[4], u32 w1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_3x4_S (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;

    case 32:
      w2[0] = 0x80;
      break;

    case 33:
      w2[0] = w2[0] | 0x8000;
      break;

    case 34:
      w2[0] = w2[0] | 0x800000;
      break;

    case 35:
      w2[0] = w2[0] | 0x80000000;
      break;

    case 36:
      w2[1] = 0x80;
      break;

    case 37:
      w2[1] = w2[1] | 0x8000;
      break;

    case 38:
      w2[1] = w2[1] | 0x800000;
      break;

    case 39:
      w2[1] = w2[1] | 0x80000000;
      break;

    case 40:
      w2[2] = 0x80;
      break;

    case 41:
      w2[2] = w2[2] | 0x8000;
      break;

    case 42:
      w2[2] = w2[2] | 0x800000;
      break;

    case 43:
      w2[2] = w2[2] | 0x80000000;
      break;

    case 44:
      w2[3] = 0x80;
      break;

    case 45:
      w2[3] = w2[3] | 0x8000;
      break;

    case 46:
      w2[3] = w2[3] | 0x800000;
      break;

    case 47:
      w2[3] = w2[3] | 0x80000000;
      break;
  }
}

inline void append_0x80_4x4_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = 0x80;
      break;

    case 1:
      w0[0] = w0[0] | 0x8000;
      break;

    case 2:
      w0[0] = w0[0] | 0x800000;
      break;

    case 3:
      w0[0] = w0[0] | 0x80000000;
      break;

    case 4:
      w0[1] = 0x80;
      break;

    case 5:
      w0[1] = w0[1] | 0x8000;
      break;

    case 6:
      w0[1] = w0[1] | 0x800000;
      break;

    case 7:
      w0[1] = w0[1] | 0x80000000;
      break;

    case 8:
      w0[2] = 0x80;
      break;

    case 9:
      w0[2] = w0[2] | 0x8000;
      break;

    case 10:
      w0[2] = w0[2] | 0x800000;
      break;

    case 11:
      w0[2] = w0[2] | 0x80000000;
      break;

    case 12:
      w0[3] = 0x80;
      break;

    case 13:
      w0[3] = w0[3] | 0x8000;
      break;

    case 14:
      w0[3] = w0[3] | 0x800000;
      break;

    case 15:
      w0[3] = w0[3] | 0x80000000;
      break;

    case 16:
      w1[0] = 0x80;
      break;

    case 17:
      w1[0] = w1[0] | 0x8000;
      break;

    case 18:
      w1[0] = w1[0] | 0x800000;
      break;

    case 19:
      w1[0] = w1[0] | 0x80000000;
      break;

    case 20:
      w1[1] = 0x80;
      break;

    case 21:
      w1[1] = w1[1] | 0x8000;
      break;

    case 22:
      w1[1] = w1[1] | 0x800000;
      break;

    case 23:
      w1[1] = w1[1] | 0x80000000;
      break;

    case 24:
      w1[2] = 0x80;
      break;

    case 25:
      w1[2] = w1[2] | 0x8000;
      break;

    case 26:
      w1[2] = w1[2] | 0x800000;
      break;

    case 27:
      w1[2] = w1[2] | 0x80000000;
      break;

    case 28:
      w1[3] = 0x80;
      break;

    case 29:
      w1[3] = w1[3] | 0x8000;
      break;

    case 30:
      w1[3] = w1[3] | 0x800000;
      break;

    case 31:
      w1[3] = w1[3] | 0x80000000;
      break;

    case 32:
      w2[0] = 0x80;
      break;

    case 33:
      w2[0] = w2[0] | 0x8000;
      break;

    case 34:
      w2[0] = w2[0] | 0x800000;
      break;

    case 35:
      w2[0] = w2[0] | 0x80000000;
      break;

    case 36:
      w2[1] = 0x80;
      break;

    case 37:
      w2[1] = w2[1] | 0x8000;
      break;

    case 38:
      w2[1] = w2[1] | 0x800000;
      break;

    case 39:
      w2[1] = w2[1] | 0x80000000;
      break;

    case 40:
      w2[2] = 0x80;
      break;

    case 41:
      w2[2] = w2[2] | 0x8000;
      break;

    case 42:
      w2[2] = w2[2] | 0x800000;
      break;

    case 43:
      w2[2] = w2[2] | 0x80000000;
      break;

    case 44:
      w2[3] = 0x80;
      break;

    case 45:
      w2[3] = w2[3] | 0x8000;
      break;

    case 46:
      w2[3] = w2[3] | 0x800000;
      break;

    case 47:
      w2[3] = w2[3] | 0x80000000;
      break;

    case 48:
      w3[0] = 0x80;
      break;

    case 49:
      w3[0] = w3[0] | 0x8000;
      break;

    case 50:
      w3[0] = w3[0] | 0x800000;
      break;

    case 51:
      w3[0] = w3[0] | 0x80000000;
      break;

    case 52:
      w3[1] = 0x80;
      break;

    case 53:
      w3[1] = w3[1] | 0x8000;
      break;

    case 54:
      w3[1] = w3[1] | 0x800000;
      break;

    case 55:
      w3[1] = w3[1] | 0x80000000;
      break;

    case 56:
      w3[2] = 0x80;
      break;

    case 57:
      w3[2] = w3[2] | 0x8000;
      break;

    case 58:
      w3[2] = w3[2] | 0x800000;
      break;

    case 59:
      w3[2] = w3[2] | 0x80000000;
      break;

    case 60:
      w3[3] = 0x80;
      break;

    case 61:
      w3[3] = w3[3] | 0x8000;
      break;

    case 62:
      w3[3] = w3[3] | 0x800000;
      break;

    case 63:
      w3[3] = w3[3] | 0x80000000;
      break;
  }
}

inline void truncate_block_S (u32 w[4], const u32 len)
{
  switch (len)
  {
    case  0:  w[0] &= 0;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  1:  w[0] &= 0x000000FF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  2:  w[0] &= 0x0000FFFF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  3:  w[0] &= 0x00FFFFFF;
              w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  4:  w[1] &= 0;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  5:  w[1] &= 0x000000FF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  6:  w[1] &= 0x0000FFFF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  7:  w[1] &= 0x00FFFFFF;
              w[2] &= 0;
              w[3] &= 0;
              break;
    case  8:  w[2] &= 0;
              w[3] &= 0;
              break;
    case  9:  w[2] &= 0x000000FF;
              w[3] &= 0;
              break;
    case 10:  w[2] &= 0x0000FFFF;
              w[3] &= 0;
              break;
    case 11:  w[2] &= 0x00FFFFFF;
              w[3] &= 0;
              break;
    case 12:  w[3] &= 0;
              break;
    case 13:  w[3] &= 0x000000FF;
              break;
    case 14:  w[3] &= 0x0000FFFF;
              break;
    case 15:  w[3] &= 0x00FFFFFF;
              break;
  }
}

inline void make_unicode_S (const u32 in[4], u32 out1[4], u32 out2[4])
{
  #ifdef IS_NV
  out2[3] = __byte_perm_S (in[3], 0, 0x7372);
  out2[2] = __byte_perm_S (in[3], 0, 0x7170);
  out2[1] = __byte_perm_S (in[2], 0, 0x7372);
  out2[0] = __byte_perm_S (in[2], 0, 0x7170);
  out1[3] = __byte_perm_S (in[1], 0, 0x7372);
  out1[2] = __byte_perm_S (in[1], 0, 0x7170);
  out1[1] = __byte_perm_S (in[0], 0, 0x7372);
  out1[0] = __byte_perm_S (in[0], 0, 0x7170);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  out2[3]  = ((in[3] >> 8) & 0x00FF0000) | ((in[3] >> 16) & 0x000000FF);
  out2[2]  = ((in[3] << 8) & 0x00FF0000) | ((in[3] >>  0) & 0x000000FF);
  out2[1]  = ((in[2] >> 8) & 0x00FF0000) | ((in[2] >> 16) & 0x000000FF);
  out2[0]  = ((in[2] << 8) & 0x00FF0000) | ((in[2] >>  0) & 0x000000FF);
  out1[3]  = ((in[1] >> 8) & 0x00FF0000) | ((in[1] >> 16) & 0x000000FF);
  out1[2]  = ((in[1] << 8) & 0x00FF0000) | ((in[1] >>  0) & 0x000000FF);
  out1[1]  = ((in[0] >> 8) & 0x00FF0000) | ((in[0] >> 16) & 0x000000FF);
  out1[0]  = ((in[0] << 8) & 0x00FF0000) | ((in[0] >>  0) & 0x000000FF);
  #endif
}

inline void undo_unicode_S (const u32 in1[4], const u32 in2[4], u32 out[4])
{
  #ifdef IS_NV
  out[0] = __byte_perm_S (in1[0], in1[1], 0x6420);
  out[1] = __byte_perm_S (in1[2], in1[3], 0x6420);
  out[2] = __byte_perm_S (in2[0], in2[1], 0x6420);
  out[3] = __byte_perm_S (in2[2], in2[3], 0x6420);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  out[0] = ((in1[0] & 0x000000ff) >>  0) | ((in1[0] & 0x00ff0000) >>  8)
         | ((in1[1] & 0x000000ff) << 16) | ((in1[1] & 0x00ff0000) <<  8);
  out[1] = ((in1[2] & 0x000000ff) >>  0) | ((in1[2] & 0x00ff0000) >>  8)
         | ((in1[3] & 0x000000ff) << 16) | ((in1[3] & 0x00ff0000) <<  8);
  out[2] = ((in2[0] & 0x000000ff) >>  0) | ((in2[0] & 0x00ff0000) >>  8)
         | ((in2[1] & 0x000000ff) << 16) | ((in2[1] & 0x00ff0000) <<  8);
  out[3] = ((in2[2] & 0x000000ff) >>  0) | ((in2[2] & 0x00ff0000) >>  8)
         | ((in2[3] & 0x000000ff) << 16) | ((in2[3] & 0x00ff0000) <<  8);
  #endif
}

inline void switch_buffer_by_offset_le_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  #if defined IS_AMD || defined IS_GENERIC
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset;

  switch (offset / 4)
  {
    case 0:
      w3[2] = amd_bytealign_S (    0, w3[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);

      if (offset_mod_4 == 0)
      {
        w0[0] = w0[1];
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 1:
      w3[2] = amd_bytealign_S (    0, w3[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 2:
      w3[2] = amd_bytealign_S (    0, w2[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 3:
      w3[2] = amd_bytealign_S (    0, w2[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 4:
      w3[2] = amd_bytealign_S (    0, w2[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 5:
      w3[2] = amd_bytealign_S (    0, w2[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 6:
      w3[2] = amd_bytealign_S (    0, w1[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 7:
      w3[2] = amd_bytealign_S (    0, w1[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 8:
      w3[2] = amd_bytealign_S (    0, w1[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 9:
      w3[2] = amd_bytealign_S (    0, w1[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 10:
      w3[2] = amd_bytealign_S (    0, w0[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 11:
      w3[2] = amd_bytealign_S (    0, w0[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 12:
      w3[2] = amd_bytealign_S (    0, w0[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;

    case 13:
      w3[2] = amd_bytealign_S (    0, w0[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w3[1] = w3[2];
        w3[2] = 0;
      }

      break;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (offset % 4);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w3[1] = __byte_perm_S (w3[0], w3[1], selector);
      w3[0] = __byte_perm_S (w2[3], w3[0], selector);
      w2[3] = __byte_perm_S (w2[2], w2[3], selector);
      w2[2] = __byte_perm_S (w2[1], w2[2], selector);
      w2[1] = __byte_perm_S (w2[0], w2[1], selector);
      w2[0] = __byte_perm_S (w1[3], w2[0], selector);
      w1[3] = __byte_perm_S (w1[2], w1[3], selector);
      w1[2] = __byte_perm_S (w1[1], w1[2], selector);
      w1[1] = __byte_perm_S (w1[0], w1[1], selector);
      w1[0] = __byte_perm_S (w0[3], w1[0], selector);
      w0[3] = __byte_perm_S (w0[2], w0[3], selector);
      w0[2] = __byte_perm_S (w0[1], w0[2], selector);
      w0[1] = __byte_perm_S (w0[0], w0[1], selector);
      w0[0] = __byte_perm_S (    0, w0[0], selector);

      break;

    case 1:
      w3[1] = __byte_perm_S (w2[3], w3[0], selector);
      w3[0] = __byte_perm_S (w2[2], w2[3], selector);
      w2[3] = __byte_perm_S (w2[1], w2[2], selector);
      w2[2] = __byte_perm_S (w2[0], w2[1], selector);
      w2[1] = __byte_perm_S (w1[3], w2[0], selector);
      w2[0] = __byte_perm_S (w1[2], w1[3], selector);
      w1[3] = __byte_perm_S (w1[1], w1[2], selector);
      w1[2] = __byte_perm_S (w1[0], w1[1], selector);
      w1[1] = __byte_perm_S (w0[3], w1[0], selector);
      w1[0] = __byte_perm_S (w0[2], w0[3], selector);
      w0[3] = __byte_perm_S (w0[1], w0[2], selector);
      w0[2] = __byte_perm_S (w0[0], w0[1], selector);
      w0[1] = __byte_perm_S (    0, w0[0], selector);
      w0[0] = 0;

      break;

    case 2:
      w3[1] = __byte_perm_S (w2[2], w2[3], selector);
      w3[0] = __byte_perm_S (w2[1], w2[2], selector);
      w2[3] = __byte_perm_S (w2[0], w2[1], selector);
      w2[2] = __byte_perm_S (w1[3], w2[0], selector);
      w2[1] = __byte_perm_S (w1[2], w1[3], selector);
      w2[0] = __byte_perm_S (w1[1], w1[2], selector);
      w1[3] = __byte_perm_S (w1[0], w1[1], selector);
      w1[2] = __byte_perm_S (w0[3], w1[0], selector);
      w1[1] = __byte_perm_S (w0[2], w0[3], selector);
      w1[0] = __byte_perm_S (w0[1], w0[2], selector);
      w0[3] = __byte_perm_S (w0[0], w0[1], selector);
      w0[2] = __byte_perm_S (    0, w0[0], selector);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 3:
      w3[1] = __byte_perm_S (w2[1], w2[2], selector);
      w3[0] = __byte_perm_S (w2[0], w2[1], selector);
      w2[3] = __byte_perm_S (w1[3], w2[0], selector);
      w2[2] = __byte_perm_S (w1[2], w1[3], selector);
      w2[1] = __byte_perm_S (w1[1], w1[2], selector);
      w2[0] = __byte_perm_S (w1[0], w1[1], selector);
      w1[3] = __byte_perm_S (w0[3], w1[0], selector);
      w1[2] = __byte_perm_S (w0[2], w0[3], selector);
      w1[1] = __byte_perm_S (w0[1], w0[2], selector);
      w1[0] = __byte_perm_S (w0[0], w0[1], selector);
      w0[3] = __byte_perm_S (    0, w0[0], selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 4:
      w3[1] = __byte_perm_S (w2[0], w2[1], selector);
      w3[0] = __byte_perm_S (w1[3], w2[0], selector);
      w2[3] = __byte_perm_S (w1[2], w1[3], selector);
      w2[2] = __byte_perm_S (w1[1], w1[2], selector);
      w2[1] = __byte_perm_S (w1[0], w1[1], selector);
      w2[0] = __byte_perm_S (w0[3], w1[0], selector);
      w1[3] = __byte_perm_S (w0[2], w0[3], selector);
      w1[2] = __byte_perm_S (w0[1], w0[2], selector);
      w1[1] = __byte_perm_S (w0[0], w0[1], selector);
      w1[0] = __byte_perm_S (    0, w0[0], selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 5:
      w3[1] = __byte_perm_S (w1[3], w2[0], selector);
      w3[0] = __byte_perm_S (w1[2], w1[3], selector);
      w2[3] = __byte_perm_S (w1[1], w1[2], selector);
      w2[2] = __byte_perm_S (w1[0], w1[1], selector);
      w2[1] = __byte_perm_S (w0[3], w1[0], selector);
      w2[0] = __byte_perm_S (w0[2], w0[3], selector);
      w1[3] = __byte_perm_S (w0[1], w0[2], selector);
      w1[2] = __byte_perm_S (w0[0], w0[1], selector);
      w1[1] = __byte_perm_S (    0, w0[0], selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 6:
      w3[1] = __byte_perm_S (w1[2], w1[3], selector);
      w3[0] = __byte_perm_S (w1[1], w1[2], selector);
      w2[3] = __byte_perm_S (w1[0], w1[1], selector);
      w2[2] = __byte_perm_S (w0[3], w1[0], selector);
      w2[1] = __byte_perm_S (w0[2], w0[3], selector);
      w2[0] = __byte_perm_S (w0[1], w0[2], selector);
      w1[3] = __byte_perm_S (w0[0], w0[1], selector);
      w1[2] = __byte_perm_S (    0, w0[0], selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 7:
      w3[1] = __byte_perm_S (w1[1], w1[2], selector);
      w3[0] = __byte_perm_S (w1[0], w1[1], selector);
      w2[3] = __byte_perm_S (w0[3], w1[0], selector);
      w2[2] = __byte_perm_S (w0[2], w0[3], selector);
      w2[1] = __byte_perm_S (w0[1], w0[2], selector);
      w2[0] = __byte_perm_S (w0[0], w0[1], selector);
      w1[3] = __byte_perm_S (    0, w0[0], selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 8:
      w3[1] = __byte_perm_S (w1[0], w1[1], selector);
      w3[0] = __byte_perm_S (w0[3], w1[0], selector);
      w2[3] = __byte_perm_S (w0[2], w0[3], selector);
      w2[2] = __byte_perm_S (w0[1], w0[2], selector);
      w2[1] = __byte_perm_S (w0[0], w0[1], selector);
      w2[0] = __byte_perm_S (    0, w0[0], selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 9:
      w3[1] = __byte_perm_S (w0[3], w1[0], selector);
      w3[0] = __byte_perm_S (w0[2], w0[3], selector);
      w2[3] = __byte_perm_S (w0[1], w0[2], selector);
      w2[2] = __byte_perm_S (w0[0], w0[1], selector);
      w2[1] = __byte_perm_S (    0, w0[0], selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      w3[1] = __byte_perm_S (w0[2], w0[3], selector);
      w3[0] = __byte_perm_S (w0[1], w0[2], selector);
      w2[3] = __byte_perm_S (w0[0], w0[1], selector);
      w2[2] = __byte_perm_S (    0, w0[0], selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      w3[1] = __byte_perm_S (w0[1], w0[2], selector);
      w3[0] = __byte_perm_S (w0[0], w0[1], selector);
      w2[3] = __byte_perm_S (    0, w0[0], selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      w3[1] = __byte_perm_S (w0[0], w0[1], selector);
      w3[0] = __byte_perm_S (    0, w0[0], selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      w3[1] = __byte_perm_S (    0, w0[0], selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }
  #endif
}

inline void switch_buffer_by_offset_be_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  #if defined IS_AMD || defined IS_GENERIC
  switch (offset / 4)
  {
    case 0:
      w3[2] = amd_bytealign_S (w3[1],     0, offset);
      w3[1] = amd_bytealign_S (w3[0], w3[1], offset);
      w3[0] = amd_bytealign_S (w2[3], w3[0], offset);
      w2[3] = amd_bytealign_S (w2[2], w2[3], offset);
      w2[2] = amd_bytealign_S (w2[1], w2[2], offset);
      w2[1] = amd_bytealign_S (w2[0], w2[1], offset);
      w2[0] = amd_bytealign_S (w1[3], w2[0], offset);
      w1[3] = amd_bytealign_S (w1[2], w1[3], offset);
      w1[2] = amd_bytealign_S (w1[1], w1[2], offset);
      w1[1] = amd_bytealign_S (w1[0], w1[1], offset);
      w1[0] = amd_bytealign_S (w0[3], w1[0], offset);
      w0[3] = amd_bytealign_S (w0[2], w0[3], offset);
      w0[2] = amd_bytealign_S (w0[1], w0[2], offset);
      w0[1] = amd_bytealign_S (w0[0], w0[1], offset);
      w0[0] = amd_bytealign_S (    0, w0[0], offset);
      break;

    case 1:
      w3[2] = amd_bytealign_S (w3[0],     0, offset);
      w3[1] = amd_bytealign_S (w2[3], w3[0], offset);
      w3[0] = amd_bytealign_S (w2[2], w2[3], offset);
      w2[3] = amd_bytealign_S (w2[1], w2[2], offset);
      w2[2] = amd_bytealign_S (w2[0], w2[1], offset);
      w2[1] = amd_bytealign_S (w1[3], w2[0], offset);
      w2[0] = amd_bytealign_S (w1[2], w1[3], offset);
      w1[3] = amd_bytealign_S (w1[1], w1[2], offset);
      w1[2] = amd_bytealign_S (w1[0], w1[1], offset);
      w1[1] = amd_bytealign_S (w0[3], w1[0], offset);
      w1[0] = amd_bytealign_S (w0[2], w0[3], offset);
      w0[3] = amd_bytealign_S (w0[1], w0[2], offset);
      w0[2] = amd_bytealign_S (w0[0], w0[1], offset);
      w0[1] = amd_bytealign_S (    0, w0[0], offset);
      w0[0] = 0;
      break;

    case 2:
      w3[2] = amd_bytealign_S (w2[3],     0, offset);
      w3[1] = amd_bytealign_S (w2[2], w2[3], offset);
      w3[0] = amd_bytealign_S (w2[1], w2[2], offset);
      w2[3] = amd_bytealign_S (w2[0], w2[1], offset);
      w2[2] = amd_bytealign_S (w1[3], w2[0], offset);
      w2[1] = amd_bytealign_S (w1[2], w1[3], offset);
      w2[0] = amd_bytealign_S (w1[1], w1[2], offset);
      w1[3] = amd_bytealign_S (w1[0], w1[1], offset);
      w1[2] = amd_bytealign_S (w0[3], w1[0], offset);
      w1[1] = amd_bytealign_S (w0[2], w0[3], offset);
      w1[0] = amd_bytealign_S (w0[1], w0[2], offset);
      w0[3] = amd_bytealign_S (w0[0], w0[1], offset);
      w0[2] = amd_bytealign_S (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w3[2] = amd_bytealign_S (w2[2],     0, offset);
      w3[1] = amd_bytealign_S (w2[1], w2[2], offset);
      w3[0] = amd_bytealign_S (w2[0], w2[1], offset);
      w2[3] = amd_bytealign_S (w1[3], w2[0], offset);
      w2[2] = amd_bytealign_S (w1[2], w1[3], offset);
      w2[1] = amd_bytealign_S (w1[1], w1[2], offset);
      w2[0] = amd_bytealign_S (w1[0], w1[1], offset);
      w1[3] = amd_bytealign_S (w0[3], w1[0], offset);
      w1[2] = amd_bytealign_S (w0[2], w0[3], offset);
      w1[1] = amd_bytealign_S (w0[1], w0[2], offset);
      w1[0] = amd_bytealign_S (w0[0], w0[1], offset);
      w0[3] = amd_bytealign_S (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 4:
      w3[2] = amd_bytealign_S (w2[1],     0, offset);
      w3[1] = amd_bytealign_S (w2[0], w2[1], offset);
      w3[0] = amd_bytealign_S (w1[3], w2[0], offset);
      w2[3] = amd_bytealign_S (w1[2], w1[3], offset);
      w2[2] = amd_bytealign_S (w1[1], w1[2], offset);
      w2[1] = amd_bytealign_S (w1[0], w1[1], offset);
      w2[0] = amd_bytealign_S (w0[3], w1[0], offset);
      w1[3] = amd_bytealign_S (w0[2], w0[3], offset);
      w1[2] = amd_bytealign_S (w0[1], w0[2], offset);
      w1[1] = amd_bytealign_S (w0[0], w0[1], offset);
      w1[0] = amd_bytealign_S (    0, w0[0], offset);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 5:
      w3[2] = amd_bytealign_S (w2[0],     0, offset);
      w3[1] = amd_bytealign_S (w1[3], w2[0], offset);
      w3[0] = amd_bytealign_S (w1[2], w1[3], offset);
      w2[3] = amd_bytealign_S (w1[1], w1[2], offset);
      w2[2] = amd_bytealign_S (w1[0], w1[1], offset);
      w2[1] = amd_bytealign_S (w0[3], w1[0], offset);
      w2[0] = amd_bytealign_S (w0[2], w0[3], offset);
      w1[3] = amd_bytealign_S (w0[1], w0[2], offset);
      w1[2] = amd_bytealign_S (w0[0], w0[1], offset);
      w1[1] = amd_bytealign_S (    0, w0[0], offset);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 6:
      w3[2] = amd_bytealign_S (w1[3],     0, offset);
      w3[1] = amd_bytealign_S (w1[2], w1[3], offset);
      w3[0] = amd_bytealign_S (w1[1], w1[2], offset);
      w2[3] = amd_bytealign_S (w1[0], w1[1], offset);
      w2[2] = amd_bytealign_S (w0[3], w1[0], offset);
      w2[1] = amd_bytealign_S (w0[2], w0[3], offset);
      w2[0] = amd_bytealign_S (w0[1], w0[2], offset);
      w1[3] = amd_bytealign_S (w0[0], w0[1], offset);
      w1[2] = amd_bytealign_S (    0, w0[0], offset);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 7:
      w3[2] = amd_bytealign_S (w1[2],     0, offset);
      w3[1] = amd_bytealign_S (w1[1], w1[2], offset);
      w3[0] = amd_bytealign_S (w1[0], w1[1], offset);
      w2[3] = amd_bytealign_S (w0[3], w1[0], offset);
      w2[2] = amd_bytealign_S (w0[2], w0[3], offset);
      w2[1] = amd_bytealign_S (w0[1], w0[2], offset);
      w2[0] = amd_bytealign_S (w0[0], w0[1], offset);
      w1[3] = amd_bytealign_S (    0, w0[0], offset);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 8:
      w3[2] = amd_bytealign_S (w1[1],     0, offset);
      w3[1] = amd_bytealign_S (w1[0], w1[1], offset);
      w3[0] = amd_bytealign_S (w0[3], w1[0], offset);
      w2[3] = amd_bytealign_S (w0[2], w0[3], offset);
      w2[2] = amd_bytealign_S (w0[1], w0[2], offset);
      w2[1] = amd_bytealign_S (w0[0], w0[1], offset);
      w2[0] = amd_bytealign_S (    0, w0[0], offset);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 9:
      w3[2] = amd_bytealign_S (w1[0],     0, offset);
      w3[1] = amd_bytealign_S (w0[3], w1[0], offset);
      w3[0] = amd_bytealign_S (w0[2], w0[3], offset);
      w2[3] = amd_bytealign_S (w0[1], w0[2], offset);
      w2[2] = amd_bytealign_S (w0[0], w0[1], offset);
      w2[1] = amd_bytealign_S (    0, w0[0], offset);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 10:
      w3[2] = amd_bytealign_S (w0[3],     0, offset);
      w3[1] = amd_bytealign_S (w0[2], w0[3], offset);
      w3[0] = amd_bytealign_S (w0[1], w0[2], offset);
      w2[3] = amd_bytealign_S (w0[0], w0[1], offset);
      w2[2] = amd_bytealign_S (    0, w0[0], offset);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 11:
      w3[2] = amd_bytealign_S (w0[2],     0, offset);
      w3[1] = amd_bytealign_S (w0[1], w0[2], offset);
      w3[0] = amd_bytealign_S (w0[0], w0[1], offset);
      w2[3] = amd_bytealign_S (    0, w0[0], offset);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 12:
      w3[2] = amd_bytealign_S (w0[1],     0, offset);
      w3[1] = amd_bytealign_S (w0[0], w0[1], offset);
      w3[0] = amd_bytealign_S (    0, w0[0], offset);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 13:
      w3[2] = amd_bytealign_S (w0[0],     0, offset);
      w3[1] = amd_bytealign_S (    0, w0[0], offset);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w3[1] = __byte_perm_S (w3[1], w3[0], selector);
      w3[0] = __byte_perm_S (w3[0], w2[3], selector);
      w2[3] = __byte_perm_S (w2[3], w2[2], selector);
      w2[2] = __byte_perm_S (w2[2], w2[1], selector);
      w2[1] = __byte_perm_S (w2[1], w2[0], selector);
      w2[0] = __byte_perm_S (w2[0], w1[3], selector);
      w1[3] = __byte_perm_S (w1[3], w1[2], selector);
      w1[2] = __byte_perm_S (w1[2], w1[1], selector);
      w1[1] = __byte_perm_S (w1[1], w1[0], selector);
      w1[0] = __byte_perm_S (w1[0], w0[3], selector);
      w0[3] = __byte_perm_S (w0[3], w0[2], selector);
      w0[2] = __byte_perm_S (w0[2], w0[1], selector);
      w0[1] = __byte_perm_S (w0[1], w0[0], selector);
      w0[0] = __byte_perm_S (w0[0],     0, selector);
      break;

    case 1:
      w3[1] = __byte_perm_S (w3[0], w2[3], selector);
      w3[0] = __byte_perm_S (w2[3], w2[2], selector);
      w2[3] = __byte_perm_S (w2[2], w2[1], selector);
      w2[2] = __byte_perm_S (w2[1], w2[0], selector);
      w2[1] = __byte_perm_S (w2[0], w1[3], selector);
      w2[0] = __byte_perm_S (w1[3], w1[2], selector);
      w1[3] = __byte_perm_S (w1[2], w1[1], selector);
      w1[2] = __byte_perm_S (w1[1], w1[0], selector);
      w1[1] = __byte_perm_S (w1[0], w0[3], selector);
      w1[0] = __byte_perm_S (w0[3], w0[2], selector);
      w0[3] = __byte_perm_S (w0[2], w0[1], selector);
      w0[2] = __byte_perm_S (w0[1], w0[0], selector);
      w0[1] = __byte_perm_S (w0[0],     0, selector);
      w0[0] = 0;
      break;

    case 2:
      w3[1] = __byte_perm_S (w2[3], w2[2], selector);
      w3[0] = __byte_perm_S (w2[2], w2[1], selector);
      w2[3] = __byte_perm_S (w2[1], w2[0], selector);
      w2[2] = __byte_perm_S (w2[0], w1[3], selector);
      w2[1] = __byte_perm_S (w1[3], w1[2], selector);
      w2[0] = __byte_perm_S (w1[2], w1[1], selector);
      w1[3] = __byte_perm_S (w1[1], w1[0], selector);
      w1[2] = __byte_perm_S (w1[0], w0[3], selector);
      w1[1] = __byte_perm_S (w0[3], w0[2], selector);
      w1[0] = __byte_perm_S (w0[2], w0[1], selector);
      w0[3] = __byte_perm_S (w0[1], w0[0], selector);
      w0[2] = __byte_perm_S (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w3[1] = __byte_perm_S (w2[2], w2[1], selector);
      w3[0] = __byte_perm_S (w2[1], w2[0], selector);
      w2[3] = __byte_perm_S (w2[0], w1[3], selector);
      w2[2] = __byte_perm_S (w1[3], w1[2], selector);
      w2[1] = __byte_perm_S (w1[2], w1[1], selector);
      w2[0] = __byte_perm_S (w1[1], w1[0], selector);
      w1[3] = __byte_perm_S (w1[0], w0[3], selector);
      w1[2] = __byte_perm_S (w0[3], w0[2], selector);
      w1[1] = __byte_perm_S (w0[2], w0[1], selector);
      w1[0] = __byte_perm_S (w0[1], w0[0], selector);
      w0[3] = __byte_perm_S (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 4:
      w3[1] = __byte_perm_S (w2[1], w2[0], selector);
      w3[0] = __byte_perm_S (w2[0], w1[3], selector);
      w2[3] = __byte_perm_S (w1[3], w1[2], selector);
      w2[2] = __byte_perm_S (w1[2], w1[1], selector);
      w2[1] = __byte_perm_S (w1[1], w1[0], selector);
      w2[0] = __byte_perm_S (w1[0], w0[3], selector);
      w1[3] = __byte_perm_S (w0[3], w0[2], selector);
      w1[2] = __byte_perm_S (w0[2], w0[1], selector);
      w1[1] = __byte_perm_S (w0[1], w0[0], selector);
      w1[0] = __byte_perm_S (w0[0],     0, selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 5:
      w3[1] = __byte_perm_S (w2[0], w1[3], selector);
      w3[0] = __byte_perm_S (w1[3], w1[2], selector);
      w2[3] = __byte_perm_S (w1[2], w1[1], selector);
      w2[2] = __byte_perm_S (w1[1], w1[0], selector);
      w2[1] = __byte_perm_S (w1[0], w0[3], selector);
      w2[0] = __byte_perm_S (w0[3], w0[2], selector);
      w1[3] = __byte_perm_S (w0[2], w0[1], selector);
      w1[2] = __byte_perm_S (w0[1], w0[0], selector);
      w1[1] = __byte_perm_S (w0[0],     0, selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 6:
      w3[1] = __byte_perm_S (w1[3], w1[2], selector);
      w3[0] = __byte_perm_S (w1[2], w1[1], selector);
      w2[3] = __byte_perm_S (w1[1], w1[0], selector);
      w2[2] = __byte_perm_S (w1[0], w0[3], selector);
      w2[1] = __byte_perm_S (w0[3], w0[2], selector);
      w2[0] = __byte_perm_S (w0[2], w0[1], selector);
      w1[3] = __byte_perm_S (w0[1], w0[0], selector);
      w1[2] = __byte_perm_S (w0[0],     0, selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 7:
      w3[1] = __byte_perm_S (w1[2], w1[1], selector);
      w3[0] = __byte_perm_S (w1[1], w1[0], selector);
      w2[3] = __byte_perm_S (w1[0], w0[3], selector);
      w2[2] = __byte_perm_S (w0[3], w0[2], selector);
      w2[1] = __byte_perm_S (w0[2], w0[1], selector);
      w2[0] = __byte_perm_S (w0[1], w0[0], selector);
      w1[3] = __byte_perm_S (w0[0],     0, selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 8:
      w3[1] = __byte_perm_S (w1[1], w1[0], selector);
      w3[0] = __byte_perm_S (w1[0], w0[3], selector);
      w2[3] = __byte_perm_S (w0[3], w0[2], selector);
      w2[2] = __byte_perm_S (w0[2], w0[1], selector);
      w2[1] = __byte_perm_S (w0[1], w0[0], selector);
      w2[0] = __byte_perm_S (w0[0],     0, selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 9:
      w3[1] = __byte_perm_S (w1[0], w0[3], selector);
      w3[0] = __byte_perm_S (w0[3], w0[2], selector);
      w2[3] = __byte_perm_S (w0[2], w0[1], selector);
      w2[2] = __byte_perm_S (w0[1], w0[0], selector);
      w2[1] = __byte_perm_S (w0[0],     0, selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 10:
      w3[1] = __byte_perm_S (w0[3], w0[2], selector);
      w3[0] = __byte_perm_S (w0[2], w0[1], selector);
      w2[3] = __byte_perm_S (w0[1], w0[0], selector);
      w2[2] = __byte_perm_S (w0[0],     0, selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 11:
      w3[1] = __byte_perm_S (w0[2], w0[1], selector);
      w3[0] = __byte_perm_S (w0[1], w0[0], selector);
      w2[3] = __byte_perm_S (w0[0],     0, selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 12:
      w3[1] = __byte_perm_S (w0[1], w0[0], selector);
      w3[0] = __byte_perm_S (w0[0],     0, selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 13:
      w3[1] = __byte_perm_S (w0[0],     0, selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif
}

/**
 * vector functions on scalar types (for inner loop usage)
 */

#define PACKVS2(sn,vn,e)  \
  sn[0] = vn[0].s##e;     \
  sn[1] = vn[1].s##e;

#define PACKSV2(sn,vn,e)  \
  vn[0].s##e = sn[0];     \
  vn[1].s##e = sn[1];

#define PACKVS24(s0,s1,v0,v1,e) \
  PACKVS4 (s0, v0, e);          \
  PACKVS4 (s1, v1, e);

#define PACKSV24(s0,s1,v0,v1,e) \
  PACKSV4 (s0, v0, e);          \
  PACKSV4 (s1, v1, e);

#define PACKVS4(sn,vn,e)  \
  sn[0] = vn[0].s##e;     \
  sn[1] = vn[1].s##e;     \
  sn[2] = vn[2].s##e;     \
  sn[3] = vn[3].s##e;

#define PACKSV4(sn,vn,e)  \
  vn[0].s##e = sn[0];     \
  vn[1].s##e = sn[1];     \
  vn[2].s##e = sn[2];     \
  vn[3].s##e = sn[3];

#define PACKVS44(s0,s1,s2,s3,v0,v1,v2,v3,e) \
  PACKVS4 (s0, v0, e);                      \
  PACKVS4 (s1, v1, e);                      \
  PACKVS4 (s2, v2, e);                      \
  PACKVS4 (s3, v3, e);

#define PACKSV44(s0,s1,s2,s3,v0,v1,v2,v3,e) \
  PACKSV4 (s0, v0, e);                      \
  PACKSV4 (s1, v1, e);                      \
  PACKSV4 (s2, v2, e);                      \
  PACKSV4 (s3, v3, e);

inline void switch_buffer_by_offset_le_VV (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32x offset)
{
  #if VECT_SIZE == 1

  switch_buffer_by_offset_le_S (w0, w1, w2, w3, offset);

  #else

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  #endif

  #if   VECT_SIZE == 2

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);

  #elif VECT_SIZE == 4

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);

  #elif VECT_SIZE == 8

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 4); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s4); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 4);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 5); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s5); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 5);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 6); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s6); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 6);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 7); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s7); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 7);

  #elif VECT_SIZE == 16

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 4); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s4); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 4);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 5); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s5); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 5);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 6); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s6); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 6);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 7); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s7); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 7);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 8); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s8); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 8);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 9); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.s9); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 9);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, a); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.sa); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, a);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, b); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.sb); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, b);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, c); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.sc); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, c);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, d); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.sd); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, d);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, e); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.se); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, e);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, f); switch_buffer_by_offset_le_S (t0, t1, t2, t3, offset.sf); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, f);

  #endif
}

inline void append_0x01_2x4_VV (u32x w0[4], u32x w1[4], const u32x offset)
{
  #if VECT_SIZE == 1

  append_0x01_2x4_S (w0, w1, offset);

  #else

  u32 t0[4];
  u32 t1[4];

  #endif

  #if   VECT_SIZE == 2

  PACKVS24 (t0, t1, w0, w1, 0); append_0x01_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x01_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);

  #elif VECT_SIZE == 4

  PACKVS24 (t0, t1, w0, w1, 0); append_0x01_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x01_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x01_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x01_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);

  #elif VECT_SIZE == 8

  PACKVS24 (t0, t1, w0, w1, 0); append_0x01_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x01_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x01_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x01_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);
  PACKVS24 (t0, t1, w0, w1, 4); append_0x01_2x4_S (t0, t1, offset.s4); PACKSV24 (t0, t1, w0, w1, 4);
  PACKVS24 (t0, t1, w0, w1, 5); append_0x01_2x4_S (t0, t1, offset.s5); PACKSV24 (t0, t1, w0, w1, 5);
  PACKVS24 (t0, t1, w0, w1, 6); append_0x01_2x4_S (t0, t1, offset.s6); PACKSV24 (t0, t1, w0, w1, 6);
  PACKVS24 (t0, t1, w0, w1, 7); append_0x01_2x4_S (t0, t1, offset.s7); PACKSV24 (t0, t1, w0, w1, 7);

  #elif VECT_SIZE == 16

  PACKVS24 (t0, t1, w0, w1, 0); append_0x01_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x01_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x01_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x01_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);
  PACKVS24 (t0, t1, w0, w1, 4); append_0x01_2x4_S (t0, t1, offset.s4); PACKSV24 (t0, t1, w0, w1, 4);
  PACKVS24 (t0, t1, w0, w1, 5); append_0x01_2x4_S (t0, t1, offset.s5); PACKSV24 (t0, t1, w0, w1, 5);
  PACKVS24 (t0, t1, w0, w1, 6); append_0x01_2x4_S (t0, t1, offset.s6); PACKSV24 (t0, t1, w0, w1, 6);
  PACKVS24 (t0, t1, w0, w1, 7); append_0x01_2x4_S (t0, t1, offset.s7); PACKSV24 (t0, t1, w0, w1, 7);
  PACKVS24 (t0, t1, w0, w1, 8); append_0x01_2x4_S (t0, t1, offset.s8); PACKSV24 (t0, t1, w0, w1, 8);
  PACKVS24 (t0, t1, w0, w1, 9); append_0x01_2x4_S (t0, t1, offset.s9); PACKSV24 (t0, t1, w0, w1, 9);
  PACKVS24 (t0, t1, w0, w1, a); append_0x01_2x4_S (t0, t1, offset.sa); PACKSV24 (t0, t1, w0, w1, a);
  PACKVS24 (t0, t1, w0, w1, b); append_0x01_2x4_S (t0, t1, offset.sb); PACKSV24 (t0, t1, w0, w1, b);
  PACKVS24 (t0, t1, w0, w1, c); append_0x01_2x4_S (t0, t1, offset.sc); PACKSV24 (t0, t1, w0, w1, c);
  PACKVS24 (t0, t1, w0, w1, d); append_0x01_2x4_S (t0, t1, offset.sd); PACKSV24 (t0, t1, w0, w1, d);
  PACKVS24 (t0, t1, w0, w1, e); append_0x01_2x4_S (t0, t1, offset.se); PACKSV24 (t0, t1, w0, w1, e);
  PACKVS24 (t0, t1, w0, w1, f); append_0x01_2x4_S (t0, t1, offset.sf); PACKSV24 (t0, t1, w0, w1, f);

  #endif
}

inline void append_0x80_2x4_VV (u32x w0[4], u32x w1[4], const u32x offset)
{
  #if VECT_SIZE == 1

  append_0x80_2x4_S (w0, w1, offset);

  #else

  u32 t0[4];
  u32 t1[4];

  #endif

  #if   VECT_SIZE == 2

  PACKVS24 (t0, t1, w0, w1, 0); append_0x80_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x80_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);

  #elif VECT_SIZE == 4

  PACKVS24 (t0, t1, w0, w1, 0); append_0x80_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x80_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x80_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x80_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);

  #elif VECT_SIZE == 8

  PACKVS24 (t0, t1, w0, w1, 0); append_0x80_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x80_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x80_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x80_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);
  PACKVS24 (t0, t1, w0, w1, 4); append_0x80_2x4_S (t0, t1, offset.s4); PACKSV24 (t0, t1, w0, w1, 4);
  PACKVS24 (t0, t1, w0, w1, 5); append_0x80_2x4_S (t0, t1, offset.s5); PACKSV24 (t0, t1, w0, w1, 5);
  PACKVS24 (t0, t1, w0, w1, 6); append_0x80_2x4_S (t0, t1, offset.s6); PACKSV24 (t0, t1, w0, w1, 6);
  PACKVS24 (t0, t1, w0, w1, 7); append_0x80_2x4_S (t0, t1, offset.s7); PACKSV24 (t0, t1, w0, w1, 7);

  #elif VECT_SIZE == 16

  PACKVS24 (t0, t1, w0, w1, 0); append_0x80_2x4_S (t0, t1, offset.s0); PACKSV24 (t0, t1, w0, w1, 0);
  PACKVS24 (t0, t1, w0, w1, 1); append_0x80_2x4_S (t0, t1, offset.s1); PACKSV24 (t0, t1, w0, w1, 1);
  PACKVS24 (t0, t1, w0, w1, 2); append_0x80_2x4_S (t0, t1, offset.s2); PACKSV24 (t0, t1, w0, w1, 2);
  PACKVS24 (t0, t1, w0, w1, 3); append_0x80_2x4_S (t0, t1, offset.s3); PACKSV24 (t0, t1, w0, w1, 3);
  PACKVS24 (t0, t1, w0, w1, 4); append_0x80_2x4_S (t0, t1, offset.s4); PACKSV24 (t0, t1, w0, w1, 4);
  PACKVS24 (t0, t1, w0, w1, 5); append_0x80_2x4_S (t0, t1, offset.s5); PACKSV24 (t0, t1, w0, w1, 5);
  PACKVS24 (t0, t1, w0, w1, 6); append_0x80_2x4_S (t0, t1, offset.s6); PACKSV24 (t0, t1, w0, w1, 6);
  PACKVS24 (t0, t1, w0, w1, 7); append_0x80_2x4_S (t0, t1, offset.s7); PACKSV24 (t0, t1, w0, w1, 7);
  PACKVS24 (t0, t1, w0, w1, 8); append_0x80_2x4_S (t0, t1, offset.s8); PACKSV24 (t0, t1, w0, w1, 8);
  PACKVS24 (t0, t1, w0, w1, 9); append_0x80_2x4_S (t0, t1, offset.s9); PACKSV24 (t0, t1, w0, w1, 9);
  PACKVS24 (t0, t1, w0, w1, a); append_0x80_2x4_S (t0, t1, offset.sa); PACKSV24 (t0, t1, w0, w1, a);
  PACKVS24 (t0, t1, w0, w1, b); append_0x80_2x4_S (t0, t1, offset.sb); PACKSV24 (t0, t1, w0, w1, b);
  PACKVS24 (t0, t1, w0, w1, c); append_0x80_2x4_S (t0, t1, offset.sc); PACKSV24 (t0, t1, w0, w1, c);
  PACKVS24 (t0, t1, w0, w1, d); append_0x80_2x4_S (t0, t1, offset.sd); PACKSV24 (t0, t1, w0, w1, d);
  PACKVS24 (t0, t1, w0, w1, e); append_0x80_2x4_S (t0, t1, offset.se); PACKSV24 (t0, t1, w0, w1, e);
  PACKVS24 (t0, t1, w0, w1, f); append_0x80_2x4_S (t0, t1, offset.sf); PACKSV24 (t0, t1, w0, w1, f);

  #endif
}

inline void append_0x80_4x4_VV (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32x offset)
{
  #if VECT_SIZE == 1

  append_0x80_4x4_S (w0, w1, w2, w3, offset);

  #else

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  #endif

  #if   VECT_SIZE == 2

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); append_0x80_4x4_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); append_0x80_4x4_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);

  #elif VECT_SIZE == 4

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); append_0x80_4x4_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); append_0x80_4x4_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); append_0x80_4x4_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); append_0x80_4x4_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);

  #elif VECT_SIZE == 8

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); append_0x80_4x4_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); append_0x80_4x4_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); append_0x80_4x4_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); append_0x80_4x4_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 4); append_0x80_4x4_S (t0, t1, t2, t3, offset.s4); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 4);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 5); append_0x80_4x4_S (t0, t1, t2, t3, offset.s5); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 5);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 6); append_0x80_4x4_S (t0, t1, t2, t3, offset.s6); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 6);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 7); append_0x80_4x4_S (t0, t1, t2, t3, offset.s7); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 7);

  #elif VECT_SIZE == 16

  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 0); append_0x80_4x4_S (t0, t1, t2, t3, offset.s0); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 0);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 1); append_0x80_4x4_S (t0, t1, t2, t3, offset.s1); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 1);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 2); append_0x80_4x4_S (t0, t1, t2, t3, offset.s2); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 2);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 3); append_0x80_4x4_S (t0, t1, t2, t3, offset.s3); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 3);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 4); append_0x80_4x4_S (t0, t1, t2, t3, offset.s4); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 4);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 5); append_0x80_4x4_S (t0, t1, t2, t3, offset.s5); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 5);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 6); append_0x80_4x4_S (t0, t1, t2, t3, offset.s6); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 6);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 7); append_0x80_4x4_S (t0, t1, t2, t3, offset.s7); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 7);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 8); append_0x80_4x4_S (t0, t1, t2, t3, offset.s8); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 8);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, 9); append_0x80_4x4_S (t0, t1, t2, t3, offset.s9); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, 9);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, a); append_0x80_4x4_S (t0, t1, t2, t3, offset.sa); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, a);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, b); append_0x80_4x4_S (t0, t1, t2, t3, offset.sb); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, b);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, c); append_0x80_4x4_S (t0, t1, t2, t3, offset.sc); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, c);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, d); append_0x80_4x4_S (t0, t1, t2, t3, offset.sd); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, d);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, e); append_0x80_4x4_S (t0, t1, t2, t3, offset.se); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, e);
  PACKVS44 (t0, t1, t2, t3, w0, w1, w2, w3, f); append_0x80_4x4_S (t0, t1, t2, t3, offset.sf); PACKSV44 (t0, t1, t2, t3, w0, w1, w2, w3, f);

  #endif
}

__kernel void gpu_memset (__global uint4 *buf, const u32 value, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  buf[gid] = (uint4) (value);
}
