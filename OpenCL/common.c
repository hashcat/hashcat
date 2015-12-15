/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

static int hash_comp (const u32 d1[4], __global u32 *d2)
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

static int find_hash (const u32 digest[4], const u32 digests_cnt, __global digest_t *digests_buf)
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

static u32 check_bitmap (__global u32 *bitmap, const u32 bitmap_mask, const u32 bitmap_shift, const u32 digest)
{
  return (bitmap[(digest >> bitmap_shift) & bitmap_mask] & (1 << (digest & 0x1f)));
}

static u32 check (const u32 digest[2], __global u32 *bitmap_s1_a, __global u32 *bitmap_s1_b, __global u32 *bitmap_s1_c, __global u32 *bitmap_s1_d, __global u32 *bitmap_s2_a, __global u32 *bitmap_s2_b, __global u32 *bitmap_s2_c, __global u32 *bitmap_s2_d, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2)
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

static void mark_hash (__global plain_t *plains_buf, __global u32 *hashes_shown, const int hash_pos, const u32 gid, const u32 il_pos)
{
  hashes_shown[hash_pos] = 1;

  plains_buf[hash_pos].gidvid = (gid * 1) + 0;
  plains_buf[hash_pos].il_pos = il_pos;
}

static void truncate_block (u32 w[4], const u32 len)
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

static void make_unicode (const u32 in[4], u32 out1[4], u32 out2[4])
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

  #ifdef IS_AMD
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

static void undo_unicode (const u32 in1[4], const u32 in2[4], u32 out[4])
{
  #ifdef IS_NV
  out[0] = __byte_perm (in1[0], in1[1], 0x6420);
  out[1] = __byte_perm (in1[2], in1[3], 0x6420);
  out[2] = __byte_perm (in2[0], in2[1], 0x6420);
  out[3] = __byte_perm (in2[2], in2[3], 0x6420);
  #endif

  #ifdef IS_AMD
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

static void append_0x01_1x4 (u32 w0[4], const u32 offset)
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

static void append_0x01_2x4 (u32 w0[4], u32 w1[4], const u32 offset)
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

static void append_0x01_3x4 (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
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

static void append_0x01_4x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
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

static void append_0x01_8x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 w4[4], u32 w5[4], u32 w6[4], u32 w7[4], const u32 offset)
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

static void append_0x02_1x4 (u32 w0[4], const u32 offset)
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

static void append_0x02_2x4 (u32 w0[4], u32 w1[4], const u32 offset)
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

static void append_0x02_3x4 (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
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

static void append_0x02_4x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
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

static void append_0x02_8x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 w4[4], u32 w5[4], u32 w6[4], u32 w7[4], const u32 offset)
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

static void append_0x80_1x4 (u32 w0[4], const u32 offset)
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

static void append_0x80_2x4 (u32 w0[4], u32 w1[4], const u32 offset)
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

static void append_0x80_3x4 (u32 w0[4], u32 w1[4], u32 w2[4], const u32 offset)
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

static void append_0x80_4x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
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

static void append_0x80_8x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 w4[4], u32 w5[4], u32 w6[4], u32 w7[4], const u32 offset)
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

static void append_0x80_1x16 (u32 w[16], const u32 offset)
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

static void switch_buffer_by_offset (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  #ifdef IS_AMD
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

static void switch_buffer_by_offset_be (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 offset)
{
  #ifdef IS_AMD
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

/* not needed anymore?

// before: append_0x80_2_be
static void append_0x80_2x4_be (u32 w0[4], u32 w1[4], const u32 offset)
{
  switch (offset)
  {
    case  0:
      w0[0] |= 0x80000000;
      break;

    case  1:
      w0[0] |= 0x800000;
      break;

    case  2:
      w0[0] |= 0x8000;
      break;

    case  3:
      w0[0] |= 0x80;
      break;

    case  4:
      w0[1] |= 0x80000000;
      break;

    case  5:
      w0[1] |= 0x800000;
      break;

    case  6:
      w0[1] |= 0x8000;
      break;

    case  7:
      w0[1] |= 0x80;
      break;

    case  8:
      w0[2] |= 0x80000000;
      break;

    case  9:
      w0[2] |= 0x800000;
      break;

    case 10:
      w0[2] |= 0x8000;
      break;

    case 11:
      w0[2] |= 0x80;
      break;

    case 12:
      w0[3] |= 0x80000000;
      break;

    case 13:
      w0[3] |= 0x800000;
      break;

    case 14:
      w0[3] |= 0x8000;
      break;

    case 15:
      w0[3] |= 0x80;
      break;

    case 16:
      w1[0] |= 0x80000000;
      break;

    case 17:
      w1[0] |= 0x800000;
      break;

    case 18:
      w1[0] |= 0x8000;
      break;

    case 19:
      w1[0] |= 0x80;
      break;

    case 20:
      w1[1] |= 0x80000000;
      break;

    case 21:
      w1[1] |= 0x800000;
      break;

    case 22:
      w1[1] |= 0x8000;
      break;

    case 23:
      w1[1] |= 0x80;
      break;

    case 24:
      w1[2] |= 0x80000000;
      break;

    case 25:
      w1[2] |= 0x800000;
      break;

    case 26:
      w1[2] |= 0x8000;
      break;

    case 27:
      w1[2] |= 0x80;
      break;

    case 28:
      w1[3] |= 0x80000000;
      break;

    case 29:
      w1[3] |= 0x800000;
      break;

    case 30:
      w1[3] |= 0x8000;
      break;

    case 31:
      w1[3] |= 0x80;
      break;
  }
}

// before: append_0x80_8
static void append_0x80_1x32 (u32 w[32], const u32 offset)
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

    case 64:
      w[16] = 0x80;
      break;

    case 65:
      w[16] = w[16] | 0x8000;
      break;

    case 66:
      w[16] = w[16] | 0x800000;
      break;

    case 67:
      w[16] = w[16] | 0x80000000;
      break;

    case 68:
      w[17] = 0x80;
      break;

    case 69:
      w[17] = w[17] | 0x8000;
      break;

    case 70:
      w[17] = w[17] | 0x800000;
      break;

    case 71:
      w[17] = w[17] | 0x80000000;
      break;

    case 72:
      w[18] = 0x80;
      break;

    case 73:
      w[18] = w[18] | 0x8000;
      break;

    case 74:
      w[18] = w[18] | 0x800000;
      break;

    case 75:
      w[18] = w[18] | 0x80000000;
      break;

    case 76:
      w[19] = 0x80;
      break;

    case 77:
      w[19] = w[19] | 0x8000;
      break;

    case 78:
      w[19] = w[19] | 0x800000;
      break;

    case 79:
      w[19] = w[19] | 0x80000000;
      break;

    case 80:
      w[20] = 0x80;
      break;

    case 81:
      w[20] = w[20] | 0x8000;
      break;

    case 82:
      w[20] = w[20] | 0x800000;
      break;

    case 83:
      w[20] = w[20] | 0x80000000;
      break;

    case 84:
      w[21] = 0x80;
      break;

    case 85:
      w[21] = w[21] | 0x8000;
      break;

    case 86:
      w[21] = w[21] | 0x800000;
      break;

    case 87:
      w[21] = w[21] | 0x80000000;
      break;

    case 88:
      w[22] = 0x80;
      break;

    case 89:
      w[22] = w[22] | 0x8000;
      break;

    case 90:
      w[22] = w[22] | 0x800000;
      break;

    case 91:
      w[22] = w[22] | 0x80000000;
      break;

    case 92:
      w[23] = 0x80;
      break;

    case 93:
      w[23] = w[23] | 0x8000;
      break;

    case 94:
      w[23] = w[23] | 0x800000;
      break;

    case 95:
      w[23] = w[23] | 0x80000000;
      break;

    case 96:
      w[24] = 0x80;
      break;

    case 97:
      w[24] = w[24] | 0x8000;
      break;

    case 98:
      w[24] = w[24] | 0x800000;
      break;

    case 99:
      w[24] = w[24] | 0x80000000;
      break;

    case 100:
      w[25] = 0x80;
      break;

    case 101:
      w[25] = w[25] | 0x8000;
      break;

    case 102:
      w[25] = w[25] | 0x800000;
      break;

    case 103:
      w[25] = w[25] | 0x80000000;
      break;

    case 104:
      w[26] = 0x80;
      break;

    case 105:
      w[26] = w[26] | 0x8000;
      break;

    case 106:
      w[26] = w[26] | 0x800000;
      break;

    case 107:
      w[26] = w[26] | 0x80000000;
      break;

    case 108:
      w[27] = 0x80;
      break;

    case 109:
      w[27] = w[27] | 0x8000;
      break;

    case 110:
      w[27] = w[27] | 0x800000;
      break;

    case 111:
      w[27] = w[27] | 0x80000000;
      break;

    case 112:
      w[28] = 0x80;
      break;

    case 113:
      w[28] = w[28] | 0x8000;
      break;

    case 114:
      w[28] = w[28] | 0x800000;
      break;

    case 115:
      w[28] = w[28] | 0x80000000;
      break;

    case 116:
      w[29] = 0x80;
      break;

    case 117:
      w[29] = w[29] | 0x8000;
      break;

    case 118:
      w[29] = w[29] | 0x800000;
      break;

    case 119:
      w[29] = w[29] | 0x80000000;
      break;

    case 120:
      w[30] = 0x80;
      break;

    case 121:
      w[30] = w[30] | 0x8000;
      break;

    case 122:
      w[30] = w[30] | 0x800000;
      break;

    case 123:
      w[30] = w[30] | 0x80000000;
      break;

    case 124:
      w[31] = 0x80;
      break;

    case 125:
      w[31] = w[31] | 0x8000;
      break;

    case 126:
      w[31] = w[31] | 0x800000;
      break;

    case 127:
      w[31] = w[31] | 0x80000000;
      break;
  }
}

// before: device_memcat2L
static void memcat_c7_d1x2_sl1x2_sr1x2 (const u32 offset, u32 dst0[2], u32 src_l0[2], u32 src_r0[2])
{
  switch (offset)
  {
    case 1:
      dst0[0] = src_l0[0]       | src_r0[0] <<  8;
      dst0[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      break;

    case 2:
      dst0[0] = src_l0[0]       | src_r0[0] << 16;
      dst0[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      break;

    case 3:
      dst0[0] = src_l0[0]       | src_r0[0] << 24;
      dst0[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      break;

    case 4:
      dst0[1] = src_r0[0];
      break;

    case 5:
      dst0[1] = src_l0[1]       | src_r0[0] <<  8;
      break;

    case 6:
      dst0[1] = src_l0[1]       | src_r0[0] << 16;
      break;

    case 7:
      dst0[1] = src_l0[1]       | src_r0[0] << 24;
      break;
  }
}

// before: device_memcat4L
static void memcat_c15_d1x4_sl1x4_sr1x4 (const u32 offset, u32 dst0[4], u32 src_l0[4], u32 src_r0[4])
{
  switch (offset)
  {
    case 1:
      dst0[0] = src_l0[0]       | src_r0[0] <<  8;
      dst0[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst0[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      break;

    case 2:
      dst0[0] = src_l0[0]       | src_r0[0] << 16;
      dst0[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst0[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      break;

    case 3:
      dst0[0] = src_l0[0]       | src_r0[0] << 24;
      dst0[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst0[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      break;

    case 4:
      dst0[1] = src_r0[0];
      dst0[2] = src_r0[1];
      dst0[3] = src_r0[2];
      break;

    case 5:
      dst0[1] = src_l0[1]       | src_r0[0] <<  8;
      dst0[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      break;

    case 6:
      dst0[1] = src_l0[1]       | src_r0[0] << 16;
      dst0[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      break;

    case 7:
      dst0[1] = src_l0[1]       | src_r0[0] << 24;
      dst0[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      break;

    case 8:
      dst0[2] = src_r0[0];
      dst0[3] = src_r0[1];
      break;

    case 9:
      dst0[2] = src_l0[2]       | src_r0[0] <<  8;
      dst0[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      break;

    case 10:
      dst0[2] = src_l0[2]       | src_r0[0] << 16;
      dst0[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      break;

    case 11:
      dst0[2] = src_l0[2]       | src_r0[0] << 24;
      dst0[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      break;

    case 12:
      dst0[3] = src_r0[0];
      break;

    case 13:
      dst0[3] = src_l0[3]       | src_r0[0] <<  8;
      break;

    case 14:
      dst0[3] = src_l0[3]       | src_r0[0] << 16;
      break;

    case 15:
      dst0[3] = src_l0[3]       | src_r0[0] << 24;
      break;
  }
}

// before: device_memcat8L
static void memcat_c31_d2x4_sl2x4_sr1x4 (const u32 offset, u32 dst0[4], u32 dst1[4], u32 src_l0[4], u32 src_l1[4], u32 src_r0[4])
{
  switch (offset)
  {
    case 1:
      dst0[0] = src_l0[0]       | src_r0[0] <<  8;
      dst0[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst0[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[0] = src_r0[3] >> 24;
      break;

    case 2:
      dst0[0] = src_l0[0]       | src_r0[0] << 16;
      dst0[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst0[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[0] = src_r0[3] >> 16;
      break;

    case 3:
      dst0[0] = src_l0[0]       | src_r0[0] << 24;
      dst0[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst0[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[0] = src_r0[3] >>  8;
      break;

    case 4:
      dst0[1] = src_r0[0];
      dst0[2] = src_r0[1];
      dst0[3] = src_r0[2];
      dst1[0] = src_r0[3];
      break;

    case 5:
      dst0[1] = src_l0[1]       | src_r0[0] <<  8;
      dst0[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[0] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[1] = src_r0[3] >> 24;
      break;

    case 6:
      dst0[1] = src_l0[1]       | src_r0[0] << 16;
      dst0[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[0] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[1] = src_r0[3] >> 16;
      break;

    case 7:
      dst0[1] = src_l0[1]       | src_r0[0] << 24;
      dst0[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[0] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[1] = src_r0[3] >>  8;
      break;

    case 8:
      dst0[2] = src_r0[0];
      dst0[3] = src_r0[1];
      dst1[0] = src_r0[2];
      dst1[1] = src_r0[3];
      break;

    case 9:
      dst0[2] = src_l0[2]       | src_r0[0] <<  8;
      dst0[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[0] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[1] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[2] = src_r0[3] >> 24;
      break;

    case 10:
      dst0[2] = src_l0[2]       | src_r0[0] << 16;
      dst0[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[0] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[1] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[2] = src_r0[3] >> 16;
      break;

    case 11:
      dst0[2] = src_l0[2]       | src_r0[0] << 24;
      dst0[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[0] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[1] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[2] = src_r0[3] >>  8;
      break;

    case 12:
      dst0[3] = src_r0[0];
      dst1[0] = src_r0[1];
      dst1[1] = src_r0[2];
      dst1[2] = src_r0[3];
      break;

    case 13:
      dst0[3] = src_l0[3]       | src_r0[0] <<  8;
      dst1[0] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[1] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[2] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[3] = src_r0[3] >> 24;
      break;

    case 14:
      dst0[3] = src_l0[3]       | src_r0[0] << 16;
      dst1[0] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[1] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[2] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[3] = src_r0[3] >> 16;
      break;

    case 15:
      dst0[3] = src_l0[3]       | src_r0[0] << 24;
      dst1[0] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[1] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[2] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[3] = src_r0[3] >>  8;
      break;

    case 16:
      dst1[0] = src_r0[0];
      dst1[1] = src_r0[1];
      dst1[2] = src_r0[2];
      dst1[3] = src_r0[3];
      break;

    case 17:
      dst1[0] = src_l1[0]       | src_r0[0] <<  8;
      dst1[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      break;

    case 18:
      dst1[0] = src_l1[0]       | src_r0[0] << 16;
      dst1[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      break;

    case 19:
      dst1[0] = src_l1[0]       | src_r0[0] << 24;
      dst1[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      break;

    case 20:
      dst1[1] = src_r0[0];
      dst1[2] = src_r0[1];
      dst1[3] = src_r0[2];
      break;

    case 21:
      dst1[1] = src_l1[1]       | src_r0[0] <<  8;
      dst1[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      break;

    case 22:
      dst1[1] = src_l1[1]       | src_r0[0] << 16;
      dst1[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      break;

    case 23:
      dst1[1] = src_l1[1]       | src_r0[0] << 24;
      dst1[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      break;

    case 24:
      dst1[2] = src_r0[0];
      dst1[3] = src_r0[1];
      break;

    case 25:
      dst1[2] = src_l1[2]       | src_r0[0] <<  8;
      dst1[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      break;

    case 26:
      dst1[2] = src_l1[2]       | src_r0[0] << 16;
      dst1[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      break;

    case 27:
      dst1[2] = src_l1[2]       | src_r0[0] << 24;
      dst1[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      break;

    case 28:
      dst1[3] = src_r0[0];
      break;

    case 29:
      dst1[3] = src_l1[3]       | src_r0[0] <<  8;
      break;

    case 30:
      dst1[3] = src_l1[3]       | src_r0[0] << 16;
      break;

    case 31:
      dst1[3] = src_l1[3]       | src_r0[0] << 24;
      break;
  }
}

// before: device_memcat12L
static void memcat_c47_d3x4_sl3x4_sr1x4 (const u32 offset, u32 dst0[4], u32 dst1[4], u32 dst2[4], u32 src_l0[4], u32 src_l1[4], u32 src_l2[4], u32 src_r0[4])
{
  switch (offset)
  {
    case 1:
      dst0[0] = src_l0[0]       | src_r0[0] <<  8;
      dst0[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst0[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[0] = src_r0[3] >> 24;
      break;

    case 2:
      dst0[0] = src_l0[0]       | src_r0[0] << 16;
      dst0[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst0[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[0] = src_r0[3] >> 16;
      break;

    case 3:
      dst0[0] = src_l0[0]       | src_r0[0] << 24;
      dst0[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst0[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[0] = src_r0[3] >>  8;
      break;

    case 4:
      dst0[1] = src_r0[0];
      dst0[2] = src_r0[1];
      dst0[3] = src_r0[2];
      dst1[0] = src_r0[3];
      break;

    case 5:
      dst0[1] = src_l0[1]       | src_r0[0] <<  8;
      dst0[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[0] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[1] = src_r0[3] >> 24;
      break;

    case 6:
      dst0[1] = src_l0[1]       | src_r0[0] << 16;
      dst0[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[0] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[1] = src_r0[3] >> 16;
      break;

    case 7:
      dst0[1] = src_l0[1]       | src_r0[0] << 24;
      dst0[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[0] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[1] = src_r0[3] >>  8;
      break;

    case 8:
      dst0[2] = src_r0[0];
      dst0[3] = src_r0[1];
      dst1[0] = src_r0[2];
      dst1[1] = src_r0[3];
      break;

    case 9:
      dst0[2] = src_l0[2]       | src_r0[0] <<  8;
      dst0[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[0] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[1] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[2] = src_r0[3] >> 24;
      break;

    case 10:
      dst0[2] = src_l0[2]       | src_r0[0] << 16;
      dst0[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[0] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[1] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[2] = src_r0[3] >> 16;
      break;

    case 11:
      dst0[2] = src_l0[2]       | src_r0[0] << 24;
      dst0[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[0] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[1] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[2] = src_r0[3] >>  8;
      break;

    case 12:
      dst0[3] = src_r0[0];
      dst1[0] = src_r0[1];
      dst1[1] = src_r0[2];
      dst1[2] = src_r0[3];
      break;

    case 13:
      dst0[3] = src_l0[3]       | src_r0[0] <<  8;
      dst1[0] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[1] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[2] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[3] = src_r0[3] >> 24;
      break;

    case 14:
      dst0[3] = src_l0[3]       | src_r0[0] << 16;
      dst1[0] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[1] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[2] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[3] = src_r0[3] >> 16;
      break;

    case 15:
      dst0[3] = src_l0[3]       | src_r0[0] << 24;
      dst1[0] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[1] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[2] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[3] = src_r0[3] >>  8;
      break;

    case 16:
      dst1[0] = src_r0[0];
      dst1[1] = src_r0[1];
      dst1[2] = src_r0[2];
      dst1[3] = src_r0[3];
      break;

    case 17:
      dst1[0] = src_l1[0]       | src_r0[0] <<  8;
      dst1[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[0] = src_r0[3] >> 24;
      break;

    case 18:
      dst1[0] = src_l1[0]       | src_r0[0] << 16;
      dst1[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[0] = src_r0[3] >> 16;
      break;

    case 19:
      dst1[0] = src_l1[0]       | src_r0[0] << 24;
      dst1[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[0] = src_r0[3] >>  8;
      break;

    case 20:
      dst1[1] = src_r0[0];
      dst1[2] = src_r0[1];
      dst1[3] = src_r0[2];
      dst2[0] = src_r0[3];
      break;

    case 21:
      dst1[1] = src_l1[1]       | src_r0[0] <<  8;
      dst1[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[0] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[1] = src_r0[3] >> 24;
      break;

    case 22:
      dst1[1] = src_l1[1]       | src_r0[0] << 16;
      dst1[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[0] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[1] = src_r0[3] >> 16;
      break;

    case 23:
      dst1[1] = src_l1[1]       | src_r0[0] << 24;
      dst1[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[0] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[1] = src_r0[3] >>  8;
      break;

    case 24:
      dst1[2] = src_r0[0];
      dst1[3] = src_r0[1];
      dst2[0] = src_r0[2];
      dst2[1] = src_r0[3];
      break;

    case 25:
      dst1[2] = src_l1[2]       | src_r0[0] <<  8;
      dst1[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[0] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[1] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[2] = src_r0[3] >> 24;
      break;

    case 26:
      dst1[2] = src_l1[2]       | src_r0[0] << 16;
      dst1[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[0] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[1] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[2] = src_r0[3] >> 16;
      break;

    case 27:
      dst1[2] = src_l1[2]       | src_r0[0] << 24;
      dst1[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[0] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[1] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[2] = src_r0[3] >>  8;
      break;

    case 28:
      dst1[3] = src_r0[0];
      dst2[0] = src_r0[1];
      dst2[1] = src_r0[2];
      dst2[2] = src_r0[3];
      break;

    case 29:
      dst1[3] = src_l1[3]       | src_r0[0] <<  8;
      dst2[0] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[1] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[2] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[3] = src_r0[3] >> 24;
      break;

    case 30:
      dst1[3] = src_l1[3]       | src_r0[0] << 16;
      dst2[0] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[1] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[2] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[3] = src_r0[3] >> 16;
      break;

    case 31:
      dst1[3] = src_l1[3]       | src_r0[0] << 24;
      dst2[0] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[1] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[2] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[3] = src_r0[3] >>  8;
      break;

    case 32:
      dst2[0] = src_r0[0];
      dst2[1] = src_r0[1];
      dst2[2] = src_r0[2];
      dst2[3] = src_r0[3];
      break;

    case 33:
      dst2[0] = src_l2[0]       | src_r0[0] <<  8;
      dst2[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      break;

    case 34:
      dst2[0] = src_l2[0]       | src_r0[0] << 16;
      dst2[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      break;

    case 35:
      dst2[0] = src_l2[0]       | src_r0[0] << 24;
      dst2[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      break;

    case 36:
      dst2[1] = src_r0[0];
      dst2[2] = src_r0[1];
      dst2[3] = src_r0[2];
      break;

    case 37:
      dst2[1] = src_l2[1]       | src_r0[0] <<  8;
      dst2[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      break;

    case 38:
      dst2[1] = src_l2[1]       | src_r0[0] << 16;
      dst2[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      break;

    case 39:
      dst2[1] = src_l2[1]       | src_r0[0] << 24;
      dst2[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      break;

    case 40:
      dst2[2] = src_r0[0];
      dst2[3] = src_r0[1];
      break;

    case 41:
      dst2[2] = src_l2[2]       | src_r0[0] <<  8;
      dst2[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      break;

    case 42:
      dst2[2] = src_l2[2]       | src_r0[0] << 16;
      dst2[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      break;

    case 43:
      dst2[2] = src_l2[2]       | src_r0[0] << 24;
      dst2[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      break;

    case 44:
      dst2[3] = src_r0[0];
      break;

    case 45:
      dst2[3] = src_l2[3]       | src_r0[0] <<  8;
      break;

    case 46:
      dst2[3] = src_l2[3]       | src_r0[0] << 16;
      break;

    case 47:
      dst2[3] = src_l2[3]       | src_r0[0] << 24;
      break;
  }
}

// before: device_memcat12L
static void memcat_c47_d3x4_sl3x4_sr2x4 (const u32 offset, u32 dst0[4], u32 dst1[4], u32 dst2[4], u32 src_l0[4], u32 src_l1[4], u32 src_l2[4], u32 src_r0[4], u32 src_r1[4])
{
  switch (offset)
  {
    case 0:
      dst0[0] = src_r0[0];
      dst0[1] = src_r0[1];
      dst0[2] = src_r0[2];
      dst0[3] = src_r0[3];
      dst1[0] = src_r1[0];
      dst1[1] = src_r1[1];
      dst1[2] = src_r1[2];
      dst1[3] = src_r1[3];
      break;

    case 1:
      dst0[0] = src_l0[0]       | src_r0[0] <<  8;
      dst0[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst0[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[0] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst1[1] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst1[2] = src_r1[1] >> 24 | src_r1[2] <<  8;
      dst1[3] = src_r1[2] >> 24 | src_r1[3] <<  8;
      dst2[0] = src_r1[3] >> 24;
      break;

    case 2:
      dst0[0] = src_l0[0]       | src_r0[0] << 16;
      dst0[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst0[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[0] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst1[1] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst1[2] = src_r1[1] >> 16 | src_r1[2] << 16;
      dst1[3] = src_r1[2] >> 16 | src_r1[3] << 16;
      dst2[0] = src_r1[3] >> 16;
      break;

    case 3:
      dst0[0] = src_l0[0]       | src_r0[0] << 24;
      dst0[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst0[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[0] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst1[1] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst1[2] = src_r1[1] >>  8 | src_r1[2] << 24;
      dst1[3] = src_r1[2] >>  8 | src_r1[3] << 24;
      dst2[0] = src_r1[3] >>  8;
      break;

    case 4:
      dst0[1] = src_r0[0];
      dst0[2] = src_r0[1];
      dst0[3] = src_r0[2];
      dst1[0] = src_r0[3];
      dst1[1] = src_r1[0];
      dst1[2] = src_r1[1];
      dst1[3] = src_r1[2];
      dst2[0] = src_r1[3];
      break;

    case 5:
      dst0[1] = src_l0[1]       | src_r0[0] <<  8;
      dst0[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst0[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[0] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[1] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst1[2] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst1[3] = src_r1[1] >> 24 | src_r1[2] <<  8;
      dst2[0] = src_r1[2] >> 24 | src_r1[3] <<  8;
      dst2[1] = src_r1[3] >> 24;
      break;

    case 6:
      dst0[1] = src_l0[1]       | src_r0[0] << 16;
      dst0[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst0[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[0] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[1] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst1[2] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst1[3] = src_r1[1] >> 16 | src_r1[2] << 16;
      dst2[0] = src_r1[2] >> 16 | src_r1[3] << 16;
      dst2[1] = src_r1[3] >> 16;
      break;

    case 7:
      dst0[1] = src_l0[1]       | src_r0[0] << 24;
      dst0[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst0[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[0] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[1] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst1[2] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst1[3] = src_r1[1] >>  8 | src_r1[2] << 24;
      dst2[0] = src_r1[2] >>  8 | src_r1[3] << 24;
      dst2[1] = src_r1[3] >>  8;
      break;

    case 8:
      dst0[2] = src_r0[0];
      dst0[3] = src_r0[1];
      dst1[0] = src_r0[2];
      dst1[1] = src_r0[3];
      dst1[2] = src_r1[0];
      dst1[3] = src_r1[1];
      dst2[0] = src_r1[2];
      dst2[1] = src_r1[3];
      break;

    case 9:
      dst0[2] = src_l0[2]       | src_r0[0] <<  8;
      dst0[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[0] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[1] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[2] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst1[3] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst2[0] = src_r1[1] >> 24 | src_r1[2] <<  8;
      dst2[1] = src_r1[2] >> 24 | src_r1[3] <<  8;
      dst2[2] = src_r1[3] >> 24;
      break;

    case 10:
      dst0[2] = src_l0[2]       | src_r0[0] << 16;
      dst0[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[0] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[1] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[2] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst1[3] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst2[0] = src_r1[1] >> 16 | src_r1[2] << 16;
      dst2[1] = src_r1[2] >> 16 | src_r1[3] << 16;
      dst2[2] = src_r1[3] >> 16;
      break;

    case 11:
      dst0[2] = src_l0[2]       | src_r0[0] << 24;
      dst0[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[0] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[1] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[2] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst1[3] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst2[0] = src_r1[1] >>  8 | src_r1[2] << 24;
      dst2[1] = src_r1[2] >>  8 | src_r1[3] << 24;
      dst2[2] = src_r1[3] >>  8;
      break;

    case 12:
      dst0[3] = src_r0[0];
      dst1[0] = src_r0[1];
      dst1[1] = src_r0[2];
      dst1[2] = src_r0[3];
      dst1[3] = src_r1[0];
      dst2[0] = src_r1[1];
      dst2[1] = src_r1[2];
      dst2[2] = src_r1[3];
      break;

    case 13:
      dst0[3] = src_l0[3]       | src_r0[0] <<  8;
      dst1[0] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[1] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[2] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst1[3] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst2[0] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst2[1] = src_r1[1] >> 24 | src_r1[2] <<  8;
      dst2[2] = src_r1[2] >> 24 | src_r1[3] <<  8;
      dst2[3] = src_r1[3] >> 24;
      break;

    case 14:
      dst0[3] = src_l0[3]       | src_r0[0] << 16;
      dst1[0] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[1] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[2] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst1[3] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst2[0] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst2[1] = src_r1[1] >> 16 | src_r1[2] << 16;
      dst2[2] = src_r1[2] >> 16 | src_r1[3] << 16;
      dst2[3] = src_r1[3] >> 16;
      break;

    case 15:
      dst0[3] = src_l0[3]       | src_r0[0] << 24;
      dst1[0] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[1] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[2] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst1[3] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst2[0] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst2[1] = src_r1[1] >>  8 | src_r1[2] << 24;
      dst2[2] = src_r1[2] >>  8 | src_r1[3] << 24;
      dst2[3] = src_r1[3] >>  8;
      break;

    case 16:
      dst1[0] = src_r0[0];
      dst1[1] = src_r0[1];
      dst1[2] = src_r0[2];
      dst1[3] = src_r0[3];
      dst2[0] = src_r1[0];
      dst2[1] = src_r1[1];
      dst2[2] = src_r1[2];
      dst2[3] = src_r1[3];
      break;

    case 17:
      dst1[0] = src_l1[0]       | src_r0[0] <<  8;
      dst1[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst1[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[0] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst2[1] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst2[2] = src_r1[1] >> 24 | src_r1[2] <<  8;
      dst2[3] = src_r1[2] >> 24 | src_r1[3] <<  8;
      break;

    case 18:
      dst1[0] = src_l1[0]       | src_r0[0] << 16;
      dst1[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst1[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[0] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst2[1] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst2[2] = src_r1[1] >> 16 | src_r1[2] << 16;
      dst2[3] = src_r1[2] >> 16 | src_r1[3] << 16;
      break;

    case 19:
      dst1[0] = src_l1[0]       | src_r0[0] << 24;
      dst1[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst1[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[0] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst2[1] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst2[2] = src_r1[1] >>  8 | src_r1[2] << 24;
      dst2[3] = src_r1[2] >>  8 | src_r1[3] << 24;
      break;

    case 20:
      dst1[1] = src_r1[0];
      dst1[2] = src_r0[1];
      dst1[3] = src_r0[2];
      dst2[0] = src_r0[3];
      dst2[1] = src_r1[0];
      dst2[2] = src_r1[1];
      dst2[3] = src_r1[2];
      break;

    case 21:
      dst1[1] = src_l1[1]       | src_r0[0] <<  8;
      dst1[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst1[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[0] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[1] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst2[2] = src_r1[0] >> 24 | src_r1[1] <<  8;
      dst2[3] = src_r1[1] >> 24 | src_r1[2] <<  8;
      break;

    case 22:
      dst1[1] = src_l1[1]       | src_r0[0] << 16;
      dst1[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst1[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[0] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[1] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst2[2] = src_r1[0] >> 16 | src_r1[1] << 16;
      dst2[3] = src_r1[1] >> 16 | src_r1[2] << 16;
      break;

    case 23:
      dst1[1] = src_l1[1]       | src_r0[0] << 24;
      dst1[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst1[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[0] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[1] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst2[2] = src_r1[0] >>  8 | src_r1[1] << 24;
      dst2[3] = src_r1[1] >>  8 | src_r1[2] << 24;
      break;

    case 24:
      dst1[2] = src_r1[0];
      dst1[3] = src_r0[1];
      dst2[0] = src_r0[2];
      dst2[1] = src_r0[3];
      dst2[2] = src_r1[0];
      dst2[3] = src_r1[1];
      break;

    case 25:
      dst1[2] = src_l1[2]       | src_r0[0] <<  8;
      dst1[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[0] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[1] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[2] = src_r0[3] >> 24 | src_r1[0] <<  8;
      dst2[3] = src_r1[0] >> 24 | src_r1[1] <<  8;
      break;

    case 26:
      dst1[2] = src_l1[2]       | src_r0[0] << 16;
      dst1[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[0] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[1] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[2] = src_r0[3] >> 16 | src_r1[0] << 16;
      dst2[3] = src_r1[0] >> 16 | src_r1[1] << 16;
      break;

    case 27:
      dst1[2] = src_l1[2]       | src_r0[0] << 24;
      dst1[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[0] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[1] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[2] = src_r0[3] >>  8 | src_r1[0] << 24;
      dst2[3] = src_r1[0] >>  8 | src_r1[1] << 24;
      break;

    case 28:
      dst1[3] = src_r1[0];
      dst2[0] = src_r0[1];
      dst2[1] = src_r0[2];
      dst2[2] = src_r0[3];
      dst2[3] = src_r1[0];
      break;

    case 29:
      dst1[3] = src_l1[3]       | src_r0[0] <<  8;
      dst2[0] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[1] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[2] = src_r0[2] >> 24 | src_r0[3] <<  8;
      dst2[3] = src_r0[3] >> 24 | src_r1[0] <<  8;
      break;

    case 30:
      dst1[3] = src_l1[3]       | src_r0[0] << 16;
      dst2[0] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[1] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[2] = src_r0[2] >> 16 | src_r0[3] << 16;
      dst2[3] = src_r0[3] >> 16 | src_r1[0] << 16;
      break;

    case 31:
      dst1[3] = src_l1[3]       | src_r0[0] << 24;
      dst2[0] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[1] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[2] = src_r0[2] >>  8 | src_r0[3] << 24;
      dst2[3] = src_r0[3] >>  8 | src_r1[0] << 24;
      break;

    case 32:
      dst2[0] = src_r0[0];
      dst2[1] = src_r0[1];
      dst2[2] = src_r0[2];
      dst2[3] = src_r0[3];
      break;

    case 33:
      dst2[0] = src_l2[0]       | src_r0[0] <<  8;
      dst2[1] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[2] = src_r0[1] >> 24 | src_r0[2] <<  8;
      dst2[3] = src_r0[2] >> 24 | src_r0[3] <<  8;
      break;

    case 34:
      dst2[0] = src_l2[0]       | src_r0[0] << 16;
      dst2[1] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[2] = src_r0[1] >> 16 | src_r0[2] << 16;
      dst2[3] = src_r0[2] >> 16 | src_r0[3] << 16;
      break;

    case 35:
      dst2[0] = src_l2[0]       | src_r0[0] << 24;
      dst2[1] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[2] = src_r0[1] >>  8 | src_r0[2] << 24;
      dst2[3] = src_r0[2] >>  8 | src_r0[3] << 24;
      break;

    case 36:
      dst2[1] = src_r0[0];
      dst2[2] = src_r0[1];
      dst2[3] = src_r0[2];
      break;

    case 37:
      dst2[1] = src_l2[1]       | src_r0[0] <<  8;
      dst2[2] = src_r0[0] >> 24 | src_r0[1] <<  8;
      dst2[3] = src_r0[1] >> 24 | src_r0[2] <<  8;
      break;

    case 38:
      dst2[1] = src_l2[1]       | src_r0[0] << 16;
      dst2[2] = src_r0[0] >> 16 | src_r0[1] << 16;
      dst2[3] = src_r0[1] >> 16 | src_r0[2] << 16;
      break;

    case 39:
      dst2[1] = src_l2[1]       | src_r0[0] << 24;
      dst2[2] = src_r0[0] >>  8 | src_r0[1] << 24;
      dst2[3] = src_r0[1] >>  8 | src_r0[2] << 24;
      break;

    case 40:
      dst2[2] = src_r0[0];
      dst2[3] = src_r0[1];
      break;

    case 41:
      dst2[2] = src_l2[2]       | src_r0[0] <<  8;
      dst2[3] = src_r0[0] >> 24 | src_r0[1] <<  8;
      break;

    case 42:
      dst2[2] = src_l2[2]       | src_r0[0] << 16;
      dst2[3] = src_r0[0] >> 16 | src_r0[1] << 16;
      break;

    case 43:
      dst2[2] = src_l2[2]       | src_r0[0] << 24;
      dst2[3] = src_r0[0] >>  8 | src_r0[1] << 24;
      break;

    case 44:
      dst2[3] = src_r0[0];
      break;

    case 45:
      dst2[3] = src_l2[3]       | src_r0[0] <<  8;
      break;

    case 46:
      dst2[3] = src_l2[3]       | src_r0[0] << 16;
      break;

    case 47:
      dst2[3] = src_l2[3]       | src_r0[0] << 24;
      break;
  }
}

// before: memcat16_9
static void memcat_c15_w4x4_a3x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 append0[4], const u32 append1[4], const u32 append2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = append0[0];
      w0[1] = append0[1];
      w0[2] = append0[2];
      w0[3] = append0[3];
      w1[0] = append1[0];
      w1[1] = append1[1];
      w1[2] = append1[2];
      w1[3] = append1[3];
      w2[0] = append2[0];
      break;

    case 1:
      w0[0] = w0[0]            | append0[0] <<  8;
      w0[1] = append0[0] >> 24 | append0[1] <<  8;
      w0[2] = append0[1] >> 24 | append0[2] <<  8;
      w0[3] = append0[2] >> 24 | append0[3] <<  8;
      w1[0] = append0[3] >> 24 | append1[0] <<  8;
      w1[1] = append1[0] >> 24 | append1[1] <<  8;
      w1[2] = append1[1] >> 24 | append1[2] <<  8;
      w1[3] = append1[2] >> 24 | append1[3] <<  8;
      w2[0] = append1[3] >> 24 | append2[0] <<  8;
      w2[1] = append2[0] >> 24;
      break;

    case 2:
      w0[0] = w0[0]            | append0[0] << 16;
      w0[1] = append0[0] >> 16 | append0[1] << 16;
      w0[2] = append0[1] >> 16 | append0[2] << 16;
      w0[3] = append0[2] >> 16 | append0[3] << 16;
      w1[0] = append0[3] >> 16 | append1[0] << 16;
      w1[1] = append1[0] >> 16 | append1[1] << 16;
      w1[2] = append1[1] >> 16 | append1[2] << 16;
      w1[3] = append1[2] >> 16 | append1[3] << 16;
      w2[0] = append1[3] >> 16 | append2[0] << 16;
      w2[1] = append2[0] >> 16;
      break;

    case 3:
      w0[0] = w0[0]            | append0[0] << 24;
      w0[1] = append0[0] >>  8 | append0[1] << 24;
      w0[2] = append0[1] >>  8 | append0[2] << 24;
      w0[3] = append0[2] >>  8 | append0[3] << 24;
      w1[0] = append0[3] >>  8 | append1[0] << 24;
      w1[1] = append1[0] >>  8 | append1[1] << 24;
      w1[2] = append1[1] >>  8 | append1[2] << 24;
      w1[3] = append1[2] >>  8 | append1[3] << 24;
      w2[0] = append1[3] >>  8 | append2[0] << 24;
      w2[1] = append2[0] >>  8;
      break;

    case 4:
      w0[1] = append0[0];
      w0[2] = append0[1];
      w0[3] = append0[2];
      w1[0] = append0[3];
      w1[1] = append1[0];
      w1[2] = append1[1];
      w1[3] = append1[2];
      w2[0] = append1[3];
      w2[1] = append2[0];
      break;

    case 5:
      w0[1] = w0[1]            | append0[0] <<  8;
      w0[2] = append0[0] >> 24 | append0[1] <<  8;
      w0[3] = append0[1] >> 24 | append0[2] <<  8;
      w1[0] = append0[2] >> 24 | append0[3] <<  8;
      w1[1] = append0[3] >> 24 | append1[0] <<  8;
      w1[2] = append1[0] >> 24 | append1[1] <<  8;
      w1[3] = append1[1] >> 24 | append1[2] <<  8;
      w2[0] = append1[2] >> 24 | append1[3] <<  8;
      w2[1] = append1[3] >> 24 | append2[0] <<  8;
      w2[2] = append2[0] >> 24;
      break;

    case 6:
      w0[1] = w0[1]            | append0[0] << 16;
      w0[2] = append0[0] >> 16 | append0[1] << 16;
      w0[3] = append0[1] >> 16 | append0[2] << 16;
      w1[0] = append0[2] >> 16 | append0[3] << 16;
      w1[1] = append0[3] >> 16 | append1[0] << 16;
      w1[2] = append1[0] >> 16 | append1[1] << 16;
      w1[3] = append1[1] >> 16 | append1[2] << 16;
      w2[0] = append1[2] >> 16 | append1[3] << 16;
      w2[1] = append1[3] >> 16 | append2[0] << 16;
      w2[2] = append2[0] >> 16;
      break;

    case 7:
      w0[1] = w0[1]            | append0[0] << 24;
      w0[2] = append0[0] >>  8 | append0[1] << 24;
      w0[3] = append0[1] >>  8 | append0[2] << 24;
      w1[0] = append0[2] >>  8 | append0[3] << 24;
      w1[1] = append0[3] >>  8 | append1[0] << 24;
      w1[2] = append1[0] >>  8 | append1[1] << 24;
      w1[3] = append1[1] >>  8 | append1[2] << 24;
      w2[0] = append1[2] >>  8 | append1[3] << 24;
      w2[1] = append1[3] >>  8 | append2[0] << 24;
      w2[2] = append2[0] >>  8;
      break;

    case 8:
      w0[2] = append0[0];
      w0[3] = append0[1];
      w1[0] = append0[2];
      w1[1] = append0[3];
      w1[2] = append1[0];
      w1[3] = append1[1];
      w2[0] = append1[2];
      w2[1] = append1[3];
      w2[2] = append2[0];
      break;

    case 9:
      w0[2] = w0[2]            | append0[0] <<  8;
      w0[3] = append0[0] >> 24 | append0[1] <<  8;
      w1[0] = append0[1] >> 24 | append0[2] <<  8;
      w1[1] = append0[2] >> 24 | append0[3] <<  8;
      w1[2] = append0[3] >> 24 | append1[0] <<  8;
      w1[3] = append1[0] >> 24 | append1[1] <<  8;
      w2[0] = append1[1] >> 24 | append1[2] <<  8;
      w2[1] = append1[2] >> 24 | append1[3] <<  8;
      w2[2] = append1[3] >> 24 | append2[0] <<  8;
      w2[3] = append2[0] >> 24;
      break;

    case 10:
      w0[2] = w0[2]            | append0[0] << 16;
      w0[3] = append0[0] >> 16 | append0[1] << 16;
      w1[0] = append0[1] >> 16 | append0[2] << 16;
      w1[1] = append0[2] >> 16 | append0[3] << 16;
      w1[2] = append0[3] >> 16 | append1[0] << 16;
      w1[3] = append1[0] >> 16 | append1[1] << 16;
      w2[0] = append1[1] >> 16 | append1[2] << 16;
      w2[1] = append1[2] >> 16 | append1[3] << 16;
      w2[2] = append1[3] >> 16 | append2[0] << 16;
      w2[3] = append2[0] >> 16;
      break;

    case 11:
      w0[2] = w0[2]            | append0[0] << 24;
      w0[3] = append0[0] >>  8 | append0[1] << 24;
      w1[0] = append0[1] >>  8 | append0[2] << 24;
      w1[1] = append0[2] >>  8 | append0[3] << 24;
      w1[2] = append0[3] >>  8 | append1[0] << 24;
      w1[3] = append1[0] >>  8 | append1[1] << 24;
      w2[0] = append1[1] >>  8 | append1[2] << 24;
      w2[1] = append1[2] >>  8 | append1[3] << 24;
      w2[2] = append1[3] >>  8 | append2[0] << 24;
      w2[3] = append2[0] >>  8;
      break;

    case 12:
      w0[3] = append0[0];
      w1[0] = append0[1];
      w1[1] = append0[2];
      w1[2] = append0[3];
      w1[3] = append1[0];
      w2[0] = append1[1];
      w2[1] = append1[2];
      w2[2] = append1[3];
      w2[3] = append2[0];
      break;

    case 13:
      w0[3] = w0[3]            | append0[0] <<  8;
      w1[0] = append0[0] >> 24 | append0[1] <<  8;
      w1[1] = append0[1] >> 24 | append0[2] <<  8;
      w1[2] = append0[2] >> 24 | append0[3] <<  8;
      w1[3] = append0[3] >> 24 | append1[0] <<  8;
      w2[0] = append1[0] >> 24 | append1[1] <<  8;
      w2[1] = append1[1] >> 24 | append1[2] <<  8;
      w2[2] = append1[2] >> 24 | append1[3] <<  8;
      w2[3] = append1[3] >> 24 | append2[0] <<  8;
      w3[0] = append2[0] >> 24;
      break;

    case 14:
      w0[3] = w0[3]            | append0[0] << 16;
      w1[0] = append0[0] >> 16 | append0[1] << 16;
      w1[1] = append0[1] >> 16 | append0[2] << 16;
      w1[2] = append0[2] >> 16 | append0[3] << 16;
      w1[3] = append0[3] >> 16 | append1[0] << 16;
      w2[0] = append1[0] >> 16 | append1[1] << 16;
      w2[1] = append1[1] >> 16 | append1[2] << 16;
      w2[2] = append1[2] >> 16 | append1[3] << 16;
      w2[3] = append1[3] >> 16 | append2[0] << 16;
      w3[0] = append2[0] >> 16;
      break;

    case 15:
      w0[3] = w0[3]            | append0[0] << 24;
      w1[0] = append0[0] >>  8 | append0[1] << 24;
      w1[1] = append0[1] >>  8 | append0[2] << 24;
      w1[2] = append0[2] >>  8 | append0[3] << 24;
      w1[3] = append0[3] >>  8 | append1[0] << 24;
      w2[0] = append1[0] >>  8 | append1[1] << 24;
      w2[1] = append1[1] >>  8 | append1[2] << 24;
      w2[2] = append1[2] >>  8 | append1[3] << 24;
      w2[3] = append1[3] >>  8 | append2[0] << 24;
      w3[0] = append2[0] >>  8;
      break;
  }
}

// before: memcat32_8
static void memcat_c32_w4x4_a2x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 append0[4], const u32 append1[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = append0[0];
      w0[1] = append0[1];
      w0[2] = append0[2];
      w0[3] = append0[3];
      w1[0] = append1[0];
      w1[1] = append1[1];
      w1[2] = append1[2];
      w1[3] = append1[3];
      break;

    case 1:
      w0[0] = w0[0]            | append0[0] <<  8;
      w0[1] = append0[0] >> 24 | append0[1] <<  8;
      w0[2] = append0[1] >> 24 | append0[2] <<  8;
      w0[3] = append0[2] >> 24 | append0[3] <<  8;
      w1[0] = append0[3] >> 24 | append1[0] <<  8;
      w1[1] = append1[0] >> 24 | append1[1] <<  8;
      w1[2] = append1[1] >> 24 | append1[2] <<  8;
      w1[3] = append1[2] >> 24 | append1[3] <<  8;
      w2[0] = append1[3] >> 24;
      break;

    case 2:
      w0[0] = w0[0]            | append0[0] << 16;
      w0[1] = append0[0] >> 16 | append0[1] << 16;
      w0[2] = append0[1] >> 16 | append0[2] << 16;
      w0[3] = append0[2] >> 16 | append0[3] << 16;
      w1[0] = append0[3] >> 16 | append1[0] << 16;
      w1[1] = append1[0] >> 16 | append1[1] << 16;
      w1[2] = append1[1] >> 16 | append1[2] << 16;
      w1[3] = append1[2] >> 16 | append1[3] << 16;
      w2[0] = append1[3] >> 16;
      break;

    case 3:
      w0[0] = w0[0]            | append0[0] << 24;
      w0[1] = append0[0] >>  8 | append0[1] << 24;
      w0[2] = append0[1] >>  8 | append0[2] << 24;
      w0[3] = append0[2] >>  8 | append0[3] << 24;
      w1[0] = append0[3] >>  8 | append1[0] << 24;
      w1[1] = append1[0] >>  8 | append1[1] << 24;
      w1[2] = append1[1] >>  8 | append1[2] << 24;
      w1[3] = append1[2] >>  8 | append1[3] << 24;
      w2[0] = append1[3] >>  8;
      break;

    case 4:
      w0[1] = append0[0];
      w0[2] = append0[1];
      w0[3] = append0[2];
      w1[0] = append0[3];
      w1[1] = append1[0];
      w1[2] = append1[1];
      w1[3] = append1[2];
      w2[0] = append1[3];
      break;

    case 5:
      w0[1] = w0[1]            | append0[0] <<  8;
      w0[2] = append0[0] >> 24 | append0[1] <<  8;
      w0[3] = append0[1] >> 24 | append0[2] <<  8;
      w1[0] = append0[2] >> 24 | append0[3] <<  8;
      w1[1] = append0[3] >> 24 | append1[0] <<  8;
      w1[2] = append1[0] >> 24 | append1[1] <<  8;
      w1[3] = append1[1] >> 24 | append1[2] <<  8;
      w2[0] = append1[2] >> 24 | append1[3] <<  8;
      w2[1] = append1[3] >> 24;
      break;

    case 6:
      w0[1] = w0[1]            | append0[0] << 16;
      w0[2] = append0[0] >> 16 | append0[1] << 16;
      w0[3] = append0[1] >> 16 | append0[2] << 16;
      w1[0] = append0[2] >> 16 | append0[3] << 16;
      w1[1] = append0[3] >> 16 | append1[0] << 16;
      w1[2] = append1[0] >> 16 | append1[1] << 16;
      w1[3] = append1[1] >> 16 | append1[2] << 16;
      w2[0] = append1[2] >> 16 | append1[3] << 16;
      w2[1] = append1[3] >> 16;
      break;

    case 7:
      w0[1] = w0[1]            | append0[0] << 24;
      w0[2] = append0[0] >>  8 | append0[1] << 24;
      w0[3] = append0[1] >>  8 | append0[2] << 24;
      w1[0] = append0[2] >>  8 | append0[3] << 24;
      w1[1] = append0[3] >>  8 | append1[0] << 24;
      w1[2] = append1[0] >>  8 | append1[1] << 24;
      w1[3] = append1[1] >>  8 | append1[2] << 24;
      w2[0] = append1[2] >>  8 | append1[3] << 24;
      w2[1] = append1[3] >>  8;
      break;

    case 8:
      w0[2] = append0[0];
      w0[3] = append0[1];
      w1[0] = append0[2];
      w1[1] = append0[3];
      w1[2] = append1[0];
      w1[3] = append1[1];
      w2[0] = append1[2];
      w2[1] = append1[3];
      break;

    case 9:
      w0[2] = w0[2]            | append0[0] <<  8;
      w0[3] = append0[0] >> 24 | append0[1] <<  8;
      w1[0] = append0[1] >> 24 | append0[2] <<  8;
      w1[1] = append0[2] >> 24 | append0[3] <<  8;
      w1[2] = append0[3] >> 24 | append1[0] <<  8;
      w1[3] = append1[0] >> 24 | append1[1] <<  8;
      w2[0] = append1[1] >> 24 | append1[2] <<  8;
      w2[1] = append1[2] >> 24 | append1[3] <<  8;
      w2[2] = append1[3] >> 24;
      break;

    case 10:
      w0[2] = w0[2]            | append0[0] << 16;
      w0[3] = append0[0] >> 16 | append0[1] << 16;
      w1[0] = append0[1] >> 16 | append0[2] << 16;
      w1[1] = append0[2] >> 16 | append0[3] << 16;
      w1[2] = append0[3] >> 16 | append1[0] << 16;
      w1[3] = append1[0] >> 16 | append1[1] << 16;
      w2[0] = append1[1] >> 16 | append1[2] << 16;
      w2[1] = append1[2] >> 16 | append1[3] << 16;
      w2[2] = append1[3] >> 16;
      break;

    case 11:
      w0[2] = w0[2]            | append0[0] << 24;
      w0[3] = append0[0] >>  8 | append0[1] << 24;
      w1[0] = append0[1] >>  8 | append0[2] << 24;
      w1[1] = append0[2] >>  8 | append0[3] << 24;
      w1[2] = append0[3] >>  8 | append1[0] << 24;
      w1[3] = append1[0] >>  8 | append1[1] << 24;
      w2[0] = append1[1] >>  8 | append1[2] << 24;
      w2[1] = append1[2] >>  8 | append1[3] << 24;
      w2[2] = append1[3] >>  8;
      break;

    case 12:
      w0[3] = append0[0];
      w1[0] = append0[1];
      w1[1] = append0[2];
      w1[2] = append0[3];
      w1[3] = append1[0];
      w2[0] = append1[1];
      w2[1] = append1[2];
      w2[2] = append1[3];
      break;

    case 13:
      w0[3] = w0[3]            | append0[0] <<  8;
      w1[0] = append0[0] >> 24 | append0[1] <<  8;
      w1[1] = append0[1] >> 24 | append0[2] <<  8;
      w1[2] = append0[2] >> 24 | append0[3] <<  8;
      w1[3] = append0[3] >> 24 | append1[0] <<  8;
      w2[0] = append1[0] >> 24 | append1[1] <<  8;
      w2[1] = append1[1] >> 24 | append1[2] <<  8;
      w2[2] = append1[2] >> 24 | append1[3] <<  8;
      w2[3] = append1[3] >> 24;
      break;

    case 14:
      w0[3] = w0[3]            | append0[0] << 16;
      w1[0] = append0[0] >> 16 | append0[1] << 16;
      w1[1] = append0[1] >> 16 | append0[2] << 16;
      w1[2] = append0[2] >> 16 | append0[3] << 16;
      w1[3] = append0[3] >> 16 | append1[0] << 16;
      w2[0] = append1[0] >> 16 | append1[1] << 16;
      w2[1] = append1[1] >> 16 | append1[2] << 16;
      w2[2] = append1[2] >> 16 | append1[3] << 16;
      w2[3] = append1[3] >> 16;
      break;

    case 15:
      w0[3] = w0[3]            | append0[0] << 24;
      w1[0] = append0[0] >>  8 | append0[1] << 24;
      w1[1] = append0[1] >>  8 | append0[2] << 24;
      w1[2] = append0[2] >>  8 | append0[3] << 24;
      w1[3] = append0[3] >>  8 | append1[0] << 24;
      w2[0] = append1[0] >>  8 | append1[1] << 24;
      w2[1] = append1[1] >>  8 | append1[2] << 24;
      w2[2] = append1[2] >>  8 | append1[3] << 24;
      w2[3] = append1[3] >>  8;
      break;

    case 16:
      w1[0] = append0[0];
      w1[1] = append0[1];
      w1[2] = append0[2];
      w1[3] = append0[3];
      w2[0] = append1[0];
      w2[1] = append1[1];
      w2[2] = append1[2];
      w2[3] = append1[3];
      break;

    case 17:
      w1[0] = w1[0]            | append0[0] <<  8;
      w1[1] = append0[0] >> 24 | append0[1] <<  8;
      w1[2] = append0[1] >> 24 | append0[2] <<  8;
      w1[3] = append0[2] >> 24 | append0[3] <<  8;
      w2[0] = append0[3] >> 24 | append1[0] <<  8;
      w2[1] = append1[0] >> 24 | append1[1] <<  8;
      w2[2] = append1[1] >> 24 | append1[2] <<  8;
      w2[3] = append1[2] >> 24 | append1[3] <<  8;
      w3[0] = append1[3] >> 24;
      break;

    case 18:
      w1[0] = w1[0]            | append0[0] << 16;
      w1[1] = append0[0] >> 16 | append0[1] << 16;
      w1[2] = append0[1] >> 16 | append0[2] << 16;
      w1[3] = append0[2] >> 16 | append0[3] << 16;
      w2[0] = append0[3] >> 16 | append1[0] << 16;
      w2[1] = append1[0] >> 16 | append1[1] << 16;
      w2[2] = append1[1] >> 16 | append1[2] << 16;
      w2[3] = append1[2] >> 16 | append1[3] << 16;
      w3[0] = append1[3] >> 16;
      break;

    case 19:
      w1[0] = w1[0]            | append0[0] << 24;
      w1[1] = append0[0] >>  8 | append0[1] << 24;
      w1[2] = append0[1] >>  8 | append0[2] << 24;
      w1[3] = append0[2] >>  8 | append0[3] << 24;
      w2[0] = append0[3] >>  8 | append1[0] << 24;
      w2[1] = append1[0] >>  8 | append1[1] << 24;
      w2[2] = append1[1] >>  8 | append1[2] << 24;
      w2[3] = append1[2] >>  8 | append1[3] << 24;
      w3[0] = append1[3] >>  8;
      break;

    case 20:
      w1[1] = append0[0];
      w1[2] = append0[1];
      w1[3] = append0[2];
      w2[0] = append0[3];
      w2[1] = append1[0];
      w2[2] = append1[1];
      w2[3] = append1[2];
      w3[0] = append1[3];
      break;

    case 21:
      w1[1] = w1[1]            | append0[0] <<  8;
      w1[2] = append0[0] >> 24 | append0[1] <<  8;
      w1[3] = append0[1] >> 24 | append0[2] <<  8;
      w2[0] = append0[2] >> 24 | append0[3] <<  8;
      w2[1] = append0[3] >> 24 | append1[0] <<  8;
      w2[2] = append1[0] >> 24 | append1[1] <<  8;
      w2[3] = append1[1] >> 24 | append1[2] <<  8;
      w3[0] = append1[2] >> 24 | append1[3] <<  8;
      w3[1] = append1[3] >> 24;
      break;

    case 22:
      w1[1] = w1[1]            | append0[0] << 16;
      w1[2] = append0[0] >> 16 | append0[1] << 16;
      w1[3] = append0[1] >> 16 | append0[2] << 16;
      w2[0] = append0[2] >> 16 | append0[3] << 16;
      w2[1] = append0[3] >> 16 | append1[0] << 16;
      w2[2] = append1[0] >> 16 | append1[1] << 16;
      w2[3] = append1[1] >> 16 | append1[2] << 16;
      w3[0] = append1[2] >> 16 | append1[3] << 16;
      w3[1] = append1[3] >> 16;
      break;

    case 23:
      w1[1] = w1[1]            | append0[0] << 24;
      w1[2] = append0[0] >>  8 | append0[1] << 24;
      w1[3] = append0[1] >>  8 | append0[2] << 24;
      w2[0] = append0[2] >>  8 | append0[3] << 24;
      w2[1] = append0[3] >>  8 | append1[0] << 24;
      w2[2] = append1[0] >>  8 | append1[1] << 24;
      w2[3] = append1[1] >>  8 | append1[2] << 24;
      w3[0] = append1[2] >>  8 | append1[3] << 24;
      w3[1] = append1[3] >>  8;
      break;

    case 24:
      w1[2] = append0[0];
      w1[3] = append0[1];
      w2[0] = append0[2];
      w2[1] = append0[3];
      w2[2] = append1[0];
      w2[3] = append1[1];
      w3[0] = append1[2];
      w3[1] = append1[3];
      break;

    case 25:
      w1[2] = w1[2]            | append0[0] <<  8;
      w1[3] = append0[0] >> 24 | append0[1] <<  8;
      w2[0] = append0[1] >> 24 | append0[2] <<  8;
      w2[1] = append0[2] >> 24 | append0[3] <<  8;
      w2[2] = append0[3] >> 24 | append1[0] <<  8;
      w2[3] = append1[0] >> 24 | append1[1] <<  8;
      w3[0] = append1[1] >> 24 | append1[2] <<  8;
      w3[1] = append1[2] >> 24 | append1[3] <<  8;
      break;

    case 26:
      w1[2] = w1[2]            | append0[0] << 16;
      w1[3] = append0[0] >> 16 | append0[1] << 16;
      w2[0] = append0[1] >> 16 | append0[2] << 16;
      w2[1] = append0[2] >> 16 | append0[3] << 16;
      w2[2] = append0[3] >> 16 | append1[0] << 16;
      w2[3] = append1[0] >> 16 | append1[1] << 16;
      w3[0] = append1[1] >> 16 | append1[2] << 16;
      w3[1] = append1[2] >> 16 | append1[3] << 16;
      break;

    case 27:
      w1[2] = w1[2]            | append0[0] << 24;
      w1[3] = append0[0] >>  8 | append0[1] << 24;
      w2[0] = append0[1] >>  8 | append0[2] << 24;
      w2[1] = append0[2] >>  8 | append0[3] << 24;
      w2[2] = append0[3] >>  8 | append1[0] << 24;
      w2[3] = append1[0] >>  8 | append1[1] << 24;
      w3[0] = append1[1] >>  8 | append1[2] << 24;
      w3[1] = append1[2] >>  8 | append1[3] << 24;
      break;

    case 28:
      w1[3] = append0[0];
      w2[0] = append0[1];
      w2[1] = append0[2];
      w2[2] = append0[3];
      w2[3] = append1[0];
      w3[0] = append1[1];
      w3[1] = append1[2];
      break;

    case 29:
      w1[3] = w1[3]            | append0[0] <<  8;
      w2[0] = append0[0] >> 24 | append0[1] <<  8;
      w2[1] = append0[1] >> 24 | append0[2] <<  8;
      w2[2] = append0[2] >> 24 | append0[3] <<  8;
      w2[3] = append0[3] >> 24 | append1[0] <<  8;
      w3[0] = append1[0] >> 24 | append1[1] <<  8;
      w3[1] = append1[1] >> 24 | append1[2] <<  8;
      break;

    case 30:
      w1[3] = w1[3]            | append0[0] << 16;
      w2[0] = append0[0] >> 16 | append0[1] << 16;
      w2[1] = append0[1] >> 16 | append0[2] << 16;
      w2[2] = append0[2] >> 16 | append0[3] << 16;
      w2[3] = append0[3] >> 16 | append1[0] << 16;
      w3[0] = append1[0] >> 16 | append1[1] << 16;
      w3[1] = append1[1] >> 16 | append1[2] << 16;
      break;

    case 31:
      w1[3] = w1[3]            | append0[0] << 24;
      w2[0] = append0[0] >>  8 | append0[1] << 24;
      w2[1] = append0[1] >>  8 | append0[2] << 24;
      w2[2] = append0[2] >>  8 | append0[3] << 24;
      w2[3] = append0[3] >>  8 | append1[0] << 24;
      w3[0] = append1[0] >>  8 | append1[1] << 24;
      w3[1] = append1[1] >>  8 | append1[2] << 24;
      break;

    case 32:
      w2[0] = append0[0];
      w2[1] = append0[1];
      w2[2] = append0[2];
      w2[3] = append0[3];
      w3[0] = append1[0];
      w3[1] = append1[1];
      break;
  }
}

// before: memcat32_9
static void memcat_c32_w4x4_a3x4 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 append0[4], const u32 append1[4], const u32 append2[4], const u32 offset)
{
  switch (offset)
  {
    case 0:
      w0[0] = append0[0];
      w0[1] = append0[1];
      w0[2] = append0[2];
      w0[3] = append0[3];
      w1[0] = append1[0];
      w1[1] = append1[1];
      w1[2] = append1[2];
      w1[3] = append1[3];
      w2[0] = append2[0];
      break;

    case 1:
      w0[0] = w0[0]            | append0[0] <<  8;
      w0[1] = append0[0] >> 24 | append0[1] <<  8;
      w0[2] = append0[1] >> 24 | append0[2] <<  8;
      w0[3] = append0[2] >> 24 | append0[3] <<  8;
      w1[0] = append0[3] >> 24 | append1[0] <<  8;
      w1[1] = append1[0] >> 24 | append1[1] <<  8;
      w1[2] = append1[1] >> 24 | append1[2] <<  8;
      w1[3] = append1[2] >> 24 | append1[3] <<  8;
      w2[0] = append1[3] >> 24 | append2[0] <<  8;
      w2[1] = append2[0] >> 24;
      break;

    case 2:
      w0[0] = w0[0]            | append0[0] << 16;
      w0[1] = append0[0] >> 16 | append0[1] << 16;
      w0[2] = append0[1] >> 16 | append0[2] << 16;
      w0[3] = append0[2] >> 16 | append0[3] << 16;
      w1[0] = append0[3] >> 16 | append1[0] << 16;
      w1[1] = append1[0] >> 16 | append1[1] << 16;
      w1[2] = append1[1] >> 16 | append1[2] << 16;
      w1[3] = append1[2] >> 16 | append1[3] << 16;
      w2[0] = append1[3] >> 16 | append2[0] << 16;
      w2[1] = append2[0] >> 16;
      break;

    case 3:
      w0[0] = w0[0]            | append0[0] << 24;
      w0[1] = append0[0] >>  8 | append0[1] << 24;
      w0[2] = append0[1] >>  8 | append0[2] << 24;
      w0[3] = append0[2] >>  8 | append0[3] << 24;
      w1[0] = append0[3] >>  8 | append1[0] << 24;
      w1[1] = append1[0] >>  8 | append1[1] << 24;
      w1[2] = append1[1] >>  8 | append1[2] << 24;
      w1[3] = append1[2] >>  8 | append1[3] << 24;
      w2[0] = append1[3] >>  8 | append2[0] << 24;
      w2[1] = append2[0] >>  8;
      break;

    case 4:
      w0[1] = append0[0];
      w0[2] = append0[1];
      w0[3] = append0[2];
      w1[0] = append0[3];
      w1[1] = append1[0];
      w1[2] = append1[1];
      w1[3] = append1[2];
      w2[0] = append1[3];
      w2[1] = append2[0];
      break;

    case 5:
      w0[1] = w0[1]            | append0[0] <<  8;
      w0[2] = append0[0] >> 24 | append0[1] <<  8;
      w0[3] = append0[1] >> 24 | append0[2] <<  8;
      w1[0] = append0[2] >> 24 | append0[3] <<  8;
      w1[1] = append0[3] >> 24 | append1[0] <<  8;
      w1[2] = append1[0] >> 24 | append1[1] <<  8;
      w1[3] = append1[1] >> 24 | append1[2] <<  8;
      w2[0] = append1[2] >> 24 | append1[3] <<  8;
      w2[1] = append1[3] >> 24 | append2[0] <<  8;
      w2[2] = append2[0] >> 24;
      break;

    case 6:
      w0[1] = w0[1]            | append0[0] << 16;
      w0[2] = append0[0] >> 16 | append0[1] << 16;
      w0[3] = append0[1] >> 16 | append0[2] << 16;
      w1[0] = append0[2] >> 16 | append0[3] << 16;
      w1[1] = append0[3] >> 16 | append1[0] << 16;
      w1[2] = append1[0] >> 16 | append1[1] << 16;
      w1[3] = append1[1] >> 16 | append1[2] << 16;
      w2[0] = append1[2] >> 16 | append1[3] << 16;
      w2[1] = append1[3] >> 16 | append2[0] << 16;
      w2[2] = append2[0] >> 16;
      break;

    case 7:
      w0[1] = w0[1]            | append0[0] << 24;
      w0[2] = append0[0] >>  8 | append0[1] << 24;
      w0[3] = append0[1] >>  8 | append0[2] << 24;
      w1[0] = append0[2] >>  8 | append0[3] << 24;
      w1[1] = append0[3] >>  8 | append1[0] << 24;
      w1[2] = append1[0] >>  8 | append1[1] << 24;
      w1[3] = append1[1] >>  8 | append1[2] << 24;
      w2[0] = append1[2] >>  8 | append1[3] << 24;
      w2[1] = append1[3] >>  8 | append2[0] << 24;
      w2[2] = append2[0] >>  8;
      break;

    case 8:
      w0[2] = append0[0];
      w0[3] = append0[1];
      w1[0] = append0[2];
      w1[1] = append0[3];
      w1[2] = append1[0];
      w1[3] = append1[1];
      w2[0] = append1[2];
      w2[1] = append1[3];
      w2[2] = append2[0];
      break;

    case 9:
      w0[2] = w0[2]            | append0[0] <<  8;
      w0[3] = append0[0] >> 24 | append0[1] <<  8;
      w1[0] = append0[1] >> 24 | append0[2] <<  8;
      w1[1] = append0[2] >> 24 | append0[3] <<  8;
      w1[2] = append0[3] >> 24 | append1[0] <<  8;
      w1[3] = append1[0] >> 24 | append1[1] <<  8;
      w2[0] = append1[1] >> 24 | append1[2] <<  8;
      w2[1] = append1[2] >> 24 | append1[3] <<  8;
      w2[2] = append1[3] >> 24 | append2[0] <<  8;
      w2[3] = append2[0] >> 24;
      break;

    case 10:
      w0[2] = w0[2]            | append0[0] << 16;
      w0[3] = append0[0] >> 16 | append0[1] << 16;
      w1[0] = append0[1] >> 16 | append0[2] << 16;
      w1[1] = append0[2] >> 16 | append0[3] << 16;
      w1[2] = append0[3] >> 16 | append1[0] << 16;
      w1[3] = append1[0] >> 16 | append1[1] << 16;
      w2[0] = append1[1] >> 16 | append1[2] << 16;
      w2[1] = append1[2] >> 16 | append1[3] << 16;
      w2[2] = append1[3] >> 16 | append2[0] << 16;
      w2[3] = append2[0] >> 16;
      break;

    case 11:
      w0[2] = w0[2]            | append0[0] << 24;
      w0[3] = append0[0] >>  8 | append0[1] << 24;
      w1[0] = append0[1] >>  8 | append0[2] << 24;
      w1[1] = append0[2] >>  8 | append0[3] << 24;
      w1[2] = append0[3] >>  8 | append1[0] << 24;
      w1[3] = append1[0] >>  8 | append1[1] << 24;
      w2[0] = append1[1] >>  8 | append1[2] << 24;
      w2[1] = append1[2] >>  8 | append1[3] << 24;
      w2[2] = append1[3] >>  8 | append2[0] << 24;
      w2[3] = append2[0] >>  8;
      break;

    case 12:
      w0[3] = append0[0];
      w1[0] = append0[1];
      w1[1] = append0[2];
      w1[2] = append0[3];
      w1[3] = append1[0];
      w2[0] = append1[1];
      w2[1] = append1[2];
      w2[2] = append1[3];
      w2[3] = append2[0];
      break;

    case 13:
      w0[3] = w0[3]            | append0[0] <<  8;
      w1[0] = append0[0] >> 24 | append0[1] <<  8;
      w1[1] = append0[1] >> 24 | append0[2] <<  8;
      w1[2] = append0[2] >> 24 | append0[3] <<  8;
      w1[3] = append0[3] >> 24 | append1[0] <<  8;
      w2[0] = append1[0] >> 24 | append1[1] <<  8;
      w2[1] = append1[1] >> 24 | append1[2] <<  8;
      w2[2] = append1[2] >> 24 | append1[3] <<  8;
      w2[3] = append1[3] >> 24 | append2[0] <<  8;
      w3[0] = append2[0] >> 24;
      break;

    case 14:
      w0[3] = w0[3]            | append0[0] << 16;
      w1[0] = append0[0] >> 16 | append0[1] << 16;
      w1[1] = append0[1] >> 16 | append0[2] << 16;
      w1[2] = append0[2] >> 16 | append0[3] << 16;
      w1[3] = append0[3] >> 16 | append1[0] << 16;
      w2[0] = append1[0] >> 16 | append1[1] << 16;
      w2[1] = append1[1] >> 16 | append1[2] << 16;
      w2[2] = append1[2] >> 16 | append1[3] << 16;
      w2[3] = append1[3] >> 16 | append2[0] << 16;
      w3[0] = append2[0] >> 16;
      break;

    case 15:
      w0[3] = w0[3]            | append0[0] << 24;
      w1[0] = append0[0] >>  8 | append0[1] << 24;
      w1[1] = append0[1] >>  8 | append0[2] << 24;
      w1[2] = append0[2] >>  8 | append0[3] << 24;
      w1[3] = append0[3] >>  8 | append1[0] << 24;
      w2[0] = append1[0] >>  8 | append1[1] << 24;
      w2[1] = append1[1] >>  8 | append1[2] << 24;
      w2[2] = append1[2] >>  8 | append1[3] << 24;
      w2[3] = append1[3] >>  8 | append2[0] << 24;
      w3[0] = append2[0] >>  8;
      break;

    case 16:
      w1[0] = append0[0];
      w1[1] = append0[1];
      w1[2] = append0[2];
      w1[3] = append0[3];
      w2[0] = append1[0];
      w2[1] = append1[1];
      w2[2] = append1[2];
      w2[3] = append1[3];
      w3[0] = append2[0];
      break;

    case 17:
      w1[0] = w1[0]            | append0[0] <<  8;
      w1[1] = append0[0] >> 24 | append0[1] <<  8;
      w1[2] = append0[1] >> 24 | append0[2] <<  8;
      w1[3] = append0[2] >> 24 | append0[3] <<  8;
      w2[0] = append0[3] >> 24 | append1[0] <<  8;
      w2[1] = append1[0] >> 24 | append1[1] <<  8;
      w2[2] = append1[1] >> 24 | append1[2] <<  8;
      w2[3] = append1[2] >> 24 | append1[3] <<  8;
      w3[0] = append1[3] >> 24 | append2[0] <<  8;
      w3[1] = append2[0] >> 24;
      break;

    case 18:
      w1[0] = w1[0]            | append0[0] << 16;
      w1[1] = append0[0] >> 16 | append0[1] << 16;
      w1[2] = append0[1] >> 16 | append0[2] << 16;
      w1[3] = append0[2] >> 16 | append0[3] << 16;
      w2[0] = append0[3] >> 16 | append1[0] << 16;
      w2[1] = append1[0] >> 16 | append1[1] << 16;
      w2[2] = append1[1] >> 16 | append1[2] << 16;
      w2[3] = append1[2] >> 16 | append1[3] << 16;
      w3[0] = append1[3] >> 16 | append2[0] << 16;
      w3[1] = append2[0] >> 16;
      break;

    case 19:
      w1[0] = w1[0]            | append0[0] << 24;
      w1[1] = append0[0] >>  8 | append0[1] << 24;
      w1[2] = append0[1] >>  8 | append0[2] << 24;
      w1[3] = append0[2] >>  8 | append0[3] << 24;
      w2[0] = append0[3] >>  8 | append1[0] << 24;
      w2[1] = append1[0] >>  8 | append1[1] << 24;
      w2[2] = append1[1] >>  8 | append1[2] << 24;
      w2[3] = append1[2] >>  8 | append1[3] << 24;
      w3[0] = append1[3] >>  8 | append2[0] << 24;
      w3[1] = append2[0] >>  8;
      break;

    case 20:
      w1[1] = append0[0];
      w1[2] = append0[1];
      w1[3] = append0[2];
      w2[0] = append0[3];
      w2[1] = append1[0];
      w2[2] = append1[1];
      w2[3] = append1[2];
      w3[0] = append1[3];
      w3[1] = append2[0];
      break;

    case 21:
      w1[1] = w1[1]            | append0[0] <<  8;
      w1[2] = append0[0] >> 24 | append0[1] <<  8;
      w1[3] = append0[1] >> 24 | append0[2] <<  8;
      w2[0] = append0[2] >> 24 | append0[3] <<  8;
      w2[1] = append0[3] >> 24 | append1[0] <<  8;
      w2[2] = append1[0] >> 24 | append1[1] <<  8;
      w2[3] = append1[1] >> 24 | append1[2] <<  8;
      w3[0] = append1[2] >> 24 | append1[3] <<  8;
      w3[1] = append1[3] >> 24 | append2[0] <<  8;
      break;

    case 22:
      w1[1] = w1[1]            | append0[0] << 16;
      w1[2] = append0[0] >> 16 | append0[1] << 16;
      w1[3] = append0[1] >> 16 | append0[2] << 16;
      w2[0] = append0[2] >> 16 | append0[3] << 16;
      w2[1] = append0[3] >> 16 | append1[0] << 16;
      w2[2] = append1[0] >> 16 | append1[1] << 16;
      w2[3] = append1[1] >> 16 | append1[2] << 16;
      w3[0] = append1[2] >> 16 | append1[3] << 16;
      w3[1] = append1[3] >> 16 | append2[0] << 16;
      break;

    case 23:
      w1[1] = w1[1]            | append0[0] << 24;
      w1[2] = append0[0] >>  8 | append0[1] << 24;
      w1[3] = append0[1] >>  8 | append0[2] << 24;
      w2[0] = append0[2] >>  8 | append0[3] << 24;
      w2[1] = append0[3] >>  8 | append1[0] << 24;
      w2[2] = append1[0] >>  8 | append1[1] << 24;
      w2[3] = append1[1] >>  8 | append1[2] << 24;
      w3[0] = append1[2] >>  8 | append1[3] << 24;
      w3[1] = append1[3] >>  8 | append2[0] << 24;
      break;

    case 24:
      w1[2] = append0[0];
      w1[3] = append0[1];
      w2[0] = append0[2];
      w2[1] = append0[3];
      w2[2] = append1[0];
      w2[3] = append1[1];
      w3[0] = append1[2];
      w3[1] = append1[3];
      break;

    case 25:
      w1[2] = w1[2]            | append0[0] <<  8;
      w1[3] = append0[0] >> 24 | append0[1] <<  8;
      w2[0] = append0[1] >> 24 | append0[2] <<  8;
      w2[1] = append0[2] >> 24 | append0[3] <<  8;
      w2[2] = append0[3] >> 24 | append1[0] <<  8;
      w2[3] = append1[0] >> 24 | append1[1] <<  8;
      w3[0] = append1[1] >> 24 | append1[2] <<  8;
      w3[1] = append1[2] >> 24 | append1[3] <<  8;
      break;

    case 26:
      w1[2] = w1[2]            | append0[0] << 16;
      w1[3] = append0[0] >> 16 | append0[1] << 16;
      w2[0] = append0[1] >> 16 | append0[2] << 16;
      w2[1] = append0[2] >> 16 | append0[3] << 16;
      w2[2] = append0[3] >> 16 | append1[0] << 16;
      w2[3] = append1[0] >> 16 | append1[1] << 16;
      w3[0] = append1[1] >> 16 | append1[2] << 16;
      w3[1] = append1[2] >> 16 | append1[3] << 16;
      break;

    case 27:
      w1[2] = w1[2]            | append0[0] << 24;
      w1[3] = append0[0] >>  8 | append0[1] << 24;
      w2[0] = append0[1] >>  8 | append0[2] << 24;
      w2[1] = append0[2] >>  8 | append0[3] << 24;
      w2[2] = append0[3] >>  8 | append1[0] << 24;
      w2[3] = append1[0] >>  8 | append1[1] << 24;
      w3[0] = append1[1] >>  8 | append1[2] << 24;
      w3[1] = append1[2] >>  8 | append1[3] << 24;
      break;

    case 28:
      w1[3] = append0[0];
      w2[0] = append0[1];
      w2[1] = append0[2];
      w2[2] = append0[3];
      w2[3] = append1[0];
      w3[0] = append1[1];
      w3[1] = append1[2];
      break;

    case 29:
      w1[3] = w1[3]            | append0[0] <<  8;
      w2[0] = append0[0] >> 24 | append0[1] <<  8;
      w2[1] = append0[1] >> 24 | append0[2] <<  8;
      w2[2] = append0[2] >> 24 | append0[3] <<  8;
      w2[3] = append0[3] >> 24 | append1[0] <<  8;
      w3[0] = append1[0] >> 24 | append1[1] <<  8;
      w3[1] = append1[1] >> 24 | append1[2] <<  8;
      break;

    case 30:
      w1[3] = w1[3]            | append0[0] << 16;
      w2[0] = append0[0] >> 16 | append0[1] << 16;
      w2[1] = append0[1] >> 16 | append0[2] << 16;
      w2[2] = append0[2] >> 16 | append0[3] << 16;
      w2[3] = append0[3] >> 16 | append1[0] << 16;
      w3[0] = append1[0] >> 16 | append1[1] << 16;
      w3[1] = append1[1] >> 16 | append1[2] << 16;
      break;

    case 31:
      w1[3] = w1[3]            | append0[0] << 24;
      w2[0] = append0[0] >>  8 | append0[1] << 24;
      w2[1] = append0[1] >>  8 | append0[2] << 24;
      w2[2] = append0[2] >>  8 | append0[3] << 24;
      w2[3] = append0[3] >>  8 | append1[0] << 24;
      w3[0] = append1[0] >>  8 | append1[1] << 24;
      w3[1] = append1[1] >>  8 | append1[2] << 24;
      break;

    case 32:
      w2[0] = append0[0];
      w2[1] = append0[1];
      w2[2] = append0[2];
      w2[3] = append0[3];
      w3[0] = append1[0];
      w3[1] = append1[1];
      break;
  }
}

*/
