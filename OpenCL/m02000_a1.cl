/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

typedef uint  u32;
typedef ulong u64;

typedef struct pw
{
  u32 i[64];

  u32 pw_len;

} pw_t;

static u32 l32_from_64_S (u64 a)
{
  const u32 r = (u32) (a);

  return r;
}

static u32 h32_from_64_S (u64 a)
{
  a >>= 32;

  const u32 r = (u32) (a);

  return r;
}

__kernel void gpu_memset (__global uint4 *buf, const u32 value, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  buf[gid] = (uint4) (value);
}

__kernel void gpu_atinit (__global pw_t *buf, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 l32 = l32_from_64_S (gid);
  const u32 h32 = h32_from_64_S (gid);

  pw_t pw;

  pw.i[ 0] = 0x5c5c5c5c ^ l32;
  pw.i[ 1] = 0x36363636 ^ h32;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0; // yep that's faster

  pw.pw_len = 1 + (l32 & 15);

  buf[gid] = pw;
}

__kernel void m02000_mxx (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global const void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
}

__kernel void m02000_sxx (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global const void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
}
