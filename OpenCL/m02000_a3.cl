/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

typedef uint   u32;
typedef ulong  u64;

__kernel void gpu_memset (__global uint4 *buf, const u32 value, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  buf[gid] = (uint4) (value);
}

__kernel void m02000_mxx (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global const void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
}

__kernel void m02000_sxx (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global const void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
}
