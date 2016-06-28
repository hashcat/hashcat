/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

__kernel void gpu_memset (__global uint4 *buf, const uint value, const uint gid_max)
{
  const uint gid = get_global_id (0);

  if (gid >= gid_max) return;

  buf[gid] = (uint4) (value);
}

__kernel void m02000_m04 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}

__kernel void m02000_m08 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}

__kernel void m02000_m16 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}

__kernel void m02000_s04 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}

__kernel void m02000_s08 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}

__kernel void m02000_s16 (__global void *pws, __global void *rules_buf, __global void *combs_buf, __global void * words_buf_r, __global void *tmps, __global void *hooks, __global void *bitmaps_buf_s1_a, __global void *bitmaps_buf_s1_b, __global void *bitmaps_buf_s1_c, __global void *bitmaps_buf_s1_d, __global void *bitmaps_buf_s2_a, __global void *bitmaps_buf_s2_b, __global void *bitmaps_buf_s2_c, __global void *bitmaps_buf_s2_d, __global void *plains_buf, __global void *digests_buf, __global void *hashes_shown, __global void *salt_bufs, __global void *esalt_bufs, __global void *d_return_buf, __global void *d_scryptV0_buf, __global void *d_scryptV1_buf, __global void *d_scryptV2_buf, __global void *d_scryptV3_buf, const uint bitmap_mask, const uint bitmap_shift1, const uint bitmap_shift2, const uint salt_pos, const uint loop_pos, const uint loop_cnt, const uint il_cnt, const uint digests_cnt, const uint digests_offset, const uint combs_mode, const uint gid_max)
{
}
