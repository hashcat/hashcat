/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SIPHASH_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 1
#define DGST_R2 2
#define DGST_R3 3

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

#define SIPROUND(v0,v1,v2,v3) \
  (v0) += (v1);               \
  (v1)  = rotl64 ((v1), 13);  \
  (v1) ^= (v0);               \
  (v0)  = as_ulong (as_uint2 ((v0)).s10); \
  (v2) += (v3);               \
  (v3)  = rotl64 ((v3), 16);  \
  (v3) ^= (v2);               \
  (v0) += (v3);               \
  (v3)  = rotl64 ((v3), 21);  \
  (v3) ^= (v0);               \
  (v2) += (v1);               \
  (v1)  = rotl64 ((v1), 17);  \
  (v1) ^= (v2);               \
  (v2)  = as_ulong (as_uint2 ((v2)).s10);

__kernel void m10100_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * base
   */

  u64 v0p = SIPHASHM_0;
  u64 v1p = SIPHASHM_1;
  u64 v2p = SIPHASHM_2;
  u64 v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    u64 *w_ptr = (u64 *) w;

    w_ptr[pw_len / 8] |= (u64) pw_len << 56;

    u64 v0 = v0p;
    u64 v1 = v1p;
    u64 v2 = v2p;
    u64 v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= pw_len; i += 8, j += 2)
    {
      u64 m = hl32_to_64 (w[j + 1], w[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64 v = v0 ^ v1 ^ v2 ^ v3;

    const u32 a = l32_from_64 (v);
    const u32 b = h32_from_64 (v);

    const u32 r0 = a;
    const u32 r1 = b;
    const u32 r2 = 0;
    const u32 r3 = 0;

    #include COMPARE_M
  }
}

__kernel void m10100_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10100_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10100_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  u64 v0p = SIPHASHM_0;
  u64 v1p = SIPHASHM_1;
  u64 v2p = SIPHASHM_2;
  u64 v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[1], salt_bufs[salt_pos].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[salt_pos].salt_buf[3], salt_bufs[salt_pos].salt_buf[2]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    u64 *w_ptr = (u64 *) w;

    w_ptr[pw_len / 8] |= (u64) pw_len << 56;

    u64 v0 = v0p;
    u64 v1 = v1p;
    u64 v2 = v2p;
    u64 v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= pw_len; i += 8, j += 2)
    {
      u64 m = hl32_to_64 (w[j + 1], w[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64 v = v0 ^ v1 ^ v2 ^ v3;

    const u32 a = l32_from_64 (v);
    const u32 b = h32_from_64 (v);

    const u32 r0 = a;
    const u32 r1 = b;
    const u32 r2 = 0;
    const u32 r3 = 0;

    #include COMPARE_S
  }
}

__kernel void m10100_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10100_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
