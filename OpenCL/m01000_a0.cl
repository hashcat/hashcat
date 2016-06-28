/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _MD4_

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"

__kernel void m01000_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    make_unicode (w1, w2, w3);
    make_unicode (w0, w0, w1);

    w3[2] = out_len * 8 * 2;
    w3[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

__kernel void m01000_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01000_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01000_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len;

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
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    make_unicode (w1, w2, w3);
    make_unicode (w0, w0, w1);

    w3[2] = out_len * 8 * 2;
    w3[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m01000_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01000_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
