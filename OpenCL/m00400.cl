/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

void md5_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[4])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = 0;

  MD5_STEP_S (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP_S (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  MD5_STEP_S (MD5_H , a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP_S (MD5_H , d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP_S (MD5_H , c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP_S (MD5_H , b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP_S (MD5_H , a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP_S (MD5_H , d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP_S (MD5_H , c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP_S (MD5_H , b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP_S (MD5_H , a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP_S (MD5_H , d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP_S (MD5_H , c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP_S (MD5_H , b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP_S (MD5_H , a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP_S (MD5_H , d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP_S (MD5_H , c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP_S (MD5_H , b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP_S (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

void md5_transform_V (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[4])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = 0;

  MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  MD5_STEP (MD5_H , a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

__kernel void m00400_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global phpass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = 0;
  w2[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];

  /**
   * init
   */

  u32 block_len = 8 + pw_len;

  u32 block0[4];

  block0[0] = salt_buf[0];
  block0[1] = salt_buf[1];
  block0[2] = w0[0];
  block0[3] = w0[1];

  u32 block1[4];

  block1[0] = w0[2];
  block1[1] = w0[3];
  block1[2] = w1[0];
  block1[3] = w1[1];

  u32 block2[4];

  block2[0] = w1[2];
  block2[1] = w1[3];
  block2[2] = w2[0];
  block2[3] = w2[1];

  u32 block3[4];

  block3[0] = 0;
  block3[1] = 0;
  block3[2] = block_len * 8;
  block3[3] = 0;

  append_0x80_4x4_S (block0, block1, block2, block3, block_len);

  /**
   * init
   */

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform_S (block0, block1, block2, block3, digest);

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

__kernel void m00400_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global phpass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];

  w0[0] = packv (pws, i, gid, 0);
  w0[1] = packv (pws, i, gid, 1);
  w0[2] = packv (pws, i, gid, 2);
  w0[3] = packv (pws, i, gid, 3);
  w1[0] = packv (pws, i, gid, 4);
  w1[1] = packv (pws, i, gid, 5);
  w1[2] = packv (pws, i, gid, 6);
  w1[3] = packv (pws, i, gid, 7);
  w2[0] = packv (pws, i, gid, 8);
  w2[1] = packv (pws, i, gid, 9);
  w2[2] = 0;
  w2[3] = 0;

  u32x pw_len = packvf (pws, pw_len, gid);

  u32x digest[4];

  digest[0] = packv (tmps, digest_buf, gid, 0);
  digest[1] = packv (tmps, digest_buf, gid, 1);
  digest[2] = packv (tmps, digest_buf, gid, 2);
  digest[3] = packv (tmps, digest_buf, gid, 3);

  /**
   * loop
   */

  u32x block_len = (16 + pw_len);

  u32x block0[4];
  u32x block1[4];
  u32x block2[4];
  u32x block3[4];

  block0[0] = 0;
  block0[1] = 0;
  block0[2] = 0;
  block0[3] = 0;
  block1[0] = w0[0];
  block1[1] = w0[1];
  block1[2] = w0[2];
  block1[3] = w0[3];
  block2[0] = w1[0];
  block2[1] = w1[1];
  block2[2] = w1[2];
  block2[3] = w1[3];
  block3[0] = w2[0];
  block3[1] = w2[1];
  block3[2] = block_len * 8;
  block3[3] = 0;

  append_0x80_4x4_VV (block0, block1, block2, block3, block_len);

  /**
   * init
   */

  for (u32 i = 0; i < loop_cnt; i++)
  {
    block0[0] = digest[0];
    block0[1] = digest[1];
    block0[2] = digest[2];
    block0[3] = digest[3];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform_V (block0, block1, block2, block3, digest);
  }

  unpackv (tmps, digest_buf, gid, 0, digest[0]);
  unpackv (tmps, digest_buf, gid, 1, digest[1]);
  unpackv (tmps, digest_buf, gid, 2, digest[2]);
  unpackv (tmps, digest_buf, gid, 3, digest[3]);
}

__kernel void m00400_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global phpass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
