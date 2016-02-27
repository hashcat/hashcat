/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _MD5_

#define NEW_SIMD_CODE

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 3
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"
#include "OpenCL/simd.c"

static void m04800m (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * salt
   */

  u32 salt_buf[5];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  u32 s0[4];

  s0[0] = salt_buf[0];
  s0[1] = salt_buf[1];
  s0[2] = salt_buf[2];
  s0[3] = salt_buf[3];

  u32 s1[4];

  s1[0] = 0x80;
  s1[1] = 0;
  s1[2] = 0;
  s1[3] = 0;

  u32 s2[4];

  s2[0] = 0;
  s2[1] = 0;
  s2[2] = 0;
  s2[3] = 0;

  u32 s3[4];

  s3[0] = 0;
  s3[1] = 0;
  s3[2] = 0;
  s3[3] = 0;

  // move w by 1

  u32x w0_t[4];

  w0_t[0] = w0[0];
  w0_t[1] = w0[1];
  w0_t[2] = w0[2];
  w0_t[3] = w0[3];

  u32x w1_t[4];

  w1_t[0] = w1[0];
  w1_t[1] = w1[1];
  w1_t[2] = w1[2];
  w1_t[3] = w1[3];

  u32x w2_t[4];

  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;

  u32x w3_t[4];

  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, 1);

  switch_buffer_by_offset_le_S (s0, s1, s2, s3, 1 + pw_len);

  w0_t[0] |= s0[0];
  w0_t[1] |= s0[1];
  w0_t[2] |= s0[2];
  w0_t[3] |= s0[3];

  w1_t[0] |= s1[0];
  w1_t[1] |= s1[1];
  w1_t[2] |= s1[2];
  w1_t[3] |= s1[3];

  w2_t[0] |= s2[0];
  w2_t[1] |= s2[1];
  w2_t[2] |= s2[2];
  w2_t[3] |= s2[3];

  w3_t[0] |= s3[0];
  w3_t[1] |= s3[1];
  w3_t[2]  = pw_salt_len * 8;
  w3_t[3]  = 0;

  /**
   * add id byte
   */

  w0_t[0] |= salt_buf[4];

  /**
   * loop
   */

  u32x w0l = w0_t[0];
  u32x w1l = w0_t[1];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    w0_t[0] = w0l | (w0r <<  8);
    w0_t[1] = w1l | (w0r >> 24);

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

static void m04800s (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * salt
   */

  u32 salt_buf[5];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  u32 s0[4];

  s0[0] = salt_buf[0];
  s0[1] = salt_buf[1];
  s0[2] = salt_buf[2];
  s0[3] = salt_buf[3];

  u32 s1[4];

  s1[0] = 0x80;
  s1[1] = 0;
  s1[2] = 0;
  s1[3] = 0;

  u32 s2[4];

  s2[0] = 0;
  s2[1] = 0;
  s2[2] = 0;
  s2[3] = 0;

  u32 s3[4];

  s3[0] = 0;
  s3[1] = 0;
  s3[2] = 0;
  s3[3] = 0;

  // move w by 1

  u32x w0_t[4];

  w0_t[0] = w0[0];
  w0_t[1] = w0[1];
  w0_t[2] = w0[2];
  w0_t[3] = w0[3];

  u32x w1_t[4];

  w1_t[0] = w1[0];
  w1_t[1] = w1[1];
  w1_t[2] = w1[2];
  w1_t[3] = w1[3];

  u32x w2_t[4];

  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;

  u32x w3_t[4];

  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, 1);

  switch_buffer_by_offset_le_S (s0, s1, s2, s3, 1 + pw_len);

  w0_t[0] |= s0[0];
  w0_t[1] |= s0[1];
  w0_t[2] |= s0[2];
  w0_t[3] |= s0[3];

  w1_t[0] |= s1[0];
  w1_t[1] |= s1[1];
  w1_t[2] |= s1[2];
  w1_t[3] |= s1[3];

  w2_t[0] |= s2[0];
  w2_t[1] |= s2[1];
  w2_t[2] |= s2[2];
  w2_t[3] |= s2[3];

  w3_t[0] |= s3[0];
  w3_t[1] |= s3[1];
  w3_t[2]  = pw_salt_len * 8;
  w3_t[3]  = 0;

  /**
   * add id byte
   */

  w0_t[0] |= salt_buf[4];

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

  u32x w0l = w0_t[0];
  u32x w1l = w0_t[1];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    w0_t[0] = w0l | (w0r <<  8);
    w0_t[1] = w1l | (w0r >> 24);

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m04800_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);


  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04800_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04800_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04800_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04800_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04800_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04800s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}
