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

DECLSPEC void m00040m (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[salt_pos].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[salt_pos].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[salt_pos].salt_buf[10];
  salt_buf2[3] = salt_bufs[salt_pos].salt_buf[11];
  salt_buf3[0] = salt_bufs[salt_pos].salt_buf[12];
  salt_buf3[1] = salt_bufs[salt_pos].salt_buf[13];
  salt_buf3[2] = salt_bufs[salt_pos].salt_buf[14];
  salt_buf3[3] = salt_bufs[salt_pos].salt_buf[15];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  /**
   * loop
   */

  const u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x t0[4];
    u32x t1[4];
    u32x t2[4];
    u32x t3[4];

    t0[0] = w0lr;
    t0[1] = w0[1];
    t0[2] = w0[2];
    t0[3] = w0[3];
    t1[0] = w1[0];
    t1[1] = w1[1];
    t1[2] = w1[2];
    t1[3] = w1[3];
    t2[0] = w2[0];
    t2[1] = w2[1];
    t2[2] = w2[2];
    t2[3] = w2[3];
    t3[0] = w3[0];
    t3[1] = w3[1];
    t3[2] = w3[2];
    t3[3] = w3[3];

    switch_buffer_by_offset_le (t0, t1, t2, t3, salt_len);

    t0[0] |= salt_buf0[0];
    t0[1] |= salt_buf0[1];
    t0[2] |= salt_buf0[2];
    t0[3] |= salt_buf0[3];
    t1[0] |= salt_buf1[0];
    t1[1] |= salt_buf1[1];
    t1[2] |= salt_buf1[2];
    t1[3] |= salt_buf1[3];
    t2[0] |= salt_buf2[0];
    t2[1] |= salt_buf2[1];
    t2[2] |= salt_buf2[2];
    t2[3] |= salt_buf2[3];
    t3[0] |= salt_buf3[0];
    t3[1] |= salt_buf3[1];
    t3[2]  = pw_salt_len * 8;
    t3[3]  = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, t0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, t0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, t1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, t0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t2[1], MD5C3f, MD5S33);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

DECLSPEC void m00040s (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[salt_pos].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[salt_pos].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[salt_pos].salt_buf[10];
  salt_buf2[3] = salt_bufs[salt_pos].salt_buf[11];
  salt_buf3[0] = salt_bufs[salt_pos].salt_buf[12];
  salt_buf3[1] = salt_bufs[salt_pos].salt_buf[13];
  salt_buf3[2] = salt_bufs[salt_pos].salt_buf[14];
  salt_buf3[3] = salt_bufs[salt_pos].salt_buf[15];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  /**
   * loop
   */

  const u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x t0[4];
    u32x t1[4];
    u32x t2[4];
    u32x t3[4];

    t0[0] = w0lr;
    t0[1] = w0[1];
    t0[2] = w0[2];
    t0[3] = w0[3];
    t1[0] = w1[0];
    t1[1] = w1[1];
    t1[2] = w1[2];
    t1[3] = w1[3];
    t2[0] = w2[0];
    t2[1] = w2[1];
    t2[2] = w2[2];
    t2[3] = w2[3];
    t3[0] = w3[0];
    t3[1] = w3[1];
    t3[2] = w3[2];
    t3[3] = w3[3];

    switch_buffer_by_offset_le (t0, t1, t2, t3, salt_len);

    t0[0] |= salt_buf0[0];
    t0[1] |= salt_buf0[1];
    t0[2] |= salt_buf0[2];
    t0[3] |= salt_buf0[3];
    t1[0] |= salt_buf1[0];
    t1[1] |= salt_buf1[1];
    t1[2] |= salt_buf1[2];
    t1[3] |= salt_buf1[3];
    t2[0] |= salt_buf2[0];
    t2[1] |= salt_buf2[1];
    t2[2] |= salt_buf2[2];
    t2[3] |= salt_buf2[3];
    t3[0] |= salt_buf3[0];
    t3[1] |= salt_buf3[1];
    t3[2]  = pw_salt_len * 8;
    t3[3]  = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, t0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, t0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, t1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, t0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t1[0], MD5C3c, MD5S30);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD5_STEP (MD5_I , d, a, b, c, t2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t2[1], MD5C3f, MD5S33);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m00040_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00040_m08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00040_m16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00040_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00040_s08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00040_s16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00040s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
