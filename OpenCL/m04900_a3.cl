/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA1_

#define NEW_SIMD_CODE

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 3
#define DGST_R1 4
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"
#include "OpenCL/simd.c"

static void m04900m (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * salt
   */

  u32 salt_buf0_t[4];

  salt_buf0_t[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0_t[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0_t[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0_t[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1_t[4];

  salt_buf1_t[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1_t[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1_t[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1_t[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 salt_buf2_t[4];

  salt_buf2_t[0] = 0;
  salt_buf2_t[1] = 0;
  salt_buf2_t[2] = 0;
  salt_buf2_t[3] = 0;

  u32 salt_buf3_t[4];

  salt_buf3_t[0] = 0;
  salt_buf3_t[1] = 0;
  salt_buf3_t[2] = 0;
  salt_buf3_t[3] = 0;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = salt_len + pw_len + salt_len;

  // first we need to switch the right-hand salt to the correct position (2nd salt)

  switch_buffer_by_offset_le_S (salt_buf0_t, salt_buf1_t, salt_buf2_t, salt_buf3_t, salt_len + pw_len);

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 salt_buf2[4];

  salt_buf2[0] = 0;
  salt_buf2[1] = 0;
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

  u32 salt_buf3[4];

  salt_buf3[0] = 0;
  salt_buf3[1] = 0;
  salt_buf3[2] = 0;
  salt_buf3[3] = 0;

  // concatenate the 1st and 2nd instance of the salt

  salt_buf0[0] |= salt_buf0_t[0];
  salt_buf0[1] |= salt_buf0_t[1];
  salt_buf0[2] |= salt_buf0_t[2];
  salt_buf0[3] |= salt_buf0_t[3];

  salt_buf1[0] |= salt_buf1_t[0];
  salt_buf1[1] |= salt_buf1_t[1];
  salt_buf1[2] |= salt_buf1_t[2];
  salt_buf1[3] |= salt_buf1_t[3];

  salt_buf2[0] |= salt_buf2_t[0];
  salt_buf2[1] |= salt_buf2_t[1];
  salt_buf2[2] |= salt_buf2_t[2];
  salt_buf2[3] |= salt_buf2_t[3];

  salt_buf3[0] |= salt_buf3_t[0];
  salt_buf3[1] |= salt_buf3_t[1];
  salt_buf3[2] |= salt_buf3_t[2];
  salt_buf3[3] |= salt_buf3_t[3];

  append_0x80_4x4_S (salt_buf0, salt_buf1, salt_buf2, salt_buf3, pw_salt_len);

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];

    u32x w1_t[4];

    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];

    u32x w2_t[4];

    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];

    u32x w3_t[4];

    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * put the password after the first salt but before the second salt
     */

    switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, salt_len);

    w0_t[0] |= salt_buf0[0];
    w0_t[1] |= salt_buf0[1];
    w0_t[2] |= salt_buf0[2];
    w0_t[3] |= salt_buf0[3];
    w1_t[0] |= salt_buf1[0];
    w1_t[1] |= salt_buf1[1];
    w1_t[2] |= salt_buf1[2];
    w1_t[3] |= salt_buf1[3];
    w2_t[0] |= salt_buf2[0];
    w2_t[1] |= salt_buf2[1];
    w2_t[2] |= salt_buf2[2];
    w2_t[3] |= salt_buf2[3];
    w3_t[0] |= salt_buf3[0];
    w3_t[1] |= salt_buf3[1];
    w3_t[2] |= salt_buf3[2];

    u32x w0 = swap32 (w0_t[0]);
    u32x w1 = swap32 (w0_t[1]);
    u32x w2 = swap32 (w0_t[2]);
    u32x w3 = swap32 (w0_t[3]);
    u32x w4 = swap32 (w1_t[0]);
    u32x w5 = swap32 (w1_t[1]);
    u32x w6 = swap32 (w1_t[2]);
    u32x w7 = swap32 (w1_t[3]);
    u32x w8 = swap32 (w2_t[0]);
    u32x w9 = swap32 (w2_t[1]);
    u32x wa = swap32 (w2_t[2]);
    u32x wb = swap32 (w2_t[3]);
    u32x wc = swap32 (w3_t[0]);
    u32x wd = swap32 (w3_t[1]);
    u32x we = swap32 (w3_t[2]);
    u32x wf = pw_salt_len * 8;

    /**
     * sha1
     */

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3);

    #undef K
    #define K SHA1C01

    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb);
    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7);

    #undef K
    #define K SHA1C02

    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb);
    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb);

    #undef K
    #define K SHA1C03

    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb);
    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf);

    COMPARE_M_SIMD (d, e, c, b);
  }
}

static void m04900s (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

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
   * reverse
   */

  const u32 e_rev = rotl32_S (search[1], 2u);

  /**
   * salt
   */

  u32 salt_buf0_t[4];

  salt_buf0_t[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0_t[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0_t[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0_t[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1_t[4];

  salt_buf1_t[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1_t[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1_t[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1_t[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 salt_buf2_t[4];

  salt_buf2_t[0] = 0;
  salt_buf2_t[1] = 0;
  salt_buf2_t[2] = 0;
  salt_buf2_t[3] = 0;

  u32 salt_buf3_t[4];

  salt_buf3_t[0] = 0;
  salt_buf3_t[1] = 0;
  salt_buf3_t[2] = 0;
  salt_buf3_t[3] = 0;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = salt_len + pw_len + salt_len;

  // first we need to switch the right-hand salt to the correct position (2nd salt)

  switch_buffer_by_offset_le_S (salt_buf0_t, salt_buf1_t, salt_buf2_t, salt_buf3_t, salt_len + pw_len);

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 salt_buf2[4];

  salt_buf2[0] = 0;
  salt_buf2[1] = 0;
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

  u32 salt_buf3[4];

  salt_buf3[0] = 0;
  salt_buf3[1] = 0;
  salt_buf3[2] = 0;
  salt_buf3[3] = 0;

  // concatenate the 1st and 2nd instance of the salt

  salt_buf0[0] |= salt_buf0_t[0];
  salt_buf0[1] |= salt_buf0_t[1];
  salt_buf0[2] |= salt_buf0_t[2];
  salt_buf0[3] |= salt_buf0_t[3];

  salt_buf1[0] |= salt_buf1_t[0];
  salt_buf1[1] |= salt_buf1_t[1];
  salt_buf1[2] |= salt_buf1_t[2];
  salt_buf1[3] |= salt_buf1_t[3];

  salt_buf2[0] |= salt_buf2_t[0];
  salt_buf2[1] |= salt_buf2_t[1];
  salt_buf2[2] |= salt_buf2_t[2];
  salt_buf2[3] |= salt_buf2_t[3];

  salt_buf3[0] |= salt_buf3_t[0];
  salt_buf3[1] |= salt_buf3_t[1];
  salt_buf3[2] |= salt_buf3_t[2];
  salt_buf3[3] |= salt_buf3_t[3];

  append_0x80_4x4_S (salt_buf0, salt_buf1, salt_buf2, salt_buf3, pw_salt_len);

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w0_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];

    u32x w1_t[4];

    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];

    u32x w2_t[4];

    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];

    u32x w3_t[4];

    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = w3[2];
    w3_t[3] = w3[3];

    /**
     * put the password after the first salt but before the second salt
     */

    switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, salt_len);

    w0_t[0] |= salt_buf0[0];
    w0_t[1] |= salt_buf0[1];
    w0_t[2] |= salt_buf0[2];
    w0_t[3] |= salt_buf0[3];
    w1_t[0] |= salt_buf1[0];
    w1_t[1] |= salt_buf1[1];
    w1_t[2] |= salt_buf1[2];
    w1_t[3] |= salt_buf1[3];
    w2_t[0] |= salt_buf2[0];
    w2_t[1] |= salt_buf2[1];
    w2_t[2] |= salt_buf2[2];
    w2_t[3] |= salt_buf2[3];
    w3_t[0] |= salt_buf3[0];
    w3_t[1] |= salt_buf3[1];
    w3_t[2] |= salt_buf3[2];

    u32x w0 = swap32 (w0_t[0]);
    u32x w1 = swap32 (w0_t[1]);
    u32x w2 = swap32 (w0_t[2]);
    u32x w3 = swap32 (w0_t[3]);
    u32x w4 = swap32 (w1_t[0]);
    u32x w5 = swap32 (w1_t[1]);
    u32x w6 = swap32 (w1_t[2]);
    u32x w7 = swap32 (w1_t[3]);
    u32x w8 = swap32 (w2_t[0]);
    u32x w9 = swap32 (w2_t[1]);
    u32x wa = swap32 (w2_t[2]);
    u32x wb = swap32 (w2_t[3]);
    u32x wc = swap32 (w3_t[0]);
    u32x wd = swap32 (w3_t[1]);
    u32x we = swap32 (w3_t[2]);
    u32x wf = pw_salt_len * 8;

    /**
     * sha1
     */

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3);

    #undef K
    #define K SHA1C01

    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb);
    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7);

    #undef K
    #define K SHA1C02

    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb);
    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb);

    #undef K
    #define K SHA1C03

    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf);
    w0 = rotl32 ((wd ^ w8 ^ w2 ^ w0), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0);
    w1 = rotl32 ((we ^ w9 ^ w3 ^ w1), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1);
    w2 = rotl32 ((wf ^ wa ^ w4 ^ w2), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2);
    w3 = rotl32 ((w0 ^ wb ^ w5 ^ w3), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3);
    w4 = rotl32 ((w1 ^ wc ^ w6 ^ w4), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4);
    w5 = rotl32 ((w2 ^ wd ^ w7 ^ w5), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5);
    w6 = rotl32 ((w3 ^ we ^ w8 ^ w6), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6);
    w7 = rotl32 ((w4 ^ wf ^ w9 ^ w7), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7);
    w8 = rotl32 ((w5 ^ w0 ^ wa ^ w8), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8);
    w9 = rotl32 ((w6 ^ w1 ^ wb ^ w9), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9);
    wa = rotl32 ((w7 ^ w2 ^ wc ^ wa), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa);
    wb = rotl32 ((w8 ^ w3 ^ wd ^ wb), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb);

    if (MATCHES_NONE_VS (e, e_rev)) continue;

    wc = rotl32 ((w9 ^ w4 ^ we ^ wc), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc);
    wd = rotl32 ((wa ^ w5 ^ wf ^ wd), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd);
    we = rotl32 ((wb ^ w6 ^ w0 ^ we), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we);
    wf = rotl32 ((wc ^ w7 ^ w1 ^ wf), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf);

    COMPARE_S_SIMD (d, e, c, b);
  }
}

__kernel void m04900_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04900_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04900_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  m04900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04900_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04900_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w3[2] = pws[gid].i[14];
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m04900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m04900_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  m04900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}
