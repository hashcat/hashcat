/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA1_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 3
#define DGST_R1 4
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"
#include "include/rp_gpu.h"
#include "OpenCL/rp.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

// no unicode yet

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_m04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];

  u32 pw_buf1[4];

  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

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

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < rules_cnt; il_pos++)
  {
    u32 w0[4];

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];

    u32 w1[4];

    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

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

    const u32 out_len = apply_rules (rules_buf[il_pos].cmds, w0, w1, pw_len);

    /**
     * append salt
     */

    u32 s0[4];

    s0[0] = salt_buf0[0];
    s0[1] = salt_buf0[1];
    s0[2] = salt_buf0[2];
    s0[3] = salt_buf0[3];

    u32 s1[4];

    s1[0] = salt_buf1[0];
    s1[1] = salt_buf1[1];
    s1[2] = salt_buf1[2];
    s1[3] = salt_buf1[3];

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

    switch_buffer_by_offset (s0, s1, s2, s3, (out_len * 2));

    const u32 out_salt_len = (out_len * 2) + salt_len;

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

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
    w3_t[2] |= s3[2];
    w3_t[3] |= s3[3];

    append_0x80_4x4 (w0_t, w1_t, w2_t, w3_t, out_salt_len);

    w3_t[3] = out_salt_len * 8;

    /**
     * sha1
     */

    w0_t[0] = swap32 (w0_t[0]);
    w0_t[1] = swap32 (w0_t[1]);
    w0_t[2] = swap32 (w0_t[2]);
    w0_t[3] = swap32 (w0_t[3]);
    w1_t[0] = swap32 (w1_t[0]);
    w1_t[1] = swap32 (w1_t[1]);
    w1_t[2] = swap32 (w1_t[2]);
    w1_t[3] = swap32 (w1_t[3]);
    w2_t[0] = swap32 (w2_t[0]);
    w2_t[1] = swap32 (w2_t[1]);
    w2_t[2] = swap32 (w2_t[2]);
    w2_t[3] = swap32 (w2_t[3]);
    w3_t[0] = swap32 (w3_t[0]);
    w3_t[1] = swap32 (w3_t[1]);
    //w3_t[2] = swap32 (w3_t[2]);
    //w3_t[3] = swap32 (w3_t[3]);

    u32 a = SHA1M_A;
    u32 b = SHA1M_B;
    u32 c = SHA1M_C;
    u32 d = SHA1M_D;
    u32 e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t[0]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t[1]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w0_t[2]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w0_t[3]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w1_t[0]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w1_t[1]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t[2]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t[3]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t[0]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w2_t[1]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w2_t[2]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w2_t[3]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w3_t[0]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t[1]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t[2]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w0_t[3]);

    #undef K
    #define K SHA1C01

    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w1_t[3]);

    #undef K
    #define K SHA1C02

    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w2_t[3]);

    #undef K
    #define K SHA1C03

    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[3]);


    const u32 r0 = d;
    const u32 r1 = e;
    const u32 r2 = c;
    const u32 r3 = b;

    #include COMPARE_M
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_m08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_m16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_s04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];

  u32 pw_buf1[4];

  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

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

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

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

  const u32 e_rev = rotl32 (search[1], 2u);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < rules_cnt; il_pos++)
  {
    u32 w0[4];

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];

    u32 w1[4];

    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

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

    const u32 out_len = apply_rules (rules_buf[il_pos].cmds, w0, w1, pw_len);

    /**
     * append salt
     */

    u32 s0[4];

    s0[0] = salt_buf0[0];
    s0[1] = salt_buf0[1];
    s0[2] = salt_buf0[2];
    s0[3] = salt_buf0[3];

    u32 s1[4];

    s1[0] = salt_buf1[0];
    s1[1] = salt_buf1[1];
    s1[2] = salt_buf1[2];
    s1[3] = salt_buf1[3];

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

    switch_buffer_by_offset (s0, s1, s2, s3, (out_len * 2));

    const u32 out_salt_len = (out_len * 2) + salt_len;

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

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
    w3_t[2] |= s3[2];
    w3_t[3] |= s3[3];

    append_0x80_4x4 (w0_t, w1_t, w2_t, w3_t, out_salt_len);

    w3_t[3] = out_salt_len * 8;

    /**
     * sha1
     */

    w0_t[0] = swap32 (w0_t[0]);
    w0_t[1] = swap32 (w0_t[1]);
    w0_t[2] = swap32 (w0_t[2]);
    w0_t[3] = swap32 (w0_t[3]);
    w1_t[0] = swap32 (w1_t[0]);
    w1_t[1] = swap32 (w1_t[1]);
    w1_t[2] = swap32 (w1_t[2]);
    w1_t[3] = swap32 (w1_t[3]);
    w2_t[0] = swap32 (w2_t[0]);
    w2_t[1] = swap32 (w2_t[1]);
    w2_t[2] = swap32 (w2_t[2]);
    w2_t[3] = swap32 (w2_t[3]);
    w3_t[0] = swap32 (w3_t[0]);
    w3_t[1] = swap32 (w3_t[1]);
    //w3_t[2] = swap32 (w3_t[2]);
    //w3_t[3] = swap32 (w3_t[3]);

    u32 a = SHA1M_A;
    u32 b = SHA1M_B;
    u32 c = SHA1M_C;
    u32 d = SHA1M_D;
    u32 e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t[0]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t[1]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w0_t[2]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w0_t[3]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w1_t[0]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w1_t[1]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t[2]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t[3]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t[0]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w2_t[1]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w2_t[2]);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w2_t[3]);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w3_t[0]);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t[1]);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t[2]);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w0_t[3]);

    #undef K
    #define K SHA1C01

    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w1_t[3]);

    #undef K
    #define K SHA1C02

    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w2_t[3]);

    #undef K
    #define K SHA1C03

    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t[0]);
    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[3]);
    w0_t[0] = rotl32 ((w3_t[1] ^ w2_t[0] ^ w0_t[2] ^ w0_t[0]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t[0]);
    w0_t[1] = rotl32 ((w3_t[2] ^ w2_t[1] ^ w0_t[3] ^ w0_t[1]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w0_t[1]);
    w0_t[2] = rotl32 ((w3_t[3] ^ w2_t[2] ^ w1_t[0] ^ w0_t[2]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w0_t[2]);
    w0_t[3] = rotl32 ((w0_t[0] ^ w2_t[3] ^ w1_t[1] ^ w0_t[3]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t[3]);
    w1_t[0] = rotl32 ((w0_t[1] ^ w3_t[0] ^ w1_t[2] ^ w1_t[0]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t[0]);
    w1_t[1] = rotl32 ((w0_t[2] ^ w3_t[1] ^ w1_t[3] ^ w1_t[1]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w1_t[1]);
    w1_t[2] = rotl32 ((w0_t[3] ^ w3_t[2] ^ w2_t[0] ^ w1_t[2]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t[2]);
    w1_t[3] = rotl32 ((w1_t[0] ^ w3_t[3] ^ w2_t[1] ^ w1_t[3]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1_t[3]);
    w2_t[0] = rotl32 ((w1_t[1] ^ w0_t[0] ^ w2_t[2] ^ w2_t[0]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w2_t[0]);
    w2_t[1] = rotl32 ((w1_t[2] ^ w0_t[1] ^ w2_t[3] ^ w2_t[1]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w2_t[1]);
    w2_t[2] = rotl32 ((w1_t[3] ^ w0_t[2] ^ w3_t[0] ^ w2_t[2]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t[2]);
    w2_t[3] = rotl32 ((w2_t[0] ^ w0_t[3] ^ w3_t[1] ^ w2_t[3]), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w2_t[3]);
    w3_t[0] = rotl32 ((w2_t[1] ^ w1_t[0] ^ w3_t[2] ^ w3_t[0]), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3_t[0]);

    if (allx (e != e_rev)) continue;

    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[3]);


    const u32 r0 = d;
    const u32 r1 = e;
    const u32 r2 = c;
    const u32 r3 = b;

    #include COMPARE_S
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_s08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m00130_s16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
