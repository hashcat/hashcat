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

static void m08100m (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * salt
   */

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * prepend salt
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = w0lr;
    w0_t[3] = w0[1];
    w1_t[0] = w0[2];
    w1_t[1] = w0[3];
    w1_t[2] = w1[0];
    w1_t[3] = w1[1];
    w2_t[0] = w1[2];
    w2_t[1] = w1[3];
    w2_t[2] = w2[0];
    w2_t[3] = w2[1];
    w3_t[0] = w2[2];
    w3_t[1] = w2[3];
    w3_t[2] = 0;
    w3_t[3] = (pw_salt_len + 1) * 8;

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

    COMPARE_M_SIMD (d, e, c, b);
  }
}

static void m08100s (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], const u32 pw_len, __global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
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

  u32 salt_buf0[2];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * prepend salt
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = w0lr;
    w0_t[3] = w0[1];
    w1_t[0] = w0[2];
    w1_t[1] = w0[3];
    w1_t[2] = w1[0];
    w1_t[3] = w1[1];
    w2_t[0] = w1[2];
    w2_t[1] = w1[3];
    w2_t[2] = w2[0];
    w2_t[3] = w2[1];
    w3_t[0] = w2[2];
    w3_t[1] = w2[3];
    w3_t[2] = 0;
    w3_t[3] = (pw_salt_len + 1) * 8;

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

    if (MATCHES_NONE_VS (e, e_rev)) continue;

    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[3]);

    COMPARE_S_SIMD (d, e, c, b);
  }
}

__kernel void m08100_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);

  append_0x80_2x4_S (w0, w1, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);

  /**
   * main
   */

  m08100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m08100_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);

  append_0x80_3x4_S (w0, w1, w2, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);

  /**
   * main
   */

  m08100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m08100_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = 0;
  w3[3] = 0;

  append_0x80_4x4_S (w0, w1, w2, w3, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = 0;
  w3[3] = 0;

  /**
   * main
   */

  m08100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m08100_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);

  append_0x80_2x4_S (w0, w1, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);

  /**
   * main
   */

  m08100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m08100_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);

  append_0x80_3x4_S (w0, w1, w2, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);

  /**
   * main
   */

  m08100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m08100_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * base
   */

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = 0;
  w3[3] = 0;

  append_0x80_4x4_S (w0, w1, w2, w3, pw_len + 1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = 0;
  w3[3] = 0;

  /**
   * main
   */

  m08100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}
