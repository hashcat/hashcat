/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA1_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#ifdef  VLIW1
#define VECT_SIZE1
#endif

#ifdef  VLIW2
#define VECT_SIZE1
#endif

#define DGST_R0 3
#define DGST_R1 4
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "types_nv.c"
#include "common_nv.c"
#include "include/rp_gpu.h"
#include "rp_nv.c"

#ifdef  VECT_SIZE1
#define VECT_COMPARE_S "check_single_vect1_comp4.c"
#define VECT_COMPARE_M "check_multi_vect1_comp4.c"
#endif

#ifdef  VECT_SIZE2
#define VECT_COMPARE_S "check_single_vect2_comp4.c"
#define VECT_COMPARE_M "check_multi_vect2_comp4.c"
#endif

#ifdef  VECT_SIZE4
#define VECT_COMPARE_S "check_single_vect4_comp4.c"
#define VECT_COMPARE_M "check_multi_vect4_comp4.c"
#endif

__device__ __constant__ gpu_rule_t c_rules[1024];

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_m04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = threadIdx.x;

  /**
   * base
   */

  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  u32x pw_buf0[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];

  u32x pw_buf1[4];

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
    u32x w0[4];

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];

    u32x w1[4];

    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

    u32x w2[4];

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;

    u32x w3[4];

    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    const u32 out_len = apply_rules (c_rules[il_pos].cmds, w0, w1, pw_len);

    /**
     * prepend salt
     */

    const u32 out_salt_len = (out_len * 2) + salt_len;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

    switch_buffer_by_offset (w0_t, w1_t, w2_t, w3_t, salt_len);

    w0_t[0] |= salt_buf0[0];
    w0_t[1] |= salt_buf0[1];
    w0_t[2] |= salt_buf0[2];
    w0_t[3] |= salt_buf0[3];
    w1_t[0] |= salt_buf1[0];
    w1_t[1] |= salt_buf1[1];
    w1_t[2] |= salt_buf1[2];
    w1_t[3] |= salt_buf1[3];

    append_0x80_4 (w0_t, w1_t, w2_t, w3_t, out_salt_len);

    w3_t[3] = out_salt_len * 8;

    /**
     * sha1
     */

    w0_t[0] = swap_workaround (w0_t[0]);
    w0_t[1] = swap_workaround (w0_t[1]);
    w0_t[2] = swap_workaround (w0_t[2]);
    w0_t[3] = swap_workaround (w0_t[3]);
    w1_t[0] = swap_workaround (w1_t[0]);
    w1_t[1] = swap_workaround (w1_t[1]);
    w1_t[2] = swap_workaround (w1_t[2]);
    w1_t[3] = swap_workaround (w1_t[3]);
    w2_t[0] = swap_workaround (w2_t[0]);
    w2_t[1] = swap_workaround (w2_t[1]);
    w2_t[2] = swap_workaround (w2_t[2]);
    w2_t[3] = swap_workaround (w2_t[3]);
    w3_t[0] = swap_workaround (w3_t[0]);
    w3_t[1] = swap_workaround (w3_t[1]);
    //w3_t[2] = swap_workaround (w3_t[2]);
    //w3_t[3] = swap_workaround (w3_t[3]);

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


    const u32x r0 = d;
    const u32x r1 = e;
    const u32x r2 = c;
    const u32x r3 = b;

    #include VECT_COMPARE_M
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_m08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_m16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_s04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = threadIdx.x;

  /**
   * base
   */

  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  u32x pw_buf0[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];

  u32x pw_buf1[4];

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
    u32x w0[4];

    w0[0] = pw_buf0[0];
    w0[1] = pw_buf0[1];
    w0[2] = pw_buf0[2];
    w0[3] = pw_buf0[3];

    u32x w1[4];

    w1[0] = pw_buf1[0];
    w1[1] = pw_buf1[1];
    w1[2] = pw_buf1[2];
    w1[3] = pw_buf1[3];

    u32x w2[4];

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;

    u32x w3[4];

    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    const u32 out_len = apply_rules (c_rules[il_pos].cmds, w0, w1, pw_len);

    /**
     * prepend salt
     */

    const u32 out_salt_len = (out_len * 2) + salt_len;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

    switch_buffer_by_offset (w0_t, w1_t, w2_t, w3_t, salt_len);

    w0_t[0] |= salt_buf0[0];
    w0_t[1] |= salt_buf0[1];
    w0_t[2] |= salt_buf0[2];
    w0_t[3] |= salt_buf0[3];
    w1_t[0] |= salt_buf1[0];
    w1_t[1] |= salt_buf1[1];
    w1_t[2] |= salt_buf1[2];
    w1_t[3] |= salt_buf1[3];

    append_0x80_4 (w0_t, w1_t, w2_t, w3_t, out_salt_len);

    w3_t[3] = out_salt_len * 8;

    /**
     * sha1
     */

    w0_t[0] = swap_workaround (w0_t[0]);
    w0_t[1] = swap_workaround (w0_t[1]);
    w0_t[2] = swap_workaround (w0_t[2]);
    w0_t[3] = swap_workaround (w0_t[3]);
    w1_t[0] = swap_workaround (w1_t[0]);
    w1_t[1] = swap_workaround (w1_t[1]);
    w1_t[2] = swap_workaround (w1_t[2]);
    w1_t[3] = swap_workaround (w1_t[3]);
    w2_t[0] = swap_workaround (w2_t[0]);
    w2_t[1] = swap_workaround (w2_t[1]);
    w2_t[2] = swap_workaround (w2_t[2]);
    w2_t[3] = swap_workaround (w2_t[3]);
    w3_t[0] = swap_workaround (w3_t[0]);
    w3_t[1] = swap_workaround (w3_t[1]);
    //w3_t[2] = swap_workaround (w3_t[2]);
    //w3_t[3] = swap_workaround (w3_t[3]);

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

    if (e != e_rev) continue;

    w3_t[1] = rotl32 ((w2_t[2] ^ w1_t[1] ^ w3_t[3] ^ w3_t[1]), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t[1]);
    w3_t[2] = rotl32 ((w2_t[3] ^ w1_t[2] ^ w0_t[0] ^ w3_t[2]), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3_t[2]);
    w3_t[3] = rotl32 ((w3_t[0] ^ w1_t[3] ^ w0_t[1] ^ w3_t[3]), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w3_t[3]);


    const u32x r0 = d;
    const u32x r1 = e;
    const u32x r2 = c;
    const u32x r3 = b;

    #include VECT_COMPARE_S
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_s08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00140_s16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
