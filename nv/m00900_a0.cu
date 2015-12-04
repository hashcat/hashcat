/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _MD4_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#ifdef  VLIW1
#define VECT_SIZE1
#endif

#ifdef  VLIW2
#define VECT_SIZE1
#endif

#define DGST_R0 0
#define DGST_R1 3
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

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_m04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

    append_0x80_2 (w0, w1, out_len);

    w3[2] = out_len * 8;

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

    const u32x r0 = a;
    const u32x r1 = d;
    const u32x r2 = c;
    const u32x r3 = b;

    #include VECT_COMPARE_M
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_m08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_m16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_s04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

    append_0x80_2 (w0, w1, out_len);

    w3[2] = out_len * 8;

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

    const u32x r0 = a;
    const u32x r1 = d;
    const u32x r2 = c;
    const u32x r3 = b;

    #include VECT_COMPARE_S
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_s08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m00900_s16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
