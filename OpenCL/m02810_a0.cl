/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _MD5_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 3
#define DGST_R2 2
#define DGST_R3 1

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"
#include "include/rp_kernel.h"
#include "OpenCL/rp.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

#define uint_to_hex_lower8(i) l_bin2asc[(i)]

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

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

  u32 s[8];

  s[0] = salt_bufs[salt_pos].salt_buf_pc[0];
  s[1] = salt_bufs[salt_pos].salt_buf_pc[1];
  s[2] = salt_bufs[salt_pos].salt_buf_pc[2];
  s[3] = salt_bufs[salt_pos].salt_buf_pc[3];
  s[4] = salt_bufs[salt_pos].salt_buf_pc[4];
  s[5] = salt_bufs[salt_pos].salt_buf_pc[5];
  s[6] = salt_bufs[salt_pos].salt_buf_pc[6];
  s[7] = salt_bufs[salt_pos].salt_buf_pc[7];

  const u32 r_00 = 0x80;
  const u32 r_14 = 64 * 8;

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * loop
   */

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

    append_0x80_2x4 (w0, w1, out_len);

    w3[2] = out_len * 8;

    u32 a = MD5M_A;
    u32 b = MD5M_B;
    u32 c = MD5M_C;
    u32 d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    const u32  w0_t = s[0];
    const u32  w1_t = s[1];
    const u32  w2_t = s[2];
    const u32  w3_t = s[3];
    const u32  w4_t = s[4];
    const u32  w5_t = s[5];
    const u32  w6_t = s[6];
    const u32  w7_t = s[7];

    const u32 w8_t = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    const u32 w9_t = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    const u32 wa_t = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    const u32 wb_t = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    const u32 wc_t = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    const u32 wd_t = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    const u32 we_t = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    const u32 wf_t = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

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

    const u32 r_a = a + MD5M_A;
    const u32 r_b = b + MD5M_B;
    const u32 r_c = c + MD5M_C;
    const u32 r_d = d + MD5M_D;

    a = r_a;
    b = r_b;
    c = r_c;
    d = r_d;

    MD5_STEP (MD5_Fo, a, b, c, d, r_00, MD5C00, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C01, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C02, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C03, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C04, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C05, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C06, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C07, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C08, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C09, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C0a, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0b, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C0c, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, r_14, MD5C0e, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0f, MD5S03);

    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C10, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C11, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, r_00, MD5C13, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C14, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C15, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C16, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C17, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, r_14, MD5C19, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1a, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1b, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C1c, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C1d, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1e, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1f, MD5S13);

    MD5_STEP0(MD5_H , a, b, c, d,       MD5C20, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C21, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, r_14, MD5C23, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C24, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C25, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C26, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C27, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, r_00, MD5C29, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C2a, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C2b, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C2c, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C2d, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C2e, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, r_00, MD5C30, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, r_14, MD5C32, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C33, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C34, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C35, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C36, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C37, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C38, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C39, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3a, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3b, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C3c, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3f, MD5S33);

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    const u32 r0 = a;
    const u32 r1 = d;
    const u32 r2 = c;
    const u32 r3 = b;

    #include COMPARE_M
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

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

  u32 s[8];

  s[0] = salt_bufs[salt_pos].salt_buf_pc[0];
  s[1] = salt_bufs[salt_pos].salt_buf_pc[1];
  s[2] = salt_bufs[salt_pos].salt_buf_pc[2];
  s[3] = salt_bufs[salt_pos].salt_buf_pc[3];
  s[4] = salt_bufs[salt_pos].salt_buf_pc[4];
  s[5] = salt_bufs[salt_pos].salt_buf_pc[5];
  s[6] = salt_bufs[salt_pos].salt_buf_pc[6];
  s[7] = salt_bufs[salt_pos].salt_buf_pc[7];

  const u32 r_00 = 0x80;
  const u32 r_14 = 64 * 8;

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
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  const u32 lid4 = lid * 4;

  const u32 lid40 = lid4 + 0;
  const u32 lid41 = lid4 + 1;
  const u32 lid42 = lid4 + 2;
  const u32 lid43 = lid4 + 3;

  const u32 v400 = (lid40 >> 0) & 15;
  const u32 v401 = (lid40 >> 4) & 15;
  const u32 v410 = (lid41 >> 0) & 15;
  const u32 v411 = (lid41 >> 4) & 15;
  const u32 v420 = (lid42 >> 0) & 15;
  const u32 v421 = (lid42 >> 4) & 15;
  const u32 v430 = (lid43 >> 0) & 15;
  const u32 v431 = (lid43 >> 4) & 15;

  l_bin2asc[lid40] = ((v400 < 10) ? '0' + v400 : 'a' - 10 + v400) << 8
                   | ((v401 < 10) ? '0' + v401 : 'a' - 10 + v401) << 0;
  l_bin2asc[lid41] = ((v410 < 10) ? '0' + v410 : 'a' - 10 + v410) << 8
                   | ((v411 < 10) ? '0' + v411 : 'a' - 10 + v411) << 0;
  l_bin2asc[lid42] = ((v420 < 10) ? '0' + v420 : 'a' - 10 + v420) << 8
                   | ((v421 < 10) ? '0' + v421 : 'a' - 10 + v421) << 0;
  l_bin2asc[lid43] = ((v430 < 10) ? '0' + v430 : 'a' - 10 + v430) << 8
                   | ((v431 < 10) ? '0' + v431 : 'a' - 10 + v431) << 0;

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

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

    append_0x80_2x4 (w0, w1, out_len);

    w3[2] = out_len * 8;

    u32 a = MD5M_A;
    u32 b = MD5M_B;
    u32 c = MD5M_C;
    u32 d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    const u32  w0_t = s[0];
    const u32  w1_t = s[1];
    const u32  w2_t = s[2];
    const u32  w3_t = s[3];
    const u32  w4_t = s[4];
    const u32  w5_t = s[5];
    const u32  w6_t = s[6];
    const u32  w7_t = s[7];

    const u32 w8_t = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    const u32 w9_t = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    const u32 wa_t = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    const u32 wb_t = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    const u32 wc_t = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    const u32 wd_t = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    const u32 we_t = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
                     | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    const u32 wf_t = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
                     | uint_to_hex_lower8 ((d >> 24) & 255) << 16;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

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

    const u32 r_a = a + MD5M_A;
    const u32 r_b = b + MD5M_B;
    const u32 r_c = c + MD5M_C;
    const u32 r_d = d + MD5M_D;

    a = r_a;
    b = r_b;
    c = r_c;
    d = r_d;

    MD5_STEP (MD5_Fo, a, b, c, d, r_00, MD5C00, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C01, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C02, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C03, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C04, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C05, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C06, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C07, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C08, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C09, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,       MD5C0a, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0b, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,       MD5C0c, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,       MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, r_14, MD5C0e, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,       MD5C0f, MD5S03);

    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C10, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C11, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, r_00, MD5C13, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C14, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C15, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C16, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C17, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, r_14, MD5C19, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1a, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1b, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,       MD5C1c, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,       MD5C1d, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,       MD5C1e, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,       MD5C1f, MD5S13);

    MD5_STEP0(MD5_H , a, b, c, d,       MD5C20, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C21, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, r_14, MD5C23, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C24, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C25, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C26, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C27, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, r_00, MD5C29, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C2a, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C2b, MD5S23);
    MD5_STEP0(MD5_H , a, b, c, d,       MD5C2c, MD5S20);
    MD5_STEP0(MD5_H , d, a, b, c,       MD5C2d, MD5S21);
    MD5_STEP0(MD5_H , c, d, a, b,       MD5C2e, MD5S22);
    MD5_STEP0(MD5_H , b, c, d, a,       MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, r_00, MD5C30, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, r_14, MD5C32, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C33, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C34, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C35, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C36, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C37, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C38, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,       MD5C39, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3a, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3b, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,       MD5C3c, MD5S30);

    if (allx ((a + r_a) != search[0])) continue;

    MD5_STEP0(MD5_I , d, a, b, c,       MD5C3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,       MD5C3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,       MD5C3f, MD5S33);

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    const u32 r0 = a;
    const u32 r1 = d;
    const u32 r2 = c;
    const u32 r3 = b;

    #include COMPARE_S
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m02810_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
