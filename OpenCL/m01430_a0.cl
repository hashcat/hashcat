/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA256_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 3
#define DGST_R1 7
#define DGST_R2 2
#define DGST_R3 6

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"
#include "include/rp_gpu.h"
#include "OpenCL/rp.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_m04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

    u32 w0_t2[4];
    u32 w1_t2[4];
    u32 w2_t2[4];
    u32 w3_t2[4];

    make_unicode (w0, w0_t2, w1_t2);
    make_unicode (w1, w2_t2, w3_t2);

    w0_t2[0] |= s0[0];
    w0_t2[1] |= s0[1];
    w0_t2[2] |= s0[2];
    w0_t2[3] |= s0[3];
    w1_t2[0] |= s1[0];
    w1_t2[1] |= s1[1];
    w1_t2[2] |= s1[2];
    w1_t2[3] |= s1[3];
    w2_t2[0] |= s2[0];
    w2_t2[1] |= s2[1];
    w2_t2[2] |= s2[2];
    w2_t2[3] |= s2[3];
    w3_t2[0] |= s3[0];
    w3_t2[1] |= s3[1];
    w3_t2[2] |= s3[2];
    w3_t2[3] |= s3[3];

    append_0x80_4x4 (w0_t2, w1_t2, w2_t2, w3_t2, out_salt_len);

    /**
     * sha256
     */

    u32 w0_t = swap32 (w0_t2[0]);
    u32 w1_t = swap32 (w0_t2[1]);
    u32 w2_t = swap32 (w0_t2[2]);
    u32 w3_t = swap32 (w0_t2[3]);
    u32 w4_t = swap32 (w1_t2[0]);
    u32 w5_t = swap32 (w1_t2[1]);
    u32 w6_t = swap32 (w1_t2[2]);
    u32 w7_t = swap32 (w1_t2[3]);
    u32 w8_t = swap32 (w2_t2[0]);
    u32 w9_t = swap32 (w2_t2[1]);
    u32 wa_t = swap32 (w2_t2[2]);
    u32 wb_t = swap32 (w2_t2[3]);
    u32 wc_t = swap32 (w3_t2[0]);
    u32 wd_t = swap32 (w3_t2[1]);
    u32 we_t = 0;
    u32 wf_t = out_salt_len * 8;

    u32 a = SHA256M_A;
    u32 b = SHA256M_B;
    u32 c = SHA256M_C;
    u32 d = SHA256M_D;
    u32 e = SHA256M_E;
    u32 f = SHA256M_F;
    u32 g = SHA256M_G;
    u32 h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);


    const u32 r0 = d;
    const u32 r1 = h;
    const u32 r2 = c;
    const u32 r3 = g;

    #include COMPARE_M
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_m08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_m16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_s04 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

    u32 w0_t2[4];
    u32 w1_t2[4];
    u32 w2_t2[4];
    u32 w3_t2[4];

    make_unicode (w0, w0_t2, w1_t2);
    make_unicode (w1, w2_t2, w3_t2);

    w0_t2[0] |= s0[0];
    w0_t2[1] |= s0[1];
    w0_t2[2] |= s0[2];
    w0_t2[3] |= s0[3];
    w1_t2[0] |= s1[0];
    w1_t2[1] |= s1[1];
    w1_t2[2] |= s1[2];
    w1_t2[3] |= s1[3];
    w2_t2[0] |= s2[0];
    w2_t2[1] |= s2[1];
    w2_t2[2] |= s2[2];
    w2_t2[3] |= s2[3];
    w3_t2[0] |= s3[0];
    w3_t2[1] |= s3[1];
    w3_t2[2] |= s3[2];
    w3_t2[3] |= s3[3];

    append_0x80_4x4 (w0_t2, w1_t2, w2_t2, w3_t2, out_salt_len);

    /**
     * sha256
     */

    u32 w0_t = swap32 (w0_t2[0]);
    u32 w1_t = swap32 (w0_t2[1]);
    u32 w2_t = swap32 (w0_t2[2]);
    u32 w3_t = swap32 (w0_t2[3]);
    u32 w4_t = swap32 (w1_t2[0]);
    u32 w5_t = swap32 (w1_t2[1]);
    u32 w6_t = swap32 (w1_t2[2]);
    u32 w7_t = swap32 (w1_t2[3]);
    u32 w8_t = swap32 (w2_t2[0]);
    u32 w9_t = swap32 (w2_t2[1]);
    u32 wa_t = swap32 (w2_t2[2]);
    u32 wb_t = swap32 (w2_t2[3]);
    u32 wc_t = swap32 (w3_t2[0]);
    u32 wd_t = swap32 (w3_t2[1]);
    u32 we_t = 0;
    u32 wf_t = out_salt_len * 8;

    u32 a = SHA256M_A;
    u32 b = SHA256M_B;
    u32 c = SHA256M_C;
    u32 d = SHA256M_D;
    u32 e = SHA256M_E;
    u32 f = SHA256M_F;
    u32 g = SHA256M_G;
    u32 h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);


    const u32 r0 = d;
    const u32 r1 = h;
    const u32 r2 = c;
    const u32 r3 = g;

    #include COMPARE_S
  }
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_s08 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void __attribute__((reqd_work_group_size (64, 1, 1))) m01430_s16 (__global pw_t *pws, __global gpu_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
