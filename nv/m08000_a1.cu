/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA256_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#ifdef  VLIW1
#define VECT_SIZE1
#endif

#ifdef  VLIW2
#define VECT_SIZE1
#endif

#define DGST_R0 3
#define DGST_R1 7
#define DGST_R2 2
#define DGST_R3 6

#include "include/kernel_functions.c"
#include "types_nv.c"
#include "common_nv.c"

#ifdef  VECT_SIZE1
#define VECT_COMPARE_S "check_single_vect1_comp4.c"
#define VECT_COMPARE_M "check_multi_vect1_comp4.c"
#endif

#ifdef  VECT_SIZE2
#define VECT_COMPARE_S "check_single_vect2_comp4.c"
#define VECT_COMPARE_M "check_multi_vect2_comp4.c"
#endif

__device__ static void sha256_transform (u32x digest[8], const u32x w[16])
{
  u32x w0_t = w[ 0];
  u32x w1_t = w[ 1];
  u32x w2_t = w[ 2];
  u32x w3_t = w[ 3];
  u32x w4_t = w[ 4];
  u32x w5_t = w[ 5];
  u32x w6_t = w[ 6];
  u32x w7_t = w[ 7];
  u32x w8_t = w[ 8];
  u32x w9_t = w[ 9];
  u32x wa_t = w[10];
  u32x wb_t = w[11];
  u32x wc_t = w[12];
  u32x wd_t = w[13];
  u32x we_t = w[14];
  u32x wf_t = w[15];

  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

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
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

__device__ __constant__ comb_t c_combs[1024];

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_m04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  u32x wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32x wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32x wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32x wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset (wordl0, wordl1, wordl2, wordl3, c_combs[0].pw_len);
  }

  /**
   * salt
   */

  const u32 salt_buf0 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 0]);
  const u32 salt_buf1 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 1]);
  const u32 salt_buf2 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 2]); // 0x80

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < combs_cnt; il_pos++)
  {
    u32 wordr0[4];
    u32 wordr1[4];
    u32 wordr2[4];
    u32 wordr3[4];

    wordr0[0] = c_combs[il_pos].i[0];
    wordr0[1] = c_combs[il_pos].i[1];
    wordr0[2] = c_combs[il_pos].i[2];
    wordr0[3] = c_combs[il_pos].i[3];
    wordr1[0] = c_combs[il_pos].i[4];
    wordr1[1] = c_combs[il_pos].i[5];
    wordr1[2] = c_combs[il_pos].i[6];
    wordr1[3] = c_combs[il_pos].i[7];
    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;
    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);

    make_unicode (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = swap_workaround (w0_t[0]);
    w_t[ 1] = swap_workaround (w0_t[1]);
    w_t[ 2] = swap_workaround (w0_t[2]);
    w_t[ 3] = swap_workaround (w0_t[3]);
    w_t[ 4] = swap_workaround (w1_t[0]);
    w_t[ 5] = swap_workaround (w1_t[1]);
    w_t[ 6] = swap_workaround (w1_t[2]);
    w_t[ 7] = swap_workaround (w1_t[3]);
    w_t[ 8] = swap_workaround (w2_t[0]);
    w_t[ 9] = swap_workaround (w2_t[1]);
    w_t[10] = swap_workaround (w2_t[2]);
    w_t[11] = swap_workaround (w2_t[3]);
    w_t[12] = swap_workaround (w3_t[0]);
    w_t[13] = swap_workaround (w3_t[1]);
    w_t[14] = swap_workaround (w3_t[2]);
    w_t[15] = swap_workaround (w3_t[3]);

    w_t[ 0] = w_t[ 0] >> 8;
    w_t[ 1] = w_t[ 1] >> 8;
    w_t[ 2] = w_t[ 2] >> 8;
    w_t[ 3] = w_t[ 3] >> 8;
    w_t[ 4] = w_t[ 4] >> 8;
    w_t[ 5] = w_t[ 5] >> 8;
    w_t[ 6] = w_t[ 6] >> 8;
    w_t[ 7] = w_t[ 7] >> 8;
    w_t[ 8] = w_t[ 8] >> 8;
    w_t[ 9] = w_t[ 9] >> 8;
    w_t[10] = w_t[10] >> 8;
    w_t[11] = w_t[11] >> 8;
    w_t[12] = w_t[12] >> 8;
    w_t[13] = w_t[13] >> 8;
    w_t[14] = w_t[14] >> 8;
    w_t[15] = w_t[15] >> 8;

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (digest, w_t); //   0 - 64

    w_t[ 0] = 0;
    w_t[ 1] = 0;
    w_t[ 2] = 0;
    w_t[ 3] = 0;
    w_t[ 4] = 0;
    w_t[ 5] = 0;
    w_t[ 6] = 0;
    w_t[ 7] = 0;
    w_t[ 8] = 0;
    w_t[ 9] = 0;
    w_t[10] = 0;
    w_t[11] = 0;
    w_t[12] = 0;
    w_t[13] = 0;
    w_t[14] = 0;
    w_t[15] = 0;

    sha256_transform (digest, w_t); //  64 - 128
    sha256_transform (digest, w_t); // 128 - 192
    sha256_transform (digest, w_t); // 192 - 256
    sha256_transform (digest, w_t); // 256 - 320
    sha256_transform (digest, w_t); // 320 - 384
    sha256_transform (digest, w_t); // 384 - 448

    w_t[15] =               0 | salt_buf0 >> 16;

    sha256_transform (digest, w_t); // 448 - 512

    w_t[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
    w_t[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
    w_t[ 2] = salt_buf2 << 16 | 0;
    w_t[15] = (510 + 8) * 8;

    sha256_transform (digest, w_t); // 512 - 576

    const u32x r0 = digest[3];
    const u32x r1 = digest[7];
    const u32x r2 = digest[2];
    const u32x r3 = digest[6];

    #include VECT_COMPARE_M
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_m08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_m16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_s04 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 combs_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  u32x wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32x wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32x wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32x wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset (wordl0, wordl1, wordl2, wordl3, c_combs[0].pw_len);
  }

  /**
   * salt
   */

  const u32 salt_buf0 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 0]);
  const u32 salt_buf1 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 1]);
  const u32 salt_buf2 = swap_workaround (salt_bufs[salt_pos].salt_buf[ 2]); // 0x80

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

  for (u32 il_pos = 0; il_pos < combs_cnt; il_pos++)
  {
    u32 wordr0[4];
    u32 wordr1[4];
    u32 wordr2[4];
    u32 wordr3[4];

    wordr0[0] = c_combs[il_pos].i[0];
    wordr0[1] = c_combs[il_pos].i[1];
    wordr0[2] = c_combs[il_pos].i[2];
    wordr0[3] = c_combs[il_pos].i[3];
    wordr1[0] = c_combs[il_pos].i[4];
    wordr1[1] = c_combs[il_pos].i[5];
    wordr1[2] = c_combs[il_pos].i[6];
    wordr1[3] = c_combs[il_pos].i[7];
    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;
    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);

    make_unicode (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = swap_workaround (w0_t[0]);
    w_t[ 1] = swap_workaround (w0_t[1]);
    w_t[ 2] = swap_workaround (w0_t[2]);
    w_t[ 3] = swap_workaround (w0_t[3]);
    w_t[ 4] = swap_workaround (w1_t[0]);
    w_t[ 5] = swap_workaround (w1_t[1]);
    w_t[ 6] = swap_workaround (w1_t[2]);
    w_t[ 7] = swap_workaround (w1_t[3]);
    w_t[ 8] = swap_workaround (w2_t[0]);
    w_t[ 9] = swap_workaround (w2_t[1]);
    w_t[10] = swap_workaround (w2_t[2]);
    w_t[11] = swap_workaround (w2_t[3]);
    w_t[12] = swap_workaround (w3_t[0]);
    w_t[13] = swap_workaround (w3_t[1]);
    w_t[14] = swap_workaround (w3_t[2]);
    w_t[15] = swap_workaround (w3_t[3]);

    w_t[ 0] = w_t[ 0] >> 8;
    w_t[ 1] = w_t[ 1] >> 8;
    w_t[ 2] = w_t[ 2] >> 8;
    w_t[ 3] = w_t[ 3] >> 8;
    w_t[ 4] = w_t[ 4] >> 8;
    w_t[ 5] = w_t[ 5] >> 8;
    w_t[ 6] = w_t[ 6] >> 8;
    w_t[ 7] = w_t[ 7] >> 8;
    w_t[ 8] = w_t[ 8] >> 8;
    w_t[ 9] = w_t[ 9] >> 8;
    w_t[10] = w_t[10] >> 8;
    w_t[11] = w_t[11] >> 8;
    w_t[12] = w_t[12] >> 8;
    w_t[13] = w_t[13] >> 8;
    w_t[14] = w_t[14] >> 8;
    w_t[15] = w_t[15] >> 8;

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (digest, w_t); //   0 - 64

    w_t[ 0] = 0;
    w_t[ 1] = 0;
    w_t[ 2] = 0;
    w_t[ 3] = 0;
    w_t[ 4] = 0;
    w_t[ 5] = 0;
    w_t[ 6] = 0;
    w_t[ 7] = 0;
    w_t[ 8] = 0;
    w_t[ 9] = 0;
    w_t[10] = 0;
    w_t[11] = 0;
    w_t[12] = 0;
    w_t[13] = 0;
    w_t[14] = 0;
    w_t[15] = 0;

    sha256_transform (digest, w_t); //  64 - 128
    sha256_transform (digest, w_t); // 128 - 192
    sha256_transform (digest, w_t); // 192 - 256
    sha256_transform (digest, w_t); // 256 - 320
    sha256_transform (digest, w_t); // 320 - 384
    sha256_transform (digest, w_t); // 384 - 448

    w_t[15] =               0 | salt_buf0 >> 16;

    sha256_transform (digest, w_t); // 448 - 512

    w_t[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
    w_t[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
    w_t[ 2] = salt_buf2 << 16 | 0;
    w_t[15] = (510 + 8) * 8;

    sha256_transform (digest, w_t); // 512 - 576

    const u32x r0 = digest[3];
    const u32x r1 = digest[7];
    const u32x r2 = digest[2];
    const u32x r3 = digest[6];

    #include VECT_COMPARE_S
  }
}

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_s08 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

extern "C" __global__ void __launch_bounds__ (256, 1) m08000_s16 (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, const void *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
