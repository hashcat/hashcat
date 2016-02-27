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

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

#define uint_to_hex_lower8_le(i) l_bin2asc[(i)]

static void sha1_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5])
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

__kernel void m08400_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * shared
   */

  __local u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    append_0x80_2x4 (wordl0, wordl1, pw_l_len);

    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 0]);
  salt_buf0[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 1]);
  salt_buf0[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 2]);
  salt_buf0[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 3]);

  u32 salt_buf1[4];

  salt_buf1[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 4]);
  salt_buf1[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 5]);
  salt_buf1[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 6]);
  salt_buf1[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 7]);

  u32 salt_buf2[4];

  salt_buf2[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 8]);
  salt_buf2[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 9]);
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      append_0x80_2x4 (wordr0, wordr1, pw_r_len);

      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    u32 w1[4];

    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32 w2[4];

    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];

    u32 w3[4];

    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32 w0_t[4];

    w0_t[0] = swap32 (w0[0]);
    w0_t[1] = swap32 (w0[1]);
    w0_t[2] = swap32 (w0[2]);
    w0_t[3] = swap32 (w0[3]);

    u32 w1_t[4];

    w1_t[0] = swap32 (w1[0]);
    w1_t[1] = swap32 (w1[1]);
    w1_t[2] = swap32 (w1[2]);
    w1_t[3] = swap32 (w1[3]);

    u32 w2_t[4];

    w2_t[0] = swap32 (w2[0]);
    w2_t[1] = swap32 (w2[1]);
    w2_t[2] = swap32 (w2[2]);
    w2_t[3] = swap32 (w2[3]);

    u32 w3_t[4];

    w3_t[0] = swap32 (w3[0]);
    w3_t[1] = swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = pw_len * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 80 * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 80 * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    const u32 r0 = digest[3];
    const u32 r1 = digest[4];
    const u32 r2 = digest[2];
    const u32 r3 = digest[1];

    #include COMPARE_M
  }
}

__kernel void m08400_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m08400_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m08400_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * shared
   */

  __local u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32 wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32 wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32 wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len;

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    append_0x80_2x4 (wordl0, wordl1, pw_l_len);

    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 0]);
  salt_buf0[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 1]);
  salt_buf0[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 2]);
  salt_buf0[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 3]);

  u32 salt_buf1[4];

  salt_buf1[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 4]);
  salt_buf1[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 5]);
  salt_buf1[2] = swap32 (salt_bufs[salt_pos].salt_buf[ 6]);
  salt_buf1[3] = swap32 (salt_bufs[salt_pos].salt_buf[ 7]);

  u32 salt_buf2[4];

  salt_buf2[0] = swap32 (salt_bufs[salt_pos].salt_buf[ 8]);
  salt_buf2[1] = swap32 (salt_bufs[salt_pos].salt_buf[ 9]);
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;

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

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    const u32 pw_len = pw_l_len + pw_r_len;

    u32 wordr0[4];

    wordr0[0] = combs_buf[il_pos].i[0];
    wordr0[1] = combs_buf[il_pos].i[1];
    wordr0[2] = combs_buf[il_pos].i[2];
    wordr0[3] = combs_buf[il_pos].i[3];

    u32 wordr1[4];

    wordr1[0] = combs_buf[il_pos].i[4];
    wordr1[1] = combs_buf[il_pos].i[5];
    wordr1[2] = combs_buf[il_pos].i[6];
    wordr1[3] = combs_buf[il_pos].i[7];

    u32 wordr2[4];

    wordr2[0] = 0;
    wordr2[1] = 0;
    wordr2[2] = 0;
    wordr2[3] = 0;

    u32 wordr3[4];

    wordr3[0] = 0;
    wordr3[1] = 0;
    wordr3[2] = 0;
    wordr3[3] = 0;

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      append_0x80_2x4 (wordr0, wordr1, pw_r_len);

      switch_buffer_by_offset_le (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }

    u32 w0[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    u32 w1[4];

    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    u32 w2[4];

    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];

    u32 w3[4];

    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32 w0_t[4];

    w0_t[0] = swap32 (w0[0]);
    w0_t[1] = swap32 (w0[1]);
    w0_t[2] = swap32 (w0[2]);
    w0_t[3] = swap32 (w0[3]);

    u32 w1_t[4];

    w1_t[0] = swap32 (w1[0]);
    w1_t[1] = swap32 (w1[1]);
    w1_t[2] = swap32 (w1[2]);
    w1_t[3] = swap32 (w1[3]);

    u32 w2_t[4];

    w2_t[0] = swap32 (w2[0]);
    w2_t[1] = swap32 (w2[1]);
    w2_t[2] = swap32 (w2[2]);
    w2_t[3] = swap32 (w2[3]);

    u32 w3_t[4];

    w3_t[0] = swap32 (w3[0]);
    w3_t[1] = swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = pw_len * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (salt_len + 40) * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w2_t[3] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w3_t[0] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w3_t[1] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w3_t[2] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w3_t[3] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w1_t[0] = 0x80000000;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (salt_len + 40) * 8;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    const u32 r0 = digest[3];
    const u32 r1 = digest[4];
    const u32 r2 = digest[2];
    const u32 r3 = digest[1];

    #include COMPARE_S
  }
}

__kernel void m08400_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m08400_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
