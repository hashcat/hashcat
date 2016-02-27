/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA512_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 14
#define DGST_R1 15
#define DGST_R2 6
#define DGST_R3 7

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

__constant u64 k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

static void sha512_transform (const u64 w0[4], const u64 w1[4], const u64 w2[4], const u64 w3[4], u64 digest[8])
{
  u64 w0_t = w0[0];
  u64 w1_t = w0[1];
  u64 w2_t = w0[2];
  u64 w3_t = w0[3];
  u64 w4_t = w1[0];
  u64 w5_t = w1[1];
  u64 w6_t = w1[2];
  u64 w7_t = w1[3];
  u64 w8_t = w2[0];
  u64 w9_t = w2[1];
  u64 wa_t = w2[2];
  u64 wb_t = w2[3];
  u64 wc_t = w3[0];
  u64 wd_t = w3[1];
  u64 we_t = w3[2];
  u64 wf_t = w3[3];

  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  //#pragma unroll
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

static void hmac_sha512_pad (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u64 ipad[8], u64 opad[8])
{
  u64 w0_t[4];
  u64 w1_t[4];
  u64 w2_t[4];
  u64 w3_t[4];

  w0_t[0] = hl32_to_64 (w0[0], w0[1]) ^ 0x3636363636363636;
  w0_t[1] = hl32_to_64 (w0[2], w0[3]) ^ 0x3636363636363636;
  w0_t[2] = hl32_to_64 (w1[0], w1[1]) ^ 0x3636363636363636;
  w0_t[3] = hl32_to_64 (w1[2], w1[3]) ^ 0x3636363636363636;
  w1_t[0] = hl32_to_64 (w2[0], w2[1]) ^ 0x3636363636363636;
  w1_t[1] = hl32_to_64 (w2[2], w2[3]) ^ 0x3636363636363636;
  w1_t[2] = hl32_to_64 (w3[0], w3[1]) ^ 0x3636363636363636;
  w1_t[3] = hl32_to_64 (w3[2], w3[3]) ^ 0x3636363636363636;
  w2_t[0] =                                 0 ^ 0x3636363636363636;
  w2_t[1] =                                 0 ^ 0x3636363636363636;
  w2_t[2] =                                 0 ^ 0x3636363636363636;
  w2_t[3] =                                 0 ^ 0x3636363636363636;
  w3_t[0] =                                 0 ^ 0x3636363636363636;
  w3_t[1] =                                 0 ^ 0x3636363636363636;
  w3_t[2] =                                 0 ^ 0x3636363636363636;
  w3_t[3] =                                 0 ^ 0x3636363636363636;

  ipad[0] = SHA512M_A;
  ipad[1] = SHA512M_B;
  ipad[2] = SHA512M_C;
  ipad[3] = SHA512M_D;
  ipad[4] = SHA512M_E;
  ipad[5] = SHA512M_F;
  ipad[6] = SHA512M_G;
  ipad[7] = SHA512M_H;

  sha512_transform (w0_t, w1_t, w2_t, w3_t, ipad);

  w0_t[0] = hl32_to_64 (w0[0], w0[1]) ^ 0x5c5c5c5c5c5c5c5c;
  w0_t[1] = hl32_to_64 (w0[2], w0[3]) ^ 0x5c5c5c5c5c5c5c5c;
  w0_t[2] = hl32_to_64 (w1[0], w1[1]) ^ 0x5c5c5c5c5c5c5c5c;
  w0_t[3] = hl32_to_64 (w1[2], w1[3]) ^ 0x5c5c5c5c5c5c5c5c;
  w1_t[0] = hl32_to_64 (w2[0], w2[1]) ^ 0x5c5c5c5c5c5c5c5c;
  w1_t[1] = hl32_to_64 (w2[2], w2[3]) ^ 0x5c5c5c5c5c5c5c5c;
  w1_t[2] = hl32_to_64 (w3[0], w3[1]) ^ 0x5c5c5c5c5c5c5c5c;
  w1_t[3] = hl32_to_64 (w3[2], w3[3]) ^ 0x5c5c5c5c5c5c5c5c;
  w2_t[0] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w2_t[1] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w2_t[2] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w2_t[3] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w3_t[0] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w3_t[1] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w3_t[2] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;
  w3_t[3] =                                 0 ^ 0x5c5c5c5c5c5c5c5c;

  opad[0] = SHA512M_A;
  opad[1] = SHA512M_B;
  opad[2] = SHA512M_C;
  opad[3] = SHA512M_D;
  opad[4] = SHA512M_E;
  opad[5] = SHA512M_F;
  opad[6] = SHA512M_G;
  opad[7] = SHA512M_H;

  sha512_transform (w0_t, w1_t, w2_t, w3_t, opad);
}

static void hmac_sha512_run (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u64 ipad[8], u64 opad[8], u64 digest[8])
{
  u64 w0_t[4];
  u64 w1_t[4];
  u64 w2_t[4];
  u64 w3_t[4];

  w0_t[0] = hl32_to_64 (w0[0], w0[1]);
  w0_t[1] = hl32_to_64 (w0[2], w0[3]);
  w0_t[2] = hl32_to_64 (w1[0], w1[1]);
  w0_t[3] = hl32_to_64 (w1[2], w1[3]);
  w1_t[0] = hl32_to_64 (w2[0], w2[1]);
  w1_t[1] = hl32_to_64 (w2[2], w2[3]);
  w1_t[2] = hl32_to_64 (w3[0], w3[1]);
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = hl32_to_64 (w3[2], w3[3]);

  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = digest[0];
  w0_t[1] = digest[1];
  w0_t[2] = digest[2];
  w0_t[3] = digest[3];
  w1_t[0] = digest[4];
  w1_t[1] = digest[5];
  w1_t[2] = digest[6];
  w1_t[3] = digest[7];
  w2_t[0] = 0x8000000000000000;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform (w0_t, w1_t, w2_t, w3_t, digest);
}

__kernel void m01760_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];

  /**
   * pads
   */

  u32 w0_t[4];

  w0_t[0] = swap32 (salt_buf0[0]);
  w0_t[1] = swap32 (salt_buf0[1]);
  w0_t[2] = swap32 (salt_buf0[2]);
  w0_t[3] = swap32 (salt_buf0[3]);

  u32 w1_t[4];

  w1_t[0] = swap32 (salt_buf1[0]);
  w1_t[1] = swap32 (salt_buf1[1]);
  w1_t[2] = swap32 (salt_buf1[2]);
  w1_t[3] = swap32 (salt_buf1[3]);

  u32 w2_t[4];

  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;

  u32 w3_t[4];

  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  u64 ipad[8];
  u64 opad[8];

  hmac_sha512_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

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
    w3[2] = 0;
    w3[3] = 0;

    append_0x80_4x4 (w0, w1, w2, w3, pw_len);

    w0_t[0] = swap32 (w0[0]);
    w0_t[1] = swap32 (w0[1]);
    w0_t[2] = swap32 (w0[2]);
    w0_t[3] = swap32 (w0[3]);
    w1_t[0] = swap32 (w1[0]);
    w1_t[1] = swap32 (w1[1]);
    w1_t[2] = swap32 (w1[2]);
    w1_t[3] = swap32 (w1[3]);
    w2_t[0] = swap32 (w2[0]);
    w2_t[1] = swap32 (w2[1]);
    w2_t[2] = swap32 (w2[2]);
    w2_t[3] = swap32 (w2[3]);
    w3_t[0] = swap32 (w3[0]);
    w3_t[1] = swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = (128 + pw_len) * 8;

    u64 digest[8];

    hmac_sha512_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);


    const u32 r0 = l32_from_64 (digest[7]);
    const u32 r1 = h32_from_64 (digest[7]);
    const u32 r2 = l32_from_64 (digest[3]);
    const u32 r3 = h32_from_64 (digest[3]);

    #include COMPARE_M
  }
}

__kernel void m01760_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01760_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01760_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
    switch_buffer_by_offset_le (wordl0, wordl1, wordl2, wordl3, combs_buf[0].pw_len);
  }

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];

  /**
   * pads
   */

  u32 w0_t[4];

  w0_t[0] = swap32 (salt_buf0[0]);
  w0_t[1] = swap32 (salt_buf0[1]);
  w0_t[2] = swap32 (salt_buf0[2]);
  w0_t[3] = swap32 (salt_buf0[3]);

  u32 w1_t[4];

  w1_t[0] = swap32 (salt_buf1[0]);
  w1_t[1] = swap32 (salt_buf1[1]);
  w1_t[2] = swap32 (salt_buf1[2]);
  w1_t[3] = swap32 (salt_buf1[3]);

  u32 w2_t[4];

  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;

  u32 w3_t[4];

  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  u64 ipad[8];
  u64 opad[8];

  hmac_sha512_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

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
    w3[2] = 0;
    w3[3] = 0;

    append_0x80_4x4 (w0, w1, w2, w3, pw_len);

    w0_t[0] = swap32 (w0[0]);
    w0_t[1] = swap32 (w0[1]);
    w0_t[2] = swap32 (w0[2]);
    w0_t[3] = swap32 (w0[3]);
    w1_t[0] = swap32 (w1[0]);
    w1_t[1] = swap32 (w1[1]);
    w1_t[2] = swap32 (w1[2]);
    w1_t[3] = swap32 (w1[3]);
    w2_t[0] = swap32 (w2[0]);
    w2_t[1] = swap32 (w2[1]);
    w2_t[2] = swap32 (w2[2]);
    w2_t[3] = swap32 (w2[3]);
    w3_t[0] = swap32 (w3[0]);
    w3_t[1] = swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = (128 + pw_len) * 8;

    u64 digest[8];

    hmac_sha512_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);


    const u32 r0 = l32_from_64 (digest[7]);
    const u32 r1 = h32_from_64 (digest[7]);
    const u32 r2 = l32_from_64 (digest[3]);
    const u32 r3 = h32_from_64 (digest[3]);

    #include COMPARE_S
  }
}

__kernel void m01760_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m01760_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
