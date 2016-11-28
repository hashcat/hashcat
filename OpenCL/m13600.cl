/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _ZIP2_

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"

#include "inc_types.cl"
#include "inc_common.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

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

static void hmac_sha1_pad (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, opad);
}

static void hmac_sha1_run (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5], u32 digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform (w0, w1, w2, w3, digest);
}

__kernel void m13600_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = swap32 (pws[gid].i[ 0]);
  w0[1] = swap32 (pws[gid].i[ 1]);
  w0[2] = swap32 (pws[gid].i[ 2]);
  w0[3] = swap32 (pws[gid].i[ 3]);

  u32 w1[4];

  w1[0] = swap32 (pws[gid].i[ 4]);
  w1[1] = swap32 (pws[gid].i[ 5]);
  w1[2] = swap32 (pws[gid].i[ 6]);
  w1[3] = swap32 (pws[gid].i[ 7]);

  u32 w2[4];

  w2[0] = swap32 (pws[gid].i[ 8]);
  w2[1] = swap32 (pws[gid].i[ 9]);
  w2[2] = swap32 (pws[gid].i[10]);
  w2[3] = swap32 (pws[gid].i[11]);

  u32 w3[4];

  w3[0] = swap32 (pws[gid].i[12]);
  w3[1] = swap32 (pws[gid].i[13]);
  w3[2] = swap32 (pws[gid].i[14]);
  w3[3] = swap32 (pws[gid].i[15]);

  /**
   * salt
   */

  const u32 salt_len = esalt_bufs[salt_pos].salt_len;

  u32 ipad[5];
  u32 opad[5];

  hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad[0] = ipad[0];
  tmps[gid].ipad[1] = ipad[1];
  tmps[gid].ipad[2] = ipad[2];
  tmps[gid].ipad[3] = ipad[3];
  tmps[gid].ipad[4] = ipad[4];

  tmps[gid].opad[0] = opad[0];
  tmps[gid].opad[1] = opad[1];
  tmps[gid].opad[2] = opad[2];
  tmps[gid].opad[3] = opad[3];
  tmps[gid].opad[4] = opad[4];

  const u32 mode = esalt_bufs[salt_pos].mode;

  u32 iter_start;
  u32 iter_stop;
  u32 count_start;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            count_start = 1;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            count_start = 2;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            count_start = 2;
            break;
  }

  for (u32 i = iter_start, j = count_start; i < iter_stop; i++, j++)
  {
    const u32 i5 = i * 5;

    u32 esalt_buf[16];

    esalt_buf[ 0] = swap32 (esalt_bufs[salt_pos].salt_buf[0]);
    esalt_buf[ 1] = swap32 (esalt_bufs[salt_pos].salt_buf[1]);
    esalt_buf[ 2] = swap32 (esalt_bufs[salt_pos].salt_buf[2]);
    esalt_buf[ 3] = swap32 (esalt_bufs[salt_pos].salt_buf[3]);
    esalt_buf[ 4] = 0;
    esalt_buf[ 5] = 0;
    esalt_buf[ 6] = 0;
    esalt_buf[ 7] = 0;
    esalt_buf[ 8] = 0;
    esalt_buf[ 9] = 0;
    esalt_buf[10] = 0;
    esalt_buf[11] = 0;
    esalt_buf[12] = 0;
    esalt_buf[13] = 0;
    esalt_buf[14] = 0;
    esalt_buf[15] = (64 + salt_len + 4) * 8;

    switch (mode)
    {
      case 1: esalt_buf[2] = j;
              esalt_buf[3] = 0x80000000;
              break;
      case 2: esalt_buf[3] = j;
              esalt_buf[4] = 0x80000000;
              break;
      case 3: esalt_buf[4] = j;
              esalt_buf[5] = 0x80000000;
              break;
    }

    u32 dgst[5];

    hmac_sha1_run (esalt_buf + 0, esalt_buf + 4, esalt_buf + 8, esalt_buf + 12, ipad, opad, dgst);

    tmps[gid].dgst[i5 + 0] = dgst[0];
    tmps[gid].dgst[i5 + 1] = dgst[1];
    tmps[gid].dgst[i5 + 2] = dgst[2];
    tmps[gid].dgst[i5 + 3] = dgst[3];
    tmps[gid].dgst[i5 + 4] = dgst[4];

    tmps[gid].out[i5 + 0] = dgst[0];
    tmps[gid].out[i5 + 1] = dgst[1];
    tmps[gid].out[i5 + 2] = dgst[2];
    tmps[gid].out[i5 + 3] = dgst[3];
    tmps[gid].out[i5 + 4] = dgst[4];
  }
}

__kernel void m13600_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 ipad[5];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];

  u32 opad[5];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];

  const u32 mode = esalt_bufs[salt_pos].mode;

  u32 iter_start;
  u32 iter_stop;
  u32 count_start;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            count_start = 1;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            count_start = 2;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            count_start = 2;
            break;
  }

  for (u32 i = iter_start, j = count_start; i < iter_stop; i++, j++)
  {
    const u32 i5 = i * 5;

    u32 dgst[5];

    dgst[0] = tmps[gid].dgst[i5 + 0];
    dgst[1] = tmps[gid].dgst[i5 + 1];
    dgst[2] = tmps[gid].dgst[i5 + 2];
    dgst[3] = tmps[gid].dgst[i5 + 3];
    dgst[4] = tmps[gid].dgst[i5 + 4];

    u32 out[5];

    out[0] = tmps[gid].out[i5 + 0];
    out[1] = tmps[gid].out[i5 + 1];
    out[2] = tmps[gid].out[i5 + 2];
    out[3] = tmps[gid].out[i5 + 3];
    out[4] = tmps[gid].out[i5 + 4];

    for (u32 k = 0; k < loop_cnt; k++)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    tmps[gid].dgst[i5 + 0] = dgst[0];
    tmps[gid].dgst[i5 + 1] = dgst[1];
    tmps[gid].dgst[i5 + 2] = dgst[2];
    tmps[gid].dgst[i5 + 3] = dgst[3];
    tmps[gid].dgst[i5 + 4] = dgst[4];

    tmps[gid].out[i5 + 0] = out[0];
    tmps[gid].out[i5 + 1] = out[1];
    tmps[gid].out[i5 + 2] = out[2];
    tmps[gid].out[i5 + 3] = out[3];
    tmps[gid].out[i5 + 4] = out[4];
  }
}

__kernel void m13600_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  u32 key[8] = { 0 };

  const u32 mode = esalt_bufs[salt_pos].mode;

  u32 iter_start;
  u32 iter_stop;

  switch (mode)
  {
    case 1: iter_start = 4;
            iter_stop  = 8;
            break;
    case 2: iter_start = 6;
            iter_stop  = 12;
            break;
    case 3: iter_start = 8;
            iter_stop  = 16;
            break;
  }

  u32 i, j;
  for (i = iter_start, j = 0; i < iter_stop; i++, j++)
  {
    key[j] = tmps[gid].out[i];
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = key[0];
  w0[1] = key[1];
  w0[2] = key[2];
  w0[3] = key[3];
  w1[0] = key[4];
  w1[1] = key[5];
  w1[2] = key[6];
  w1[3] = key[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  u32 ipad[5];
  u32 opad[5];

  hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

  int data_len = esalt_bufs[salt_pos].data_len;

  int data_left;
  int data_off;

  for (data_left = data_len, data_off = 0; data_left >= 56; data_left -= 64, data_off += 16)
  {
    w0[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  0]);
    w0[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  1]);
    w0[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  2]);
    w0[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  3]);
    w1[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  4]);
    w1[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  5]);
    w1[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  6]);
    w1[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  7]);
    w2[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  8]);
    w2[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  9]);
    w2[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 10]);
    w2[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 11]);
    w3[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 12]);
    w3[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 13]);
    w3[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 14]);
    w3[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 15]);

    sha1_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  0]);
  w0[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  1]);
  w0[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  2]);
  w0[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  3]);
  w1[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  4]);
  w1[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  5]);
  w1[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  6]);
  w1[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  7]);
  w2[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  8]);
  w2[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off +  9]);
  w2[2] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 10]);
  w2[3] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 11]);
  w3[0] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 12]);
  w3[1] = swap32 (esalt_bufs[salt_pos].data_buf[data_off + 13]);
  w3[2] = 0;
  w3[3] = (64 + data_len) * 8;

  u32 digest[5];

  hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

  const u32 r0 = swap32 (digest[0] & 0xffffffff);
  const u32 r1 = swap32 (digest[1] & 0xffffffff);
  const u32 r2 = swap32 (digest[2] & 0xffff0000);
  const u32 r3 = swap32 (digest[3] & 0x00000000);

  #define il_pos 0

  #include COMPARE_M
}
