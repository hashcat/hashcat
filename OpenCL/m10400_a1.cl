/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#define _MD5_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#define DGST_R0 0
#define DGST_R1 1
#define DGST_R2 2
#define DGST_R3 3

#include "include/kernel_functions.c"
#include "OpenCL/types_ocl.c"
#include "OpenCL/common.c"

#define COMPARE_S "OpenCL/check_single_comp4.c"
#define COMPARE_M "OpenCL/check_multi_comp4.c"

__constant u32 padding[8] =
{
  0x5e4ebf28,
  0x418a754e,
  0x564e0064,
  0x0801faff,
  0xb6002e2e,
  0x803e68d0,
  0xfea90c2f,
  0x7a695364
};

typedef struct
{
  u8 S[256];

  u32 wtf_its_faster;

} RC4_KEY;

static void swap (__local RC4_KEY *rc4_key, const u8 i, const u8 j)
{
  u8 tmp;

  tmp           = rc4_key->S[i];
  rc4_key->S[i] = rc4_key->S[j];
  rc4_key->S[j] = tmp;
}

static void rc4_init_16 (__local RC4_KEY *rc4_key, const u32 data[4])
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  __local u32 *ptr = (__local u32 *) rc4_key->S;

  #pragma unroll
  for (u32 i = 0; i < 64; i++)
  {
    ptr[i] = v; v += a;
  }

  const u32 d0 = data[0] >>  0;
  const u32 d1 = data[0] >>  8;
  const u32 d2 = data[0] >> 16;
  const u32 d3 = data[0] >> 24;
  const u32 d4 = data[1] >>  0;

  u32 j = 0;

  #pragma unroll
  for (u32 i = 0; i < 255; i += 5)
  {
    j += rc4_key->S[i + 0] + d0; swap (rc4_key, i + 0, j);
    j += rc4_key->S[i + 1] + d1; swap (rc4_key, i + 1, j);
    j += rc4_key->S[i + 2] + d2; swap (rc4_key, i + 2, j);
    j += rc4_key->S[i + 3] + d3; swap (rc4_key, i + 3, j);
    j += rc4_key->S[i + 4] + d4; swap (rc4_key, i + 4, j);
  }

  j += rc4_key->S[255] + d0; swap (rc4_key, 255, j);
}

static u8 rc4_next_16 (__local RC4_KEY *rc4_key, u8 i, u8 j, __constant u32 *in, u32 out[4])
{
  #pragma unroll 4
  for (u32 k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u8 idx;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  0;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  8;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 16;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 24;

    out[k] = in[k] ^ xor4;
  }

  return j;
}

static void md5_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[4])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

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

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

__kernel void m10400_m04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * key
   */

  __local RC4_KEY rc4_keys[64];

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = pdf_bufs[salt_pos].o_buf[0];
  o_buf[1] = pdf_bufs[salt_pos].o_buf[1];
  o_buf[2] = pdf_bufs[salt_pos].o_buf[2];
  o_buf[3] = pdf_bufs[salt_pos].o_buf[3];
  o_buf[4] = pdf_bufs[salt_pos].o_buf[4];
  o_buf[5] = pdf_bufs[salt_pos].o_buf[5];
  o_buf[6] = pdf_bufs[salt_pos].o_buf[6];
  o_buf[7] = pdf_bufs[salt_pos].o_buf[7];

  u32 P = pdf_bufs[salt_pos].P;

  u32 id_buf[4];

  id_buf[0] = pdf_bufs[salt_pos].id_buf[0];
  id_buf[1] = pdf_bufs[salt_pos].id_buf[1];
  id_buf[2] = pdf_bufs[salt_pos].id_buf[2];
  id_buf[3] = pdf_bufs[salt_pos].id_buf[3];

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
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // max length supported by pdf11 is 32

    w0_t[0] = padding[0];
    w0_t[1] = padding[1];
    w0_t[2] = padding[2];
    w0_t[3] = padding[3];
    w1_t[0] = padding[4];
    w1_t[1] = padding[5];
    w1_t[2] = padding[6];
    w1_t[3] = padding[7];
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, pw_len);

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] |= w0[0];
    w0_t[1] |= w0[1];
    w0_t[2] |= w0[2];
    w0_t[3] |= w0[3];
    w1_t[0] |= w1[0];
    w1_t[1] |= w1[1];
    w1_t[2] |= w1[2];
    w1_t[3] |= w1[3];
    w2_t[0]  = o_buf[0];
    w2_t[1]  = o_buf[1];
    w2_t[2]  = o_buf[2];
    w2_t[3]  = o_buf[3];
    w3_t[0]  = o_buf[4];
    w3_t[1]  = o_buf[5];
    w3_t[2]  = o_buf[6];
    w3_t[3]  = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    u32 key[4];

    key[0] = digest[0];
    key[1] = digest[1] & 0xff;
    key[2] = 0;
    key[3] = 0;

    rc4_init_16 (rc4_key, key);

    u32 out[4];

    rc4_next_16 (rc4_key, 0, 0, padding, out);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #include COMPARE_M
  }
}

__kernel void m10400_m08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10400_m16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10400_s04 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * key
   */

  __local RC4_KEY rc4_keys[64];

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

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
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = pdf_bufs[salt_pos].o_buf[0];
  o_buf[1] = pdf_bufs[salt_pos].o_buf[1];
  o_buf[2] = pdf_bufs[salt_pos].o_buf[2];
  o_buf[3] = pdf_bufs[salt_pos].o_buf[3];
  o_buf[4] = pdf_bufs[salt_pos].o_buf[4];
  o_buf[5] = pdf_bufs[salt_pos].o_buf[5];
  o_buf[6] = pdf_bufs[salt_pos].o_buf[6];
  o_buf[7] = pdf_bufs[salt_pos].o_buf[7];

  u32 P = pdf_bufs[salt_pos].P;

  u32 id_buf[4];

  id_buf[0] = pdf_bufs[salt_pos].id_buf[0];
  id_buf[1] = pdf_bufs[salt_pos].id_buf[1];
  id_buf[2] = pdf_bufs[salt_pos].id_buf[2];
  id_buf[3] = pdf_bufs[salt_pos].id_buf[3];

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
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // max length supported by pdf11 is 32

    w0_t[0] = padding[0];
    w0_t[1] = padding[1];
    w0_t[2] = padding[2];
    w0_t[3] = padding[3];
    w1_t[0] = padding[4];
    w1_t[1] = padding[5];
    w1_t[2] = padding[6];
    w1_t[3] = padding[7];
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, pw_len);

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] |= w0[0];
    w0_t[1] |= w0[1];
    w0_t[2] |= w0[2];
    w0_t[3] |= w0[3];
    w1_t[0] |= w1[0];
    w1_t[1] |= w1[1];
    w1_t[2] |= w1[2];
    w1_t[3] |= w1[3];
    w2_t[0]  = o_buf[0];
    w2_t[1]  = o_buf[1];
    w2_t[2]  = o_buf[2];
    w2_t[3]  = o_buf[3];
    w3_t[0]  = o_buf[4];
    w3_t[1]  = o_buf[5];
    w3_t[2]  = o_buf[6];
    w3_t[3]  = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    u32 key[4];

    key[0] = digest[0];
    key[1] = digest[1] & 0xff;
    key[2] = 0;
    key[3] = 0;

    rc4_init_16 (rc4_key, key);

    u32 out[4];

    rc4_next_16 (rc4_key, 0, 0, padding, out);

    const u32 r0 = out[0];
    const u32 r1 = out[1];
    const u32 r2 = out[2];
    const u32 r3 = out[3];

    #include COMPARE_S
  }
}

__kernel void m10400_s08 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m10400_s16 (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global pdf_t *pdf_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
