/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#include "inc_cipher_aes.cl"
#include "inc_cipher_twofish.cl"

void AES256_ExpandKey (u32 *userkey, u32 *rek, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  rek[0] = userkey[0];
  rek[1] = userkey[1];
  rek[2] = userkey[2];
  rek[3] = userkey[3];
  rek[4] = userkey[4];
  rek[5] = userkey[5];
  rek[6] = userkey[6];
  rek[7] = userkey[7];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0, j = 0; i < 7; i += 1, j += 8)
  {
    const u32 temp1 = rek[j + 7];

    rek[j +  8] = rek[j + 0]
                ^ (s_te2[(temp1 >> 16) & 0xff] & 0xff000000)
                ^ (s_te3[(temp1 >>  8) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp1 >>  0) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp1 >> 24) & 0xff] & 0x000000ff)
                ^ rcon[i];
    rek[j +  9] = rek[j + 1] ^ rek[j +  8];
    rek[j + 10] = rek[j + 2] ^ rek[j +  9];
    rek[j + 11] = rek[j + 3] ^ rek[j + 10];

    if (i == 6) continue;

    const u32 temp2 = rek[j + 11];

    rek[j + 12] = rek[j + 4]
                ^ (s_te2[(temp2 >> 24) & 0xff] & 0xff000000)
                ^ (s_te3[(temp2 >> 16) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp2 >>  8) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp2 >>  0) & 0xff] & 0x000000ff);
    rek[j + 13] = rek[j + 5] ^ rek[j + 12];
    rek[j + 14] = rek[j + 6] ^ rek[j + 13];
    rek[j + 15] = rek[j + 7] ^ rek[j + 14];
  }
}

void AES256_InvertKey (u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0, j = 56; i < 28; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 1, j = 4; i < 14; i += 1, j += 4)
  {
    rdk[j + 0] =
      s_td0[s_te1[(rdk[j + 0] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 0] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 0] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 0] >>  0) & 0xff] & 0xff];

    rdk[j + 1] =
      s_td0[s_te1[(rdk[j + 1] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 1] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 1] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 1] >>  0) & 0xff] & 0xff];

    rdk[j + 2] =
      s_td0[s_te1[(rdk[j + 2] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 2] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 2] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 2] >>  0) & 0xff] & 0xff];

    rdk[j + 3] =
      s_td0[s_te1[(rdk[j + 3] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 3] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 3] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 3] >>  0) & 0xff] & 0xff];
  }
}

void AES256_decrypt (const u32 *in, u32 *out, const u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 t0 = in[0] ^ rdk[0];
  u32 t1 = in[1] ^ rdk[1];
  u32 t2 = in[2] ^ rdk[2];
  u32 t3 = in[3] ^ rdk[3];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 4; i < 56; i += 4)
  {
    const uchar4 x0 = as_uchar4 (t0);
    const uchar4 x1 = as_uchar4 (t1);
    const uchar4 x2 = as_uchar4 (t2);
    const uchar4 x3 = as_uchar4 (t3);

    t0 = s_td0[x0.s3] ^ s_td1[x3.s2] ^ s_td2[x2.s1] ^ s_td3[x1.s0] ^ rdk[i + 0];
    t1 = s_td0[x1.s3] ^ s_td1[x0.s2] ^ s_td2[x3.s1] ^ s_td3[x2.s0] ^ rdk[i + 1];
    t2 = s_td0[x2.s3] ^ s_td1[x1.s2] ^ s_td2[x0.s1] ^ s_td3[x3.s0] ^ rdk[i + 2];
    t3 = s_td0[x3.s3] ^ s_td1[x2.s2] ^ s_td2[x1.s1] ^ s_td3[x0.s0] ^ rdk[i + 3];
  }

  out[0] = (s_td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[56];

  out[1] = (s_td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[57];

  out[2] = (s_td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[58];

  out[3] = (s_td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[59];
}

void AES256_encrypt (const u32 *in, u32 *out, const u32 *rek, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 t0 = in[0] ^ rek[0];
  u32 t1 = in[1] ^ rek[1];
  u32 t2 = in[2] ^ rek[2];
  u32 t3 = in[3] ^ rek[3];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 4; i < 56; i += 4)
  {
    const uchar4 x0 = as_uchar4 (t0);
    const uchar4 x1 = as_uchar4 (t1);
    const uchar4 x2 = as_uchar4 (t2);
    const uchar4 x3 = as_uchar4 (t3);

    t0 = s_te0[x0.s3] ^ s_te1[x1.s2] ^ s_te2[x2.s1] ^ s_te3[x3.s0] ^ rek[i + 0];
    t1 = s_te0[x1.s3] ^ s_te1[x2.s2] ^ s_te2[x3.s1] ^ s_te3[x0.s0] ^ rek[i + 1];
    t2 = s_te0[x2.s3] ^ s_te1[x3.s2] ^ s_te2[x0.s1] ^ s_te3[x1.s0] ^ rek[i + 2];
    t3 = s_te0[x3.s3] ^ s_te1[x0.s2] ^ s_te2[x1.s1] ^ s_te3[x2.s0] ^ rek[i + 3];
  }

  out[0] = (s_te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rek[56];

  out[1] = (s_te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rek[57];

  out[2] = (s_te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rek[58];

  out[3] = (s_te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rek[59];
}

__constant u32a k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

void sha256_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[8])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

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

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
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

__kernel void m13400_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global keepass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global keepass_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  append_0x80_4x4 (w0, w1, w2, w3, pw_len);

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);

  w3[3] = pw_len * 8;

  /**
   * main
   */

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  if (esalt_bufs[digests_offset].version == 2 && esalt_bufs[digests_offset].keyfile_len == 0)
  {
    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];

    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];

    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;

    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 32 * 8;

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, digest);
  }

  if (esalt_bufs[digests_offset].keyfile_len != 0)
  {
    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];

    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];

    w2[0] = esalt_bufs[digests_offset].keyfile[0];
    w2[1] = esalt_bufs[digests_offset].keyfile[1];
    w2[2] = esalt_bufs[digests_offset].keyfile[2];
    w2[3] = esalt_bufs[digests_offset].keyfile[3];

    w3[0] = esalt_bufs[digests_offset].keyfile[4];
    w3[1] = esalt_bufs[digests_offset].keyfile[5];
    w3[3] = esalt_bufs[digests_offset].keyfile[7];
    w3[2] = esalt_bufs[digests_offset].keyfile[6];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, digest);

    w0[0] = 0x80000000;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;

    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;

    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 64 * 8;

    sha256_transform (w0, w1, w2, w3, digest);
  }

  tmps[gid].tmp_digest[0] = digest[0];
  tmps[gid].tmp_digest[1] = digest[1];
  tmps[gid].tmp_digest[2] = digest[2];
  tmps[gid].tmp_digest[3] = digest[3];
  tmps[gid].tmp_digest[4] = digest[4];
  tmps[gid].tmp_digest[5] = digest[5];
  tmps[gid].tmp_digest[6] = digest[6];
  tmps[gid].tmp_digest[7] = digest[7];
}

__kernel void m13400_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global keepass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global keepass_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /* Construct AES key */

  u32 key[8];

  key[0] = esalt_bufs[digests_offset].transf_random_seed[0];
  key[1] = esalt_bufs[digests_offset].transf_random_seed[1];
  key[2] = esalt_bufs[digests_offset].transf_random_seed[2];
  key[3] = esalt_bufs[digests_offset].transf_random_seed[3];
  key[4] = esalt_bufs[digests_offset].transf_random_seed[4];
  key[5] = esalt_bufs[digests_offset].transf_random_seed[5];
  key[6] = esalt_bufs[digests_offset].transf_random_seed[6];
  key[7] = esalt_bufs[digests_offset].transf_random_seed[7];

  #define KEYLEN 60

  u32 rk[KEYLEN];

  AES256_ExpandKey (key, rk, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 data0[4];
  u32 data1[4];

  data0[0] = tmps[gid].tmp_digest[0];
  data0[1] = tmps[gid].tmp_digest[1];
  data0[2] = tmps[gid].tmp_digest[2];
  data0[3] = tmps[gid].tmp_digest[3];
  data1[0] = tmps[gid].tmp_digest[4];
  data1[1] = tmps[gid].tmp_digest[5];
  data1[2] = tmps[gid].tmp_digest[6];
  data1[3] = tmps[gid].tmp_digest[7];

  for (u32 i = 0; i < loop_cnt; i++)
  {
    AES256_encrypt (data0, data0, rk, s_te0, s_te1, s_te2, s_te3, s_te4);
    AES256_encrypt (data1, data1, rk, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  tmps[gid].tmp_digest[0] = data0[0];
  tmps[gid].tmp_digest[1] = data0[1];
  tmps[gid].tmp_digest[2] = data0[2];
  tmps[gid].tmp_digest[3] = data0[3];
  tmps[gid].tmp_digest[4] = data1[0];
  tmps[gid].tmp_digest[5] = data1[1];
  tmps[gid].tmp_digest[6] = data1[2];
  tmps[gid].tmp_digest[7] = data1[3];
}

__kernel void m13400_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global keepass_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global keepass_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /* hash output... */
  u32 w0[4];

  w0[0] = tmps[gid].tmp_digest[0];
  w0[1] = tmps[gid].tmp_digest[1];
  w0[2] = tmps[gid].tmp_digest[2];
  w0[3] = tmps[gid].tmp_digest[3];

  u32 w1[4];

  w1[0] = tmps[gid].tmp_digest[4];
  w1[1] = tmps[gid].tmp_digest[5];
  w1[2] = tmps[gid].tmp_digest[6];
  w1[3] = tmps[gid].tmp_digest[7];

  u32 w2[4];

  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 32 * 8;

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  /* ...then hash final_random_seed | output */
  if (esalt_bufs[digests_offset].version == 1)
  {
    u32 final_random_seed[4];

    final_random_seed[0] = esalt_bufs[digests_offset].final_random_seed[0];
    final_random_seed[1] = esalt_bufs[digests_offset].final_random_seed[1];
    final_random_seed[2] = esalt_bufs[digests_offset].final_random_seed[2];
    final_random_seed[3] = esalt_bufs[digests_offset].final_random_seed[3];

    w0[0] = final_random_seed[0];
    w0[1] = final_random_seed[1];
    w0[2] = final_random_seed[2];
    w0[3] = final_random_seed[3];
    w1[0] = digest[0];
    w1[1] = digest[1];
    w1[2] = digest[2];
    w1[3] = digest[3];
    w2[0] = digest[4];
    w2[1] = digest[5];
    w2[2] = digest[6];
    w2[3] = digest[7];
    w3[0] = 0x80000000;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 48 * 8;

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, digest);
  }
  else
  {
    /* merkle-damgard implementation */
    u32 final_random_seed[8];

    final_random_seed[0] = esalt_bufs[digests_offset].final_random_seed[0];
    final_random_seed[1] = esalt_bufs[digests_offset].final_random_seed[1];
    final_random_seed[2] = esalt_bufs[digests_offset].final_random_seed[2];
    final_random_seed[3] = esalt_bufs[digests_offset].final_random_seed[3];
    final_random_seed[4] = esalt_bufs[digests_offset].final_random_seed[4];
    final_random_seed[5] = esalt_bufs[digests_offset].final_random_seed[5];
    final_random_seed[6] = esalt_bufs[digests_offset].final_random_seed[6];
    final_random_seed[7] = esalt_bufs[digests_offset].final_random_seed[7];

    w0[0] = final_random_seed[0];
    w0[1] = final_random_seed[1];
    w0[2] = final_random_seed[2];
    w0[3] = final_random_seed[3];
    w1[0] = final_random_seed[4];
    w1[1] = final_random_seed[5];
    w1[2] = final_random_seed[6];
    w1[3] = final_random_seed[7];
    w2[0] = digest[0];
    w2[1] = digest[1];
    w2[2] = digest[2];
    w2[3] = digest[3];
    w3[0] = digest[4];
    w3[1] = digest[5];
    w3[2] = digest[6];
    w3[3] = digest[7];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, digest);

    w0[0] = 0x80000000;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 64 * 8;

    sha256_transform (w0, w1, w2, w3, digest);
  }

  // at this point we have to distinguish between the different keypass versions

  u32 iv[4];

  iv[0] = esalt_bufs[digests_offset].enc_iv[0];
  iv[1] = esalt_bufs[digests_offset].enc_iv[1];
  iv[2] = esalt_bufs[digests_offset].enc_iv[2];
  iv[3] = esalt_bufs[digests_offset].enc_iv[3];

  u32 out[8];

  if (esalt_bufs[digests_offset].version == 1)
  {
    if (esalt_bufs[digests_offset].algorithm == 1)
    {
      /* Construct final Twofish key */
      u32 sk[4];
      u32 lk[40];

      digest[0] = swap32 (digest[0]);
      digest[1] = swap32 (digest[1]);
      digest[2] = swap32 (digest[2]);
      digest[3] = swap32 (digest[3]);
      digest[4] = swap32 (digest[4]);
      digest[5] = swap32 (digest[5]);
      digest[6] = swap32 (digest[6]);
      digest[7] = swap32 (digest[7]);

      twofish256_set_key (sk, lk, digest);

      iv[0] = swap32 (iv[0]);
      iv[1] = swap32 (iv[1]);
      iv[2] = swap32 (iv[2]);
      iv[3] = swap32 (iv[3]);

      u32 wx[16];

      u32 final_digest[8];

      final_digest[0] = SHA256M_A;
      final_digest[1] = SHA256M_B;
      final_digest[2] = SHA256M_C;
      final_digest[3] = SHA256M_D;
      final_digest[4] = SHA256M_E;
      final_digest[5] = SHA256M_F;
      final_digest[6] = SHA256M_G;
      final_digest[7] = SHA256M_H;

      u32 contents_len = esalt_bufs[digests_offset].contents_len;

      u32 contents_pos;
      u32 contents_off;

      // process (decrypt and hash) the buffer with the biggest steps possible.

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 64; contents_pos += 64, contents_off += 16)
      {
        for (u32 se = 0; se < 16; se += 4)
        {
          u32 data[4];

          data[0] = swap32 (esalt_bufs[digests_offset].contents[contents_off + se + 0]);
          data[1] = swap32 (esalt_bufs[digests_offset].contents[contents_off + se + 1]);
          data[2] = swap32 (esalt_bufs[digests_offset].contents[contents_off + se + 2]);
          data[3] = swap32 (esalt_bufs[digests_offset].contents[contents_off + se + 3]);

          u32 out[4];

          twofish256_decrypt (sk, lk, data, out);

          out[0] ^= iv[0];
          out[1] ^= iv[1];
          out[2] ^= iv[2];
          out[3] ^= iv[3];

          wx[se + 0] = swap32 (out[0]);
          wx[se + 1] = swap32 (out[1]);
          wx[se + 2] = swap32 (out[2]);
          wx[se + 3] = swap32 (out[3]);

          iv[0] = data[0];
          iv[1] = data[1];
          iv[2] = data[2];
          iv[3] = data[3];
        }

        sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);
      }

      // we've reached the final (or prefinal) block for hashing. this depends on the final length which we don't know at this point.
      // attention, this is not the final block for decrypt
      // since we don't know the final length, we simply set the entire block to zero, this will make the processing easier

      wx[ 0] = 0;
      wx[ 1] = 0;
      wx[ 2] = 0;
      wx[ 3] = 0;
      wx[ 4] = 0;
      wx[ 5] = 0;
      wx[ 6] = 0;
      wx[ 7] = 0;
      wx[ 8] = 0;
      wx[ 9] = 0;
      wx[10] = 0;
      wx[11] = 0;
      wx[12] = 0;
      wx[13] = 0;
      wx[14] = 0;
      wx[15] = 0;

      u32 wx_off;

      for (wx_off = 0; contents_pos < contents_len - 16; wx_off += 4, contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 0]);
        data[1] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 1]);
        data[2] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 2]);
        data[3] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 3]);

        u32 out[4];

        twofish256_decrypt (sk, lk, data, out);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        wx[wx_off + 0] = swap32 (out[0]);
        wx[wx_off + 1] = swap32 (out[1]);
        wx[wx_off + 2] = swap32 (out[2]);
        wx[wx_off + 3] = swap32 (out[3]);

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 0]);
      data[1] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 1]);
      data[2] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 2]);
      data[3] = swap32 (esalt_bufs[digests_offset].contents[contents_off + 3]);

      u32 out[4];

      twofish256_decrypt (sk, lk, data, out);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // now we can access the pad byte

      const u32 pad_byte = out[3] >> 24;

      const u32 real_len = esalt_bufs[digests_offset].contents_len - pad_byte;

      // we need to clear the buffer of the padding data

      truncate_block (out, 16 - pad_byte);

      // it's also a good point to push our 0x80

      append_0x80_1x4 (out, 16 - pad_byte);

      // now we can save it

      wx[wx_off + 0] = swap32 (out[0]);
      wx[wx_off + 1] = swap32 (out[1]);
      wx[wx_off + 2] = swap32 (out[2]);
      wx[wx_off + 3] = swap32 (out[3]);

      // since we were informed about real length so late we have
      // to check a final branch for hashing

      if ((real_len & 0x3f) >= 56)
      {
        sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);

        wx[ 0] = 0;
        wx[ 1] = 0;
        wx[ 2] = 0;
        wx[ 3] = 0;
        wx[ 4] = 0;
        wx[ 5] = 0;
        wx[ 6] = 0;
        wx[ 7] = 0;
        wx[ 8] = 0;
        wx[ 9] = 0;
        wx[10] = 0;
        wx[11] = 0;
        wx[12] = 0;
        wx[13] = 0;
        wx[14] = 0;
        wx[15] = 0;
      }

      wx[15] = real_len * 8;

      sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);

      #define il_pos 0

      if ( esalt_bufs[digests_offset].contents_hash[0] == final_digest[0]
        && esalt_bufs[digests_offset].contents_hash[1] == final_digest[1]
        && esalt_bufs[digests_offset].contents_hash[2] == final_digest[2]
        && esalt_bufs[digests_offset].contents_hash[3] == final_digest[3]
        && esalt_bufs[digests_offset].contents_hash[4] == final_digest[4]
        && esalt_bufs[digests_offset].contents_hash[5] == final_digest[5]
        && esalt_bufs[digests_offset].contents_hash[6] == final_digest[6]
        && esalt_bufs[digests_offset].contents_hash[7] == final_digest[7])
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
        }
    }
    else
    {
      /* Construct final AES key */
      #define KEYLEN 60

      u32 final_rk[KEYLEN];

      AES256_ExpandKey (digest, final_rk, s_te0, s_te1, s_te2, s_te3, s_te4);

      AES256_InvertKey (final_rk, s_td0, s_td1, s_td2, s_td3, s_td4, s_te0, s_te1, s_te2, s_te3, s_te4);

      u32 wx[16];

      u32 final_digest[8];

      final_digest[0] = SHA256M_A;
      final_digest[1] = SHA256M_B;
      final_digest[2] = SHA256M_C;
      final_digest[3] = SHA256M_D;
      final_digest[4] = SHA256M_E;
      final_digest[5] = SHA256M_F;
      final_digest[6] = SHA256M_G;
      final_digest[7] = SHA256M_H;

      u32 contents_len = esalt_bufs[digests_offset].contents_len;

      u32 contents_pos;
      u32 contents_off;

      // process (decrypt and hash) the buffer with the biggest steps possible.

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 64; contents_pos += 64, contents_off += 16)
      {
        for (u32 se = 0; se < 16; se += 4)
        {
          u32 data[4];

          data[0] = esalt_bufs[digests_offset].contents[contents_off + se + 0];
          data[1] = esalt_bufs[digests_offset].contents[contents_off + se + 1];
          data[2] = esalt_bufs[digests_offset].contents[contents_off + se + 2];
          data[3] = esalt_bufs[digests_offset].contents[contents_off + se + 3];

          u32 out[4];

          AES256_decrypt (data, out, final_rk, s_td0, s_td1, s_td2, s_td3, s_td4);

          out[0] ^= iv[0];
          out[1] ^= iv[1];
          out[2] ^= iv[2];
          out[3] ^= iv[3];

          wx[se + 0] = out[0];
          wx[se + 1] = out[1];
          wx[se + 2] = out[2];
          wx[se + 3] = out[3];

          iv[0] = data[0];
          iv[1] = data[1];
          iv[2] = data[2];
          iv[3] = data[3];
        }

        sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);
      }

      // we've reached the final (or prefinal) block for hashing. this depends on the final length which we don't know at this point.
      // attention, this is not the final block for decrypt
      // since we don't know the final length, we simply set the entire block to zero, this will make the processing easier

      wx[ 0] = 0;
      wx[ 1] = 0;
      wx[ 2] = 0;
      wx[ 3] = 0;
      wx[ 4] = 0;
      wx[ 5] = 0;
      wx[ 6] = 0;
      wx[ 7] = 0;
      wx[ 8] = 0;
      wx[ 9] = 0;
      wx[10] = 0;
      wx[11] = 0;
      wx[12] = 0;
      wx[13] = 0;
      wx[14] = 0;
      wx[15] = 0;

      u32 wx_off;

      for (wx_off = 0; contents_pos < contents_len - 16; wx_off += 4, contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
        data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
        data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
        data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

        u32 out[4];

        AES256_decrypt (data, out, final_rk, s_td0, s_td1, s_td2, s_td3, s_td4);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        wx[wx_off + 0] = out[0];
        wx[wx_off + 1] = out[1];
        wx[wx_off + 2] = out[2];
        wx[wx_off + 3] = out[3];

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
      data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
      data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
      data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

      u32 out[4];

      AES256_decrypt (data, out, final_rk, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // now we can access the pad byte

      out[0] = swap32 (out[0]);
      out[1] = swap32 (out[1]);
      out[2] = swap32 (out[2]);
      out[3] = swap32 (out[3]);

      const u32 pad_byte = out[3] >> 24;

      const u32 real_len = esalt_bufs[digests_offset].contents_len - pad_byte;

      // we need to clear the buffer of the padding data

      truncate_block (out, 16 - pad_byte);

      // it's also a good point to push our 0x80

      append_0x80_1x4 (out, 16 - pad_byte);

      // now we can save it

      wx[wx_off + 0] = swap32 (out[0]);
      wx[wx_off + 1] = swap32 (out[1]);
      wx[wx_off + 2] = swap32 (out[2]);
      wx[wx_off + 3] = swap32 (out[3]);

      // since we were informed about real length so late we have
      // to check a final branch for hashing

      if ((real_len & 0x3f) >= 56)
      {
        sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);

        wx[ 0] = 0;
        wx[ 1] = 0;
        wx[ 2] = 0;
        wx[ 3] = 0;
        wx[ 4] = 0;
        wx[ 5] = 0;
        wx[ 6] = 0;
        wx[ 7] = 0;
        wx[ 8] = 0;
        wx[ 9] = 0;
        wx[10] = 0;
        wx[11] = 0;
        wx[12] = 0;
        wx[13] = 0;
        wx[14] = 0;
        wx[15] = 0;
      }

      wx[15] = real_len * 8;

      sha256_transform (&wx[0], &wx[4], &wx[8], &wx[12], final_digest);

      #define il_pos 0

      if ( esalt_bufs[digests_offset].contents_hash[0] == final_digest[0]
        && esalt_bufs[digests_offset].contents_hash[1] == final_digest[1]
        && esalt_bufs[digests_offset].contents_hash[2] == final_digest[2]
        && esalt_bufs[digests_offset].contents_hash[3] == final_digest[3]
        && esalt_bufs[digests_offset].contents_hash[4] == final_digest[4]
        && esalt_bufs[digests_offset].contents_hash[5] == final_digest[5]
        && esalt_bufs[digests_offset].contents_hash[6] == final_digest[6]
        && esalt_bufs[digests_offset].contents_hash[7] == final_digest[7])
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
        }
    }
  }
  else
  {
    /* Construct final AES key */
    #define KEYLEN 60

    u32 final_rk[KEYLEN];

    AES256_ExpandKey (digest, final_rk, s_te0, s_te1, s_te2, s_te3, s_te4);

    AES256_InvertKey (final_rk, s_td0, s_td1, s_td2, s_td3, s_td4, s_te0, s_te1, s_te2, s_te3, s_te4);

    u32 contents_hash[4];

    contents_hash[0] = esalt_bufs[digests_offset].contents_hash[0];
    contents_hash[1] = esalt_bufs[digests_offset].contents_hash[1];
    contents_hash[2] = esalt_bufs[digests_offset].contents_hash[2];
    contents_hash[3] = esalt_bufs[digests_offset].contents_hash[3];

    AES256_decrypt (contents_hash, out, final_rk, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    /* We get rid of last 16 bytes */

    #define il_pos 0

    if ( esalt_bufs[digests_offset].expected_bytes[0] == out[0]
      && esalt_bufs[digests_offset].expected_bytes[1] == out[1]
      && esalt_bufs[digests_offset].expected_bytes[2] == out[2]
      && esalt_bufs[digests_offset].expected_bytes[3] == out[3])
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
      }
  }
}
