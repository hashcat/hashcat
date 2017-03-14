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
#include "inc_cipher_serpent.cl"

#include "inc_truecrypt_crc32.cl"
#include "inc_truecrypt_xts.cl"

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

void hmac_sha256_pad (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[8], u32 opad[8])
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

  ipad[0] = SHA256M_A;
  ipad[1] = SHA256M_B;
  ipad[2] = SHA256M_C;
  ipad[3] = SHA256M_D;
  ipad[4] = SHA256M_E;
  ipad[5] = SHA256M_F;
  ipad[6] = SHA256M_G;
  ipad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, ipad);

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

  opad[0] = SHA256M_A;
  opad[1] = SHA256M_B;
  opad[2] = SHA256M_C;
  opad[3] = SHA256M_D;
  opad[4] = SHA256M_E;
  opad[5] = SHA256M_F;
  opad[6] = SHA256M_G;
  opad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, opad);
}

void hmac_sha256_run (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[8], u32 opad[8], u32 digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform (w0, w1, w2, w3, digest);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = digest[0];
  t0[1] = digest[1];
  t0[2] = digest[2];
  t0[3] = digest[3];
  t1[0] = digest[4];
  t1[1] = digest[5];
  t1[2] = digest[6];
  t1[3] = digest[7];
  t2[0] = 0x80000000;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;
  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform (t0, t1, t2, t3, digest);
}

void hmac_sha256_run2 (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 w4[4], u32 w5[4], u32 w6[4], u32 w7[4], u32 ipad[8], u32 opad[8], u32 digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform (w0, w1, w2, w3, digest);
  sha256_transform (w4, w5, w6, w7, digest);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = digest[0];
  t0[1] = digest[1];
  t0[2] = digest[2];
  t0[3] = digest[3];
  t1[0] = digest[4];
  t1[1] = digest[5];
  t1[2] = digest[6];
  t1[3] = digest[7];
  t2[0] = 0x80000000;
  t2[1] = 0;
  t2[2] = 0;
  t2[3] = 0;
  t3[0] = 0;
  t3[1] = 0;
  t3[2] = 0;
  t3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform (t0, t1, t2, t3, digest);
}

u32 u8add (const u32 a, const u32 b)
{
  const u32 a1 = (a >>  0) & 0xff;
  const u32 a2 = (a >>  8) & 0xff;
  const u32 a3 = (a >> 16) & 0xff;
  const u32 a4 = (a >> 24) & 0xff;

  const u32 b1 = (b >>  0) & 0xff;
  const u32 b2 = (b >>  8) & 0xff;
  const u32 b3 = (b >> 16) & 0xff;
  const u32 b4 = (b >> 24) & 0xff;

  const u32 r1 = (a1 + b1) & 0xff;
  const u32 r2 = (a2 + b2) & 0xff;
  const u32 r3 = (a3 + b3) & 0xff;
  const u32 r4 = (a4 + b4) & 0xff;

  const u32 r = r1 <<  0
              | r2 <<  8
              | r3 << 16
              | r4 << 24;

  return r;
}

__kernel void m13751_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];
  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];
  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * keyfile
   */

  w0[0] = u8add (w0[0], esalt_bufs[digests_offset].keyfile_buf[ 0]);
  w0[1] = u8add (w0[1], esalt_bufs[digests_offset].keyfile_buf[ 1]);
  w0[2] = u8add (w0[2], esalt_bufs[digests_offset].keyfile_buf[ 2]);
  w0[3] = u8add (w0[3], esalt_bufs[digests_offset].keyfile_buf[ 3]);
  w1[0] = u8add (w1[0], esalt_bufs[digests_offset].keyfile_buf[ 4]);
  w1[1] = u8add (w1[1], esalt_bufs[digests_offset].keyfile_buf[ 5]);
  w1[2] = u8add (w1[2], esalt_bufs[digests_offset].keyfile_buf[ 6]);
  w1[3] = u8add (w1[3], esalt_bufs[digests_offset].keyfile_buf[ 7]);
  w2[0] = u8add (w2[0], esalt_bufs[digests_offset].keyfile_buf[ 8]);
  w2[1] = u8add (w2[1], esalt_bufs[digests_offset].keyfile_buf[ 9]);
  w2[2] = u8add (w2[2], esalt_bufs[digests_offset].keyfile_buf[10]);
  w2[3] = u8add (w2[3], esalt_bufs[digests_offset].keyfile_buf[11]);
  w3[0] = u8add (w3[0], esalt_bufs[digests_offset].keyfile_buf[12]);
  w3[1] = u8add (w3[1], esalt_bufs[digests_offset].keyfile_buf[13]);
  w3[2] = u8add (w3[2], esalt_bufs[digests_offset].keyfile_buf[14]);
  w3[3] = u8add (w3[3], esalt_bufs[digests_offset].keyfile_buf[15]);

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

  /**
   * salt
   */

  u32 s0[4];
  u32 s1[4];
  u32 s2[4];
  u32 s3[4];
  u32 s4[4];
  u32 s5[4];
  u32 s6[4];
  u32 s7[4];

  s0[0] = swap32 (esalt_bufs[digests_offset].salt_buf[ 0]);
  s0[1] = swap32 (esalt_bufs[digests_offset].salt_buf[ 1]);
  s0[2] = swap32 (esalt_bufs[digests_offset].salt_buf[ 2]);
  s0[3] = swap32 (esalt_bufs[digests_offset].salt_buf[ 3]);
  s1[0] = swap32 (esalt_bufs[digests_offset].salt_buf[ 4]);
  s1[1] = swap32 (esalt_bufs[digests_offset].salt_buf[ 5]);
  s1[2] = swap32 (esalt_bufs[digests_offset].salt_buf[ 6]);
  s1[3] = swap32 (esalt_bufs[digests_offset].salt_buf[ 7]);
  s2[0] = swap32 (esalt_bufs[digests_offset].salt_buf[ 8]);
  s2[1] = swap32 (esalt_bufs[digests_offset].salt_buf[ 9]);
  s2[2] = swap32 (esalt_bufs[digests_offset].salt_buf[10]);
  s2[3] = swap32 (esalt_bufs[digests_offset].salt_buf[11]);
  s3[0] = swap32 (esalt_bufs[digests_offset].salt_buf[12]);
  s3[1] = swap32 (esalt_bufs[digests_offset].salt_buf[13]);
  s3[2] = swap32 (esalt_bufs[digests_offset].salt_buf[14]);
  s3[3] = swap32 (esalt_bufs[digests_offset].salt_buf[15]);
  s4[0] = 0;
  s4[1] = 0x80000000;
  s4[2] = 0;
  s4[3] = 0;
  s5[0] = 0;
  s5[1] = 0;
  s5[2] = 0;
  s5[3] = 0;
  s6[0] = 0;
  s6[1] = 0;
  s6[2] = 0;
  s6[3] = 0;
  s7[0] = 0;
  s7[1] = 0;
  s7[2] = 0;
  s7[3] = (64 + 64 + 4) * 8;

  u32 ipad[8];
  u32 opad[8];

  hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad[0] = ipad[0];
  tmps[gid].ipad[1] = ipad[1];
  tmps[gid].ipad[2] = ipad[2];
  tmps[gid].ipad[3] = ipad[3];
  tmps[gid].ipad[4] = ipad[4];
  tmps[gid].ipad[5] = ipad[5];
  tmps[gid].ipad[6] = ipad[6];
  tmps[gid].ipad[7] = ipad[7];

  tmps[gid].opad[0] = opad[0];
  tmps[gid].opad[1] = opad[1];
  tmps[gid].opad[2] = opad[2];
  tmps[gid].opad[3] = opad[3];
  tmps[gid].opad[4] = opad[4];
  tmps[gid].opad[5] = opad[5];
  tmps[gid].opad[6] = opad[6];
  tmps[gid].opad[7] = opad[7];

  for (u32 i = 0, j = 1; i < 16; i += 8, j += 1)
  {
    s4[0] = j;

    u32 dgst[8];

    hmac_sha256_run2 (s0, s1, s2, s3, s4, s5, s6, s7, ipad, opad, dgst);

    tmps[gid].dgst[i + 0] = dgst[0];
    tmps[gid].dgst[i + 1] = dgst[1];
    tmps[gid].dgst[i + 2] = dgst[2];
    tmps[gid].dgst[i + 3] = dgst[3];
    tmps[gid].dgst[i + 4] = dgst[4];
    tmps[gid].dgst[i + 5] = dgst[5];
    tmps[gid].dgst[i + 6] = dgst[6];
    tmps[gid].dgst[i + 7] = dgst[7];

    tmps[gid].out[i + 0] = dgst[0];
    tmps[gid].out[i + 1] = dgst[1];
    tmps[gid].out[i + 2] = dgst[2];
    tmps[gid].out[i + 3] = dgst[3];
    tmps[gid].out[i + 4] = dgst[4];
    tmps[gid].out[i + 5] = dgst[5];
    tmps[gid].out[i + 6] = dgst[6];
    tmps[gid].out[i + 7] = dgst[7];
  }
}

__kernel void m13751_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 ipad[8];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];
  ipad[5] = tmps[gid].ipad[5];
  ipad[6] = tmps[gid].ipad[6];
  ipad[7] = tmps[gid].ipad[7];

  u32 opad[8];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];
  opad[5] = tmps[gid].opad[5];
  opad[6] = tmps[gid].opad[6];
  opad[7] = tmps[gid].opad[7];

  for (u32 i = 0; i < 16; i += 8)
  {
    u32 dgst[8];

    dgst[0] = tmps[gid].dgst[i + 0];
    dgst[1] = tmps[gid].dgst[i + 1];
    dgst[2] = tmps[gid].dgst[i + 2];
    dgst[3] = tmps[gid].dgst[i + 3];
    dgst[4] = tmps[gid].dgst[i + 4];
    dgst[5] = tmps[gid].dgst[i + 5];
    dgst[6] = tmps[gid].dgst[i + 6];
    dgst[7] = tmps[gid].dgst[i + 7];

    u32 out[8];

    out[0] = tmps[gid].out[i + 0];
    out[1] = tmps[gid].out[i + 1];
    out[2] = tmps[gid].out[i + 2];
    out[3] = tmps[gid].out[i + 3];
    out[4] = tmps[gid].out[i + 4];
    out[5] = tmps[gid].out[i + 5];
    out[6] = tmps[gid].out[i + 6];
    out[7] = tmps[gid].out[i + 7];

    for (u32 j = 0; j < loop_cnt; j++)
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
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    tmps[gid].dgst[i + 0] = dgst[0];
    tmps[gid].dgst[i + 1] = dgst[1];
    tmps[gid].dgst[i + 2] = dgst[2];
    tmps[gid].dgst[i + 3] = dgst[3];
    tmps[gid].dgst[i + 4] = dgst[4];
    tmps[gid].dgst[i + 5] = dgst[5];
    tmps[gid].dgst[i + 6] = dgst[6];
    tmps[gid].dgst[i + 7] = dgst[7];

    tmps[gid].out[i + 0] = out[0];
    tmps[gid].out[i + 1] = out[1];
    tmps[gid].out[i + 2] = out[2];
    tmps[gid].out[i + 3] = out[3];
    tmps[gid].out[i + 4] = out[4];
    tmps[gid].out[i + 5] = out[5];
    tmps[gid].out[i + 6] = out[6];
    tmps[gid].out[i + 7] = out[7];
  }
}

__kernel void m13751_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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

  u32 ukey1[8];

  ukey1[0] = swap32 (tmps[gid].out[ 0]);
  ukey1[1] = swap32 (tmps[gid].out[ 1]);
  ukey1[2] = swap32 (tmps[gid].out[ 2]);
  ukey1[3] = swap32 (tmps[gid].out[ 3]);
  ukey1[4] = swap32 (tmps[gid].out[ 4]);
  ukey1[5] = swap32 (tmps[gid].out[ 5]);
  ukey1[6] = swap32 (tmps[gid].out[ 6]);
  ukey1[7] = swap32 (tmps[gid].out[ 7]);

  u32 ukey2[8];

  ukey2[0] = swap32 (tmps[gid].out[ 8]);
  ukey2[1] = swap32 (tmps[gid].out[ 9]);
  ukey2[2] = swap32 (tmps[gid].out[10]);
  ukey2[3] = swap32 (tmps[gid].out[11]);
  ukey2[4] = swap32 (tmps[gid].out[12]);
  ukey2[5] = swap32 (tmps[gid].out[13]);
  ukey2[6] = swap32 (tmps[gid].out[14]);
  ukey2[7] = swap32 (tmps[gid].out[15]);

  if (verify_header_aes (esalt_bufs, ukey1, ukey2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
  }

  if (verify_header_serpent (esalt_bufs, ukey1, ukey2) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
  }

  if (verify_header_twofish (esalt_bufs, ukey1, ukey2) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
  }
}
