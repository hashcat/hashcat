/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"

void AES256_ExpandKey (u32 *userkey, u32 *rek, __local u32 *s_te0, __local u32 *s_te1, __local u32 *s_te2, __local u32 *s_te3, __local u32 *s_te4)
{
  rek[0] = userkey[0];
  rek[1] = userkey[1];
  rek[2] = userkey[2];
  rek[3] = userkey[3];
  rek[4] = userkey[4];
  rek[5] = userkey[5];
  rek[6] = userkey[6];
  rek[7] = userkey[7];

  int i;
  int j;

  i = 0;
  j = 0;

  u32 run = 1;

  while (run)
  {
    u32 temp = rek[j +  7];

    rek[j +  8] = rek[j +  0]
           ^ (s_te2[(temp >> 16) & 0xff] & 0xff000000)
           ^ (s_te3[(temp >>  8) & 0xff] & 0x00ff0000)
           ^ (s_te0[(temp >>  0) & 0xff] & 0x0000ff00)
           ^ (s_te1[(temp >> 24) & 0xff] & 0x000000ff)
           ^ rcon[i];

    rek[j +  9] = rek[j +  1] ^ rek[j +  8];
    rek[j + 10] = rek[j +  2] ^ rek[j +  9];
    rek[j + 11] = rek[j +  3] ^ rek[j + 10];

    if (++i == 7)
    {
      run = 0;
      continue;
    }

    temp = rek[j + 11];

    rek[j + 12] = rek[j +  4]
           ^ (s_te2[(temp >> 24) & 0xff] & 0xff000000)
           ^ (s_te3[(temp >> 16) & 0xff] & 0x00ff0000)
           ^ (s_te0[(temp >>  8) & 0xff] & 0x0000ff00)
           ^ (s_te1[(temp >>  0) & 0xff] & 0x000000ff);

    rek[j + 13] = rek[j +  5] ^ rek[j + 12];
    rek[j + 14] = rek[j +  6] ^ rek[j + 13];
    rek[j + 15] = rek[j +  7] ^ rek[j + 14];

    j += 8;
  }
}

void AES256_InvertKey (u32 *rdk, __local u32 *s_td0, __local u32 *s_td1, __local u32 *s_td2, __local u32 *s_td3, __local u32 *s_td4, __local u32 *s_te0, __local u32 *s_te1, __local u32 *s_te2, __local u32 *s_te3, __local u32 *s_te4)
{
  for (u32 i = 0, j = 56; i < 28; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

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

void AES256_decrypt (const u32 *in, u32 *out, const u32 *rdk, __local u32 *s_td0, __local u32 *s_td1, __local u32 *s_td2, __local u32 *s_td3, __local u32 *s_td4)
{
  u32 s0 = in[0] ^ rdk[0];
  u32 s1 = in[1] ^ rdk[1];
  u32 s2 = in[2] ^ rdk[2];
  u32 s3 = in[3] ^ rdk[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[ 4];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[ 5];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[ 6];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[ 7];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[ 8];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[ 9];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[10];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[11];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[12];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[13];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[14];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[15];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[16];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[17];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[18];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[19];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[20];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[21];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[22];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[23];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[24];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[25];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[26];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[27];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[28];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[29];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[30];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[31];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[32];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[33];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[34];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[35];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[36];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[37];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[38];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[39];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[40];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[41];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[42];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[43];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[44];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[45];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[46];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[47];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ rdk[48];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ rdk[49];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ rdk[50];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ rdk[51];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ rdk[52];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ rdk[53];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ rdk[54];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ rdk[55];

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

void hmac_sha512_run_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x w4[4], u32x w5[4], u32x w6[4], u32x w7[4], u64x ipad[8], u64x opad[8], u64x digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

__kernel void m11300_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global bitcoin_wallet_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global bitcoin_wallet_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_update_global_swap (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha512_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
  tmps[gid].dgst[5] = ctx.h[5];
  tmps[gid].dgst[6] = ctx.h[6];
  tmps[gid].dgst[7] = ctx.h[7];
}

__kernel void m11300_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global bitcoin_wallet_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global bitcoin_wallet_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x t0 = pack64v (tmps, dgst, gid, 0);
  u64x t1 = pack64v (tmps, dgst, gid, 1);
  u64x t2 = pack64v (tmps, dgst, gid, 2);
  u64x t3 = pack64v (tmps, dgst, gid, 3);
  u64x t4 = pack64v (tmps, dgst, gid, 4);
  u64x t5 = pack64v (tmps, dgst, gid, 5);
  u64x t6 = pack64v (tmps, dgst, gid, 6);
  u64x t7 = pack64v (tmps, dgst, gid, 7);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  w0[0] = 0;
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
  w3[3] = 0;
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 64 * 8;

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    w0[0] = h32_from_64 (t0);
    w0[1] = l32_from_64 (t0);
    w0[2] = h32_from_64 (t1);
    w0[3] = l32_from_64 (t1);
    w1[0] = h32_from_64 (t2);
    w1[1] = l32_from_64 (t2);
    w1[2] = h32_from_64 (t3);
    w1[3] = l32_from_64 (t3);
    w2[0] = h32_from_64 (t4);
    w2[1] = l32_from_64 (t4);
    w2[2] = h32_from_64 (t5);
    w2[3] = l32_from_64 (t5);
    w3[0] = h32_from_64 (t6);
    w3[1] = l32_from_64 (t6);
    w3[2] = h32_from_64 (t7);
    w3[3] = l32_from_64 (t7);

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

    t0 = digest[0];
    t1 = digest[1];
    t2 = digest[2];
    t3 = digest[3];
    t4 = digest[4];
    t5 = digest[5];
    t6 = digest[6];
    t7 = digest[7];
  }

  unpack64v (tmps, dgst, gid, 0, t0);
  unpack64v (tmps, dgst, gid, 1, t1);
  unpack64v (tmps, dgst, gid, 2, t2);
  unpack64v (tmps, dgst, gid, 3, t3);
  unpack64v (tmps, dgst, gid, 4, t4);
  unpack64v (tmps, dgst, gid, 5, t5);
  unpack64v (tmps, dgst, gid, 6, t6);
  unpack64v (tmps, dgst, gid, 7, t7);
}

__kernel void m11300_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global bitcoin_wallet_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global bitcoin_wallet_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * aes shared
   */

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

  if (gid >= gid_max) return;

  /**
   * real code
   */

  u64 dgst[8];

  dgst[0] = tmps[gid].dgst[0];
  dgst[1] = tmps[gid].dgst[1];
  dgst[2] = tmps[gid].dgst[2];
  dgst[3] = tmps[gid].dgst[3];
  dgst[4] = tmps[gid].dgst[4];
  dgst[5] = tmps[gid].dgst[5];
  dgst[6] = tmps[gid].dgst[6];
  dgst[7] = tmps[gid].dgst[7];

  u32 key[8];

  key[0] = h32_from_64 (dgst[0]);
  key[1] = l32_from_64 (dgst[0]);
  key[2] = h32_from_64 (dgst[1]);
  key[3] = l32_from_64 (dgst[1]);
  key[4] = h32_from_64 (dgst[2]);
  key[5] = l32_from_64 (dgst[2]);
  key[6] = h32_from_64 (dgst[3]);
  key[7] = l32_from_64 (dgst[3]);

  u32 iv[4];

  iv[0] = h32_from_64 (dgst[4]);
  iv[1] = l32_from_64 (dgst[4]);
  iv[2] = h32_from_64 (dgst[5]);
  iv[3] = l32_from_64 (dgst[5]);

  #define KEYLEN 60

  u32 rk[KEYLEN];

  AES256_ExpandKey (key, rk, s_te0, s_te1, s_te2, s_te3, s_te4);

  AES256_InvertKey (rk, s_td0, s_td1, s_td2, s_td3, s_td4, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 out[4];

  for (u32 i = 0; i < esalt_bufs[digests_offset].cry_master_len; i += 16)
  {
    u32 data[4];

    data[0] = swap32 (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 0]);
    data[1] = swap32 (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 1]);
    data[2] = swap32 (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 2]);
    data[3] = swap32 (esalt_bufs[digests_offset].cry_master_buf[(i / 4) + 3]);

    AES256_decrypt (data, out, rk, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];
  }

  if ((out[0] == 0x10101010)
   && (out[1] == 0x10101010)
   && (out[2] == 0x10101010)
   && (out[3] == 0x10101010))
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0);
    }
  }
}
