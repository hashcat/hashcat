/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_blake2b.h"

DECLSPEC u64 blake2b_rot16_S (const u64 a)
{
  #if defined IS_NV

  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = hc_byte_perm_S (in.v32.b, in.v32.a, 0x1076);
  out.v32.b = hc_byte_perm_S (in.v32.b, in.v32.a, 0x5432);

  return out.v64;

  #elif (defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1

  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = hc_byte_perm_S (in.v32.b, in.v32.a, 0x01000706);
  out.v32.b = hc_byte_perm_S (in.v32.b, in.v32.a, 0x05040302);

  return out.v64;

  #else

  return hc_rotr64_S (a, 16);

  #endif
}

DECLSPEC u64x blake2b_rot16 (const u64x a)
{
  u64x r;

  #if VECT_SIZE == 1
  r = blake2b_rot16_S (a);
  #endif

  #if VECT_SIZE >= 2
  r.s0 = blake2b_rot16_S (a.s0);
  r.s1 = blake2b_rot16_S (a.s1);
  #endif

  #if VECT_SIZE >= 4
  r.s2 = blake2b_rot16_S (a.s2);
  r.s3 = blake2b_rot16_S (a.s3);
  #endif

  #if VECT_SIZE >= 8
  r.s4 = blake2b_rot16_S (a.s4);
  r.s5 = blake2b_rot16_S (a.s5);
  r.s6 = blake2b_rot16_S (a.s6);
  r.s7 = blake2b_rot16_S (a.s7);
  #endif

  #if VECT_SIZE >= 16
  r.s8 = blake2b_rot16_S (a.s8);
  r.s9 = blake2b_rot16_S (a.s9);
  r.sa = blake2b_rot16_S (a.sa);
  r.sb = blake2b_rot16_S (a.sb);
  r.sc = blake2b_rot16_S (a.sc);
  r.sd = blake2b_rot16_S (a.sd);
  r.se = blake2b_rot16_S (a.se);
  r.sf = blake2b_rot16_S (a.sf);
  #endif

  return r;
}

DECLSPEC u64 blake2b_rot24_S (const u64 a)
{
  #if defined IS_NV

  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = hc_byte_perm_S (in.v32.b, in.v32.a, 0x2107);
  out.v32.b = hc_byte_perm_S (in.v32.b, in.v32.a, 0x6543);

  return out.v64;

  #elif (defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1

  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = hc_byte_perm_S (in.v32.b, in.v32.a, 0x02010007);
  out.v32.b = hc_byte_perm_S (in.v32.b, in.v32.a, 0x06050403);

  return out.v64;

  #else

  return hc_rotr64_S (a, 24);

  #endif
}

DECLSPEC u64x blake2b_rot24 (const u64x a)
{
  u64x r;

  #if VECT_SIZE == 1
  r = blake2b_rot24_S (a);
  #endif

  #if VECT_SIZE >= 2
  r.s0 = blake2b_rot24_S (a.s0);
  r.s1 = blake2b_rot24_S (a.s1);
  #endif

  #if VECT_SIZE >= 4
  r.s2 = blake2b_rot24_S (a.s2);
  r.s3 = blake2b_rot24_S (a.s3);
  #endif

  #if VECT_SIZE >= 8
  r.s4 = blake2b_rot24_S (a.s4);
  r.s5 = blake2b_rot24_S (a.s5);
  r.s6 = blake2b_rot24_S (a.s6);
  r.s7 = blake2b_rot24_S (a.s7);
  #endif

  #if VECT_SIZE >= 16
  r.s8 = blake2b_rot24_S (a.s8);
  r.s9 = blake2b_rot24_S (a.s9);
  r.sa = blake2b_rot24_S (a.sa);
  r.sb = blake2b_rot24_S (a.sb);
  r.sc = blake2b_rot24_S (a.sc);
  r.sd = blake2b_rot24_S (a.sd);
  r.se = blake2b_rot24_S (a.se);
  r.sf = blake2b_rot24_S (a.sf);
  #endif

  return r;
}

DECLSPEC u64 blake2b_rot32_S (const u64 a)
{
  vconv64_t in;

  in.v64 = a;

  vconv64_t out;

  out.v32.a = in.v32.b;
  out.v32.b = in.v32.a;

  return out.v64;
}

DECLSPEC u64x blake2b_rot32 (const u64x a)
{
  u64x r;

  #if VECT_SIZE == 1
  r = blake2b_rot32_S (a);
  #endif

  #if VECT_SIZE >= 2
  r.s0 = blake2b_rot32_S (a.s0);
  r.s1 = blake2b_rot32_S (a.s1);
  #endif

  #if VECT_SIZE >= 4
  r.s2 = blake2b_rot32_S (a.s2);
  r.s3 = blake2b_rot32_S (a.s3);
  #endif

  #if VECT_SIZE >= 8
  r.s4 = blake2b_rot32_S (a.s4);
  r.s5 = blake2b_rot32_S (a.s5);
  r.s6 = blake2b_rot32_S (a.s6);
  r.s7 = blake2b_rot32_S (a.s7);
  #endif

  #if VECT_SIZE >= 16
  r.s8 = blake2b_rot32_S (a.s8);
  r.s9 = blake2b_rot32_S (a.s9);
  r.sa = blake2b_rot32_S (a.sa);
  r.sb = blake2b_rot32_S (a.sb);
  r.sc = blake2b_rot32_S (a.sc);
  r.sd = blake2b_rot32_S (a.sd);
  r.se = blake2b_rot32_S (a.se);
  r.sf = blake2b_rot32_S (a.sf);
  #endif

  return r;
}

DECLSPEC void blake2b_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const int len, const u64 f0)
{
  const u64 t0 = hl32_to_64_S (0, len);

  u64 v[16];

  v[ 0] = h[0];
  v[ 1] = h[1];
  v[ 2] = h[2];
  v[ 3] = h[3];
  v[ 4] = h[4];
  v[ 5] = h[5];
  v[ 6] = h[6];
  v[ 7] = h[7];
  v[ 8] = BLAKE2B_IV_00;
  v[ 9] = BLAKE2B_IV_01;
  v[10] = BLAKE2B_IV_02;
  v[11] = BLAKE2B_IV_03;
  v[12] = BLAKE2B_IV_04 ^ t0;
  v[13] = BLAKE2B_IV_05; // ^ t1;
  v[14] = BLAKE2B_IV_06 ^ f0;
  v[15] = BLAKE2B_IV_07; // ^ f1;

  BLAKE2B_ROUND ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
  BLAKE2B_ROUND (11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
  BLAKE2B_ROUND ( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
  BLAKE2B_ROUND ( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
  BLAKE2B_ROUND ( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);
  BLAKE2B_ROUND (12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11);
  BLAKE2B_ROUND (13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10);
  BLAKE2B_ROUND ( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5);
  BLAKE2B_ROUND (10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0);
  BLAKE2B_ROUND ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);

  h[0] = h[0] ^ v[0] ^ v[ 8];
  h[1] = h[1] ^ v[1] ^ v[ 9];
  h[2] = h[2] ^ v[2] ^ v[10];
  h[3] = h[3] ^ v[3] ^ v[11];
  h[4] = h[4] ^ v[4] ^ v[12];
  h[5] = h[5] ^ v[5] ^ v[13];
  h[6] = h[6] ^ v[6] ^ v[14];
  h[7] = h[7] ^ v[7] ^ v[15];
}

DECLSPEC void blake2b_init (PRIVATE_AS blake2b_ctx_t *ctx)
{
  ctx->h[0] = BLAKE2B_IV_00 ^ 0x01010040; // default output length: 0x40 = 64 bytes
  ctx->h[1] = BLAKE2B_IV_01;
  ctx->h[2] = BLAKE2B_IV_02;
  ctx->h[3] = BLAKE2B_IV_03;
  ctx->h[4] = BLAKE2B_IV_04;
  ctx->h[5] = BLAKE2B_IV_05;
  ctx->h[6] = BLAKE2B_IV_06;
  ctx->h[7] = BLAKE2B_IV_07;

  ctx->m[ 0] = 0;
  ctx->m[ 1] = 0;
  ctx->m[ 2] = 0;
  ctx->m[ 3] = 0;
  ctx->m[ 4] = 0;
  ctx->m[ 5] = 0;
  ctx->m[ 6] = 0;
  ctx->m[ 7] = 0;
  ctx->m[ 8] = 0;
  ctx->m[ 9] = 0;
  ctx->m[10] = 0;
  ctx->m[11] = 0;
  ctx->m[12] = 0;
  ctx->m[13] = 0;
  ctx->m[14] = 0;
  ctx->m[15] = 0;

  ctx->len = 0;
}

DECLSPEC void blake2b_update_128 (PRIVATE_AS blake2b_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 127;

  if (pos == 0)
  {
    if (ctx->len > 0) // if new block (pos == 0) AND the (old) len is not zero => transform
    {
      blake2b_transform (ctx->h, ctx->m, ctx->len, BLAKE2B_UPDATE);
    }

    ctx->m[ 0] = hl32_to_64_S (w0[1], w0[0]);
    ctx->m[ 1] = hl32_to_64_S (w0[3], w0[2]);
    ctx->m[ 2] = hl32_to_64_S (w1[1], w1[0]);
    ctx->m[ 3] = hl32_to_64_S (w1[3], w1[2]);
    ctx->m[ 4] = hl32_to_64_S (w2[1], w2[0]);
    ctx->m[ 5] = hl32_to_64_S (w2[3], w2[2]);
    ctx->m[ 6] = hl32_to_64_S (w3[1], w3[0]);
    ctx->m[ 7] = hl32_to_64_S (w3[3], w3[2]);
    ctx->m[ 8] = hl32_to_64_S (w4[1], w4[0]);
    ctx->m[ 9] = hl32_to_64_S (w4[3], w4[2]);
    ctx->m[10] = hl32_to_64_S (w5[1], w5[0]);
    ctx->m[11] = hl32_to_64_S (w5[3], w5[2]);
    ctx->m[12] = hl32_to_64_S (w6[1], w6[0]);
    ctx->m[13] = hl32_to_64_S (w6[3], w6[2]);
    ctx->m[14] = hl32_to_64_S (w7[1], w7[0]);
    ctx->m[15] = hl32_to_64_S (w7[3], w7[2]);
  }
  else
  {
    if ((pos + len) <= 128)
    {
      switch_buffer_by_offset_8x4_le_S (w0, w1, w2, w3, w4, w5, w6, w7, pos);

      ctx->m[ 0] |= hl32_to_64_S (w0[1], w0[0]);
      ctx->m[ 1] |= hl32_to_64_S (w0[3], w0[2]);
      ctx->m[ 2] |= hl32_to_64_S (w1[1], w1[0]);
      ctx->m[ 3] |= hl32_to_64_S (w1[3], w1[2]);
      ctx->m[ 4] |= hl32_to_64_S (w2[1], w2[0]);
      ctx->m[ 5] |= hl32_to_64_S (w2[3], w2[2]);
      ctx->m[ 6] |= hl32_to_64_S (w3[1], w3[0]);
      ctx->m[ 7] |= hl32_to_64_S (w3[3], w3[2]);
      ctx->m[ 8] |= hl32_to_64_S (w4[1], w4[0]);
      ctx->m[ 9] |= hl32_to_64_S (w4[3], w4[2]);
      ctx->m[10] |= hl32_to_64_S (w5[1], w5[0]);
      ctx->m[11] |= hl32_to_64_S (w5[3], w5[2]);
      ctx->m[12] |= hl32_to_64_S (w6[1], w6[0]);
      ctx->m[13] |= hl32_to_64_S (w6[3], w6[2]);
      ctx->m[14] |= hl32_to_64_S (w7[1], w7[0]);
      ctx->m[15] |= hl32_to_64_S (w7[3], w7[2]);
    }
    else
    {
      u32 c0[4] = { 0 };
      u32 c1[4] = { 0 };
      u32 c2[4] = { 0 };
      u32 c3[4] = { 0 };
      u32 c4[4] = { 0 };
      u32 c5[4] = { 0 };
      u32 c6[4] = { 0 };
      u32 c7[4] = { 0 };

      switch_buffer_by_offset_8x4_carry_le_S (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

      ctx->m[ 0] |= hl32_to_64_S (w0[1], w0[0]);
      ctx->m[ 1] |= hl32_to_64_S (w0[3], w0[2]);
      ctx->m[ 2] |= hl32_to_64_S (w1[1], w1[0]);
      ctx->m[ 3] |= hl32_to_64_S (w1[3], w1[2]);
      ctx->m[ 4] |= hl32_to_64_S (w2[1], w2[0]);
      ctx->m[ 5] |= hl32_to_64_S (w2[3], w2[2]);
      ctx->m[ 6] |= hl32_to_64_S (w3[1], w3[0]);
      ctx->m[ 7] |= hl32_to_64_S (w3[3], w3[2]);
      ctx->m[ 8] |= hl32_to_64_S (w4[1], w4[0]);
      ctx->m[ 9] |= hl32_to_64_S (w4[3], w4[2]);
      ctx->m[10] |= hl32_to_64_S (w5[1], w5[0]);
      ctx->m[11] |= hl32_to_64_S (w5[3], w5[2]);
      ctx->m[12] |= hl32_to_64_S (w6[1], w6[0]);
      ctx->m[13] |= hl32_to_64_S (w6[3], w6[2]);
      ctx->m[14] |= hl32_to_64_S (w7[1], w7[0]);
      ctx->m[15] |= hl32_to_64_S (w7[3], w7[2]);

      // len must be a multiple of 128 (not ctx->len) for BLAKE2B_UPDATE:

      const u32 cur_len = ((ctx->len + len) / 128) * 128;

      blake2b_transform (ctx->h, ctx->m, cur_len, BLAKE2B_UPDATE);

      ctx->m[ 0] = hl32_to_64_S (c0[1], c0[0]);
      ctx->m[ 1] = hl32_to_64_S (c0[3], c0[2]);
      ctx->m[ 2] = hl32_to_64_S (c1[1], c1[0]);
      ctx->m[ 3] = hl32_to_64_S (c1[3], c1[2]);
      ctx->m[ 4] = hl32_to_64_S (c2[1], c2[0]);
      ctx->m[ 5] = hl32_to_64_S (c2[3], c2[2]);
      ctx->m[ 6] = hl32_to_64_S (c3[1], c3[0]);
      ctx->m[ 7] = hl32_to_64_S (c3[3], c3[2]);
      ctx->m[ 8] = hl32_to_64_S (c4[1], c4[0]);
      ctx->m[ 9] = hl32_to_64_S (c4[3], c4[2]);
      ctx->m[10] = hl32_to_64_S (c5[1], c5[0]);
      ctx->m[11] = hl32_to_64_S (c5[3], c5[2]);
      ctx->m[12] = hl32_to_64_S (c6[1], c6[0]);
      ctx->m[13] = hl32_to_64_S (c6[3], c6[2]);
      ctx->m[14] = hl32_to_64_S (c7[1], c7[0]);
      ctx->m[15] = hl32_to_64_S (c7[3], c7[2]);
    }
  }

  ctx->len += len;
}

DECLSPEC void blake2b_update (PRIVATE_AS blake2b_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  const int limit = (const int) len - 128; // int type needed, could be negative

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < limit; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    blake2b_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  blake2b_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - (u32) pos1);
}

DECLSPEC void blake2b_update_global (PRIVATE_AS blake2b_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  const int limit = (const int) len - 128; // int type needed, could be negative

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < limit; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    blake2b_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  blake2b_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - (u32) pos1);
}

DECLSPEC void blake2b_final (PRIVATE_AS blake2b_ctx_t *ctx)
{
  blake2b_transform (ctx->h, ctx->m, ctx->len, BLAKE2B_FINAL);
}

DECLSPEC void blake2b_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u32x len, const u64 f0)
{
  const u64x t0 = hl32_to_64 (0, len);

  u64x v[16];

  v[ 0] = h[0];
  v[ 1] = h[1];
  v[ 2] = h[2];
  v[ 3] = h[3];
  v[ 4] = h[4];
  v[ 5] = h[5];
  v[ 6] = h[6];
  v[ 7] = h[7];
  v[ 8] = BLAKE2B_IV_00;
  v[ 9] = BLAKE2B_IV_01;
  v[10] = BLAKE2B_IV_02;
  v[11] = BLAKE2B_IV_03;
  v[12] = make_u64x (BLAKE2B_IV_04) ^ t0;
  v[13] = BLAKE2B_IV_05; // ^ t1;
  v[14] = make_u64x (BLAKE2B_IV_06) ^ f0;
  v[15] = BLAKE2B_IV_07; // ^ f1;

  BLAKE2B_ROUND_VECTOR ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND_VECTOR (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
  BLAKE2B_ROUND_VECTOR (11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
  BLAKE2B_ROUND_VECTOR ( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
  BLAKE2B_ROUND_VECTOR ( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
  BLAKE2B_ROUND_VECTOR ( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);
  BLAKE2B_ROUND_VECTOR (12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11);
  BLAKE2B_ROUND_VECTOR (13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10);
  BLAKE2B_ROUND_VECTOR ( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5);
  BLAKE2B_ROUND_VECTOR (10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0);
  BLAKE2B_ROUND_VECTOR ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND_VECTOR (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);

  h[0] = h[0] ^ v[0] ^ v[ 8];
  h[1] = h[1] ^ v[1] ^ v[ 9];
  h[2] = h[2] ^ v[2] ^ v[10];
  h[3] = h[3] ^ v[3] ^ v[11];
  h[4] = h[4] ^ v[4] ^ v[12];
  h[5] = h[5] ^ v[5] ^ v[13];
  h[6] = h[6] ^ v[6] ^ v[14];
  h[7] = h[7] ^ v[7] ^ v[15];
}

DECLSPEC void blake2b_init_vector (PRIVATE_AS blake2b_ctx_vector_t *ctx)
{
  ctx->h[0] = BLAKE2B_IV_00 ^ 0x01010040; // default output length: 0x40 = 64 bytes
  ctx->h[1] = BLAKE2B_IV_01;
  ctx->h[2] = BLAKE2B_IV_02;
  ctx->h[3] = BLAKE2B_IV_03;
  ctx->h[4] = BLAKE2B_IV_04;
  ctx->h[5] = BLAKE2B_IV_05;
  ctx->h[6] = BLAKE2B_IV_06;
  ctx->h[7] = BLAKE2B_IV_07;

  ctx->m[ 0] = 0;
  ctx->m[ 1] = 0;
  ctx->m[ 2] = 0;
  ctx->m[ 3] = 0;
  ctx->m[ 4] = 0;
  ctx->m[ 5] = 0;
  ctx->m[ 6] = 0;
  ctx->m[ 7] = 0;
  ctx->m[ 8] = 0;
  ctx->m[ 9] = 0;
  ctx->m[10] = 0;
  ctx->m[11] = 0;
  ctx->m[12] = 0;
  ctx->m[13] = 0;
  ctx->m[14] = 0;
  ctx->m[15] = 0;

  ctx->len = 0;
}

DECLSPEC void blake2b_init_vector_from_scalar(blake2b_ctx_vector_t* ctx, blake2b_ctx_t* ctx0) {
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];
  ctx->h[5] = ctx0->h[5];
  ctx->h[6] = ctx0->h[6];
  ctx->h[7] = ctx0->h[7];

  ctx->m[ 0] = ctx0->m[ 0];
  ctx->m[ 1] = ctx0->m[ 1];
  ctx->m[ 2] = ctx0->m[ 2];
  ctx->m[ 3] = ctx0->m[ 3];
  ctx->m[ 4] = ctx0->m[ 4];
  ctx->m[ 5] = ctx0->m[ 5];
  ctx->m[ 6] = ctx0->m[ 6];
  ctx->m[ 7] = ctx0->m[ 7];
  ctx->m[ 8] = ctx0->m[ 8];
  ctx->m[ 9] = ctx0->m[ 9];
  ctx->m[10] = ctx0->m[10];
  ctx->m[11] = ctx0->m[11];
  ctx->m[12] = ctx0->m[12];
  ctx->m[13] = ctx0->m[13];
  ctx->m[14] = ctx0->m[14];
  ctx->m[15] = ctx0->m[15];

  ctx->len = ctx0->len;
}

DECLSPEC void blake2b_update_vector_128 (PRIVATE_AS blake2b_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 127;

  if (pos == 0)
  {
    if (ctx->len > 0) // if new block (pos == 0) AND the (old) len is not zero => transform
    {
      blake2b_transform_vector (ctx->h, ctx->m, (u32x) ctx->len, BLAKE2B_UPDATE);
    }

    ctx->m[ 0] = hl32_to_64 (w0[1], w0[0]);
    ctx->m[ 1] = hl32_to_64 (w0[3], w0[2]);
    ctx->m[ 2] = hl32_to_64 (w1[1], w1[0]);
    ctx->m[ 3] = hl32_to_64 (w1[3], w1[2]);
    ctx->m[ 4] = hl32_to_64 (w2[1], w2[0]);
    ctx->m[ 5] = hl32_to_64 (w2[3], w2[2]);
    ctx->m[ 6] = hl32_to_64 (w3[1], w3[0]);
    ctx->m[ 7] = hl32_to_64 (w3[3], w3[2]);
    ctx->m[ 8] = hl32_to_64 (w4[1], w4[0]);
    ctx->m[ 9] = hl32_to_64 (w4[3], w4[2]);
    ctx->m[10] = hl32_to_64 (w5[1], w5[0]);
    ctx->m[11] = hl32_to_64 (w5[3], w5[2]);
    ctx->m[12] = hl32_to_64 (w6[1], w6[0]);
    ctx->m[13] = hl32_to_64 (w6[3], w6[2]);
    ctx->m[14] = hl32_to_64 (w7[1], w7[0]);
    ctx->m[15] = hl32_to_64 (w7[3], w7[2]);
  }
  else
  {
    if ((pos + len) <= 128)
    {
      switch_buffer_by_offset_8x4_le (w0, w1, w2, w3, w4, w5, w6, w7, pos);

      ctx->m[ 0] |= hl32_to_64 (w0[1], w0[0]);
      ctx->m[ 1] |= hl32_to_64 (w0[3], w0[2]);
      ctx->m[ 2] |= hl32_to_64 (w1[1], w1[0]);
      ctx->m[ 3] |= hl32_to_64 (w1[3], w1[2]);
      ctx->m[ 4] |= hl32_to_64 (w2[1], w2[0]);
      ctx->m[ 5] |= hl32_to_64 (w2[3], w2[2]);
      ctx->m[ 6] |= hl32_to_64 (w3[1], w3[0]);
      ctx->m[ 7] |= hl32_to_64 (w3[3], w3[2]);
      ctx->m[ 8] |= hl32_to_64 (w4[1], w4[0]);
      ctx->m[ 9] |= hl32_to_64 (w4[3], w4[2]);
      ctx->m[10] |= hl32_to_64 (w5[1], w5[0]);
      ctx->m[11] |= hl32_to_64 (w5[3], w5[2]);
      ctx->m[12] |= hl32_to_64 (w6[1], w6[0]);
      ctx->m[13] |= hl32_to_64 (w6[3], w6[2]);
      ctx->m[14] |= hl32_to_64 (w7[1], w7[0]);
      ctx->m[15] |= hl32_to_64 (w7[3], w7[2]);
    }
    else
    {
      u32x c0[4] = { 0 };
      u32x c1[4] = { 0 };
      u32x c2[4] = { 0 };
      u32x c3[4] = { 0 };
      u32x c4[4] = { 0 };
      u32x c5[4] = { 0 };
      u32x c6[4] = { 0 };
      u32x c7[4] = { 0 };

      switch_buffer_by_offset_8x4_carry_le (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

      ctx->m[ 0] |= hl32_to_64 (w0[1], w0[0]);
      ctx->m[ 1] |= hl32_to_64 (w0[3], w0[2]);
      ctx->m[ 2] |= hl32_to_64 (w1[1], w1[0]);
      ctx->m[ 3] |= hl32_to_64 (w1[3], w1[2]);
      ctx->m[ 4] |= hl32_to_64 (w2[1], w2[0]);
      ctx->m[ 5] |= hl32_to_64 (w2[3], w2[2]);
      ctx->m[ 6] |= hl32_to_64 (w3[1], w3[0]);
      ctx->m[ 7] |= hl32_to_64 (w3[3], w3[2]);
      ctx->m[ 8] |= hl32_to_64 (w4[1], w4[0]);
      ctx->m[ 9] |= hl32_to_64 (w4[3], w4[2]);
      ctx->m[10] |= hl32_to_64 (w5[1], w5[0]);
      ctx->m[11] |= hl32_to_64 (w5[3], w5[2]);
      ctx->m[12] |= hl32_to_64 (w6[1], w6[0]);
      ctx->m[13] |= hl32_to_64 (w6[3], w6[2]);
      ctx->m[14] |= hl32_to_64 (w7[1], w7[0]);
      ctx->m[15] |= hl32_to_64 (w7[3], w7[2]);

      // len must be a multiple of 128 (not ctx->len) for BLAKE2B_UPDATE:

      const u32x cur_len = ((ctx->len + len) / 128) * 128;

      blake2b_transform_vector (ctx->h, ctx->m, cur_len, BLAKE2B_UPDATE);

      ctx->m[ 0] = hl32_to_64 (c0[1], c0[0]);
      ctx->m[ 1] = hl32_to_64 (c0[3], c0[2]);
      ctx->m[ 2] = hl32_to_64 (c1[1], c1[0]);
      ctx->m[ 3] = hl32_to_64 (c1[3], c1[2]);
      ctx->m[ 4] = hl32_to_64 (c2[1], c2[0]);
      ctx->m[ 5] = hl32_to_64 (c2[3], c2[2]);
      ctx->m[ 6] = hl32_to_64 (c3[1], c3[0]);
      ctx->m[ 7] = hl32_to_64 (c3[3], c3[2]);
      ctx->m[ 8] = hl32_to_64 (c4[1], c4[0]);
      ctx->m[ 9] = hl32_to_64 (c4[3], c4[2]);
      ctx->m[10] = hl32_to_64 (c5[1], c5[0]);
      ctx->m[11] = hl32_to_64 (c5[3], c5[2]);
      ctx->m[12] = hl32_to_64 (c6[1], c6[0]);
      ctx->m[13] = hl32_to_64 (c6[3], c6[2]);
      ctx->m[14] = hl32_to_64 (c7[1], c7[0]);
      ctx->m[15] = hl32_to_64 (c7[3], c7[2]);
    }
  }

  ctx->len += len;
}

DECLSPEC void blake2b_update_vector (PRIVATE_AS blake2b_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  const int limit = (const int) len - 128; // int type needed, could be negative

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < limit; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    blake2b_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  blake2b_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - (u32) pos1);
}

DECLSPEC void blake2b_final_vector (PRIVATE_AS blake2b_ctx_vector_t *ctx)
{
  blake2b_transform_vector (ctx->h, ctx->m, (u32x) ctx->len, BLAKE2B_FINAL);
}
