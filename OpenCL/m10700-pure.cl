/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_sha384.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define PUTCHAR(a,p,c) ((u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)   ((u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((u8 *)(a))[(p) ^ 3]

DECLSPEC void aes128_encrypt_cbc (const u32 *aes_ks, u32 *aes_iv, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 data[4];

  data[0] = swap32_S (in[0]);
  data[1] = swap32_S (in[1]);
  data[2] = swap32_S (in[2]);
  data[3] = swap32_S (in[3]);

  data[0] ^= aes_iv[0];
  data[1] ^= aes_iv[1];
  data[2] ^= aes_iv[2];
  data[3] ^= aes_iv[3];

  aes128_encrypt (aes_ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes_iv[0] = out[0];
  aes_iv[1] = out[1];
  aes_iv[2] = out[2];
  aes_iv[3] = out[3];

  out[0] = swap32_S (out[0]);
  out[1] = swap32_S (out[1]);
  out[2] = swap32_S (out[2]);
  out[3] = swap32_S (out[3]);
}

DECLSPEC u32 sha256_update_aes_64 (sha256_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ex = 0;

  const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_be_S (w0, w1, w2, w3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };

    switch_buffer_by_offset_carry_be_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];

    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w0, ctx->w0, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w1, ctx->w1, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w2, ctx->w2, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w3, ctx->w3, s_te0, s_te1, s_te2, s_te3, s_te4);

    ex = ctx->w3[3] & 0xff;

    sha256_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
  }

  return ex;
}

DECLSPEC void sha256_update_aes (sha256_ctx_t *ctx, const u32 *w, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
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

    sha256_update_aes_64 (ctx, w0, w1, w2, w3, 64, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
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

  sha256_update_aes_64 (ctx, w0, w1, w2, w3, len - pos1, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void sha256_final_aes (sha256_ctx_t *ctx, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  int pos = ctx->len & 63;

  // no encryption needed, because pos is always 0

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  if (pos >= 56)
  {
    sha256_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = 0;
  ctx->w3[3] = ctx->len * 8;

  sha256_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

DECLSPEC void sha384_update_aes_128 (sha384_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  const int pos = ctx->len & 127;

  ctx->len += len;

  if ((pos + len) < 128)
  {
    switch_buffer_by_offset_8x4_be_S (w0, w1, w2, w3, w4, w5, w6, w7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];
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

    switch_buffer_by_offset_8x4_carry_be_S (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];

    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w0, ctx->w0, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w1, ctx->w1, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w2, ctx->w2, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w3, ctx->w3, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w4, ctx->w4, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w5, ctx->w5, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w6, ctx->w6, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w7, ctx->w7, s_te0, s_te1, s_te2, s_te3, s_te4);

    sha384_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
    ctx->w4[0] = c4[0];
    ctx->w4[1] = c4[1];
    ctx->w4[2] = c4[2];
    ctx->w4[3] = c4[3];
    ctx->w5[0] = c5[0];
    ctx->w5[1] = c5[1];
    ctx->w5[2] = c5[2];
    ctx->w5[3] = c5[3];
    ctx->w6[0] = c6[0];
    ctx->w6[1] = c6[1];
    ctx->w6[2] = c6[2];
    ctx->w6[3] = c6[3];
    ctx->w7[0] = c7[0];
    ctx->w7[1] = c7[1];
    ctx->w7[2] = c7[2];
    ctx->w7[3] = c7[3];
  }
}

DECLSPEC void sha384_update_aes (sha384_ctx_t *ctx, const u32 *w, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
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

    sha384_update_aes_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
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

  sha384_update_aes_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void sha384_final_aes (sha384_ctx_t *ctx, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  int pos = ctx->len & 127;

  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w0, ctx->w0, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w1, ctx->w1, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w2, ctx->w2, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w3, ctx->w3, s_te0, s_te1, s_te2, s_te3, s_te4);

  append_0x80_8x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sha384_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
    ctx->w4[0] = 0;
    ctx->w4[1] = 0;
    ctx->w4[2] = 0;
    ctx->w4[3] = 0;
    ctx->w5[0] = 0;
    ctx->w5[1] = 0;
    ctx->w5[2] = 0;
    ctx->w5[3] = 0;
    ctx->w6[0] = 0;
    ctx->w6[1] = 0;
    ctx->w6[2] = 0;
    ctx->w6[3] = 0;
    ctx->w7[0] = 0;
    ctx->w7[1] = 0;
    ctx->w7[2] = 0;
    ctx->w7[3] = 0;
  }

  ctx->w7[2] = 0;
  ctx->w7[3] = ctx->len * 8;

  sha384_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

DECLSPEC void sha512_update_aes_128 (sha512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  const int pos = ctx->len & 127;

  ctx->len += len;

  if ((pos + len) < 128)
  {
    switch_buffer_by_offset_8x4_be_S (w0, w1, w2, w3, w4, w5, w6, w7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];
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

    switch_buffer_by_offset_8x4_carry_be_S (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];

    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w0, ctx->w0, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w1, ctx->w1, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w2, ctx->w2, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w3, ctx->w3, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w4, ctx->w4, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w5, ctx->w5, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w6, ctx->w6, s_te0, s_te1, s_te2, s_te3, s_te4);
    aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w7, ctx->w7, s_te0, s_te1, s_te2, s_te3, s_te4);

    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
    ctx->w4[0] = c4[0];
    ctx->w4[1] = c4[1];
    ctx->w4[2] = c4[2];
    ctx->w4[3] = c4[3];
    ctx->w5[0] = c5[0];
    ctx->w5[1] = c5[1];
    ctx->w5[2] = c5[2];
    ctx->w5[3] = c5[3];
    ctx->w6[0] = c6[0];
    ctx->w6[1] = c6[1];
    ctx->w6[2] = c6[2];
    ctx->w6[3] = c6[3];
    ctx->w7[0] = c7[0];
    ctx->w7[1] = c7[1];
    ctx->w7[2] = c7[2];
    ctx->w7[3] = c7[3];
  }
}

DECLSPEC void sha512_update_aes (sha512_ctx_t *ctx, const u32 *w, const int len, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
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

    sha512_update_aes_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
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

  sha512_update_aes_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void sha512_final_aes (sha512_ctx_t *ctx, const u32 *aes_ks, u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  int pos = ctx->len & 127;

  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w0, ctx->w0, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w1, ctx->w1, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w2, ctx->w2, s_te0, s_te1, s_te2, s_te3, s_te4);
  aes128_encrypt_cbc (aes_ks, aes_iv, ctx->w3, ctx->w3, s_te0, s_te1, s_te2, s_te3, s_te4);

  append_0x80_8x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
    ctx->w4[0] = 0;
    ctx->w4[1] = 0;
    ctx->w4[2] = 0;
    ctx->w4[3] = 0;
    ctx->w5[0] = 0;
    ctx->w5[1] = 0;
    ctx->w5[2] = 0;
    ctx->w5[3] = 0;
    ctx->w6[0] = 0;
    ctx->w6[1] = 0;
    ctx->w6[2] = 0;
    ctx->w6[3] = 0;
    ctx->w7[0] = 0;
    ctx->w7[1] = 0;
    ctx->w7[2] = 0;
    ctx->w7[3] = 0;
  }

  ctx->w7[2] = 0;
  ctx->w7[3] = ctx->len * 8;

  sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

DECLSPEC int find_sum (const u32 *w, const u32 pw_len, u32 *bb, const u32 *aes_ks, const u32 *aes_iv, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 data[4];

  data[0] = w[0];
  data[1] = w[1];
  data[2] = w[2];
  data[3] = w[3];

  for (int i = pw_len, j = 0; i < 16; i++, j++)
  {
    PUTCHAR_BE (data, i, GETCHAR_BE (bb, j));
  }

  data[0] = swap32_S (data[0]);
  data[1] = swap32_S (data[1]);
  data[2] = swap32_S (data[2]);
  data[3] = swap32_S (data[3]);

  data[0] ^= aes_iv[0];
  data[1] ^= aes_iv[1];
  data[2] ^= aes_iv[2];
  data[3] ^= aes_iv[3];

  u32 out[4];

  aes128_encrypt (aes_ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 sum = 0;

  for (u32 i = 0; i < 4; i++)
  {
    sum += (out[i] >> 24) & 0xff;
    sum += (out[i] >> 16) & 0xff;
    sum += (out[i] >>  8) & 0xff;
    sum += (out[i] >>  0) & 0xff;
  }

  return sum;
}

DECLSPEC u32 do_round (const u32 *w, const u32 pw_len, pdf17l8_tmp_t *tmp, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  // get previous hash (already padded)

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = tmp->dgst32[0];
  w0[1] = tmp->dgst32[1];
  w0[2] = tmp->dgst32[2];
  w0[3] = tmp->dgst32[3];
  w1[0] = tmp->dgst32[4];
  w1[1] = tmp->dgst32[5];
  w1[2] = tmp->dgst32[6];
  w1[3] = tmp->dgst32[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
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
  w7[3] = 0;

  // cipher setup

  u32 aes_key[4];

  aes_key[0] = swap32_S (w0[0]);
  aes_key[1] = swap32_S (w0[1]);
  aes_key[2] = swap32_S (w0[2]);
  aes_key[3] = swap32_S (w0[3]);

  u32 aes_ks[44];

  aes128_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 aes_iv[4];

  aes_iv[0] = swap32_S (w1[0]);
  aes_iv[1] = swap32_S (w1[1]);
  aes_iv[2] = swap32_S (w1[2]);
  aes_iv[3] = swap32_S (w1[3]);

  // find hash to use

  const int sum = find_sum (w, pw_len, w0, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

  int sum3 = sum % 3;

  // hash data

  u32 ex = 0;

  if (sum3 == 0)
  {
    sha256_ctx_t ctx256;

    sha256_init (&ctx256);

    for (int i = 0; i < 64; i++)
    {
      sha256_update_aes (&ctx256, w, pw_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

      w0[0] = tmp->dgst32[ 0];
      w0[1] = tmp->dgst32[ 1];
      w0[2] = tmp->dgst32[ 2];
      w0[3] = tmp->dgst32[ 3];
      w1[0] = tmp->dgst32[ 4];
      w1[1] = tmp->dgst32[ 5];
      w1[2] = tmp->dgst32[ 6];
      w1[3] = tmp->dgst32[ 7];
      w2[0] = tmp->dgst32[ 8];
      w2[1] = tmp->dgst32[ 9];
      w2[2] = tmp->dgst32[10];
      w2[3] = tmp->dgst32[11];
      w3[0] = tmp->dgst32[12];
      w3[1] = tmp->dgst32[13];
      w3[2] = tmp->dgst32[14];
      w3[3] = tmp->dgst32[15];
      w4[0] = 0;
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
      w7[3] = 0;

      ex = sha256_update_aes_64 (&ctx256, w0, w1, w2, w3, tmp->dgst_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    sha256_final_aes (&ctx256, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    tmp->dgst32[ 0] = ctx256.h[0];
    tmp->dgst32[ 1] = ctx256.h[1];
    tmp->dgst32[ 2] = ctx256.h[2];
    tmp->dgst32[ 3] = ctx256.h[3];
    tmp->dgst32[ 4] = ctx256.h[4];
    tmp->dgst32[ 5] = ctx256.h[5];
    tmp->dgst32[ 6] = ctx256.h[6];
    tmp->dgst32[ 7] = ctx256.h[7];
    tmp->dgst32[ 8] = 0;
    tmp->dgst32[ 9] = 0;
    tmp->dgst32[10] = 0;
    tmp->dgst32[11] = 0;
    tmp->dgst32[12] = 0;
    tmp->dgst32[13] = 0;
    tmp->dgst32[14] = 0;
    tmp->dgst32[15] = 0;

    tmp->dgst_len = 32;
  }
  else if (sum3 == 1)
  {
    sha384_ctx_t ctx384;

    sha384_init (&ctx384);

    for (int i = 0; i < 64; i++)
    {
      sha384_update_aes (&ctx384, w, pw_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

      w0[0] = tmp->dgst32[ 0];
      w0[1] = tmp->dgst32[ 1];
      w0[2] = tmp->dgst32[ 2];
      w0[3] = tmp->dgst32[ 3];
      w1[0] = tmp->dgst32[ 4];
      w1[1] = tmp->dgst32[ 5];
      w1[2] = tmp->dgst32[ 6];
      w1[3] = tmp->dgst32[ 7];
      w2[0] = tmp->dgst32[ 8];
      w2[1] = tmp->dgst32[ 9];
      w2[2] = tmp->dgst32[10];
      w2[3] = tmp->dgst32[11];
      w3[0] = tmp->dgst32[12];
      w3[1] = tmp->dgst32[13];
      w3[2] = tmp->dgst32[14];
      w3[3] = tmp->dgst32[15];
      w4[0] = 0;
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
      w7[3] = 0;

      sha384_update_aes_128 (&ctx384, w0, w1, w2, w3, w4, w5, w6, w7, tmp->dgst_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    sha384_final_aes (&ctx384, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    ex = ctx384.w3[3] & 0xff;

    tmp->dgst32[ 0] = h32_from_64_S (ctx384.h[0]);
    tmp->dgst32[ 1] = l32_from_64_S (ctx384.h[0]);
    tmp->dgst32[ 2] = h32_from_64_S (ctx384.h[1]);
    tmp->dgst32[ 3] = l32_from_64_S (ctx384.h[1]);
    tmp->dgst32[ 4] = h32_from_64_S (ctx384.h[2]);
    tmp->dgst32[ 5] = l32_from_64_S (ctx384.h[2]);
    tmp->dgst32[ 6] = h32_from_64_S (ctx384.h[3]);
    tmp->dgst32[ 7] = l32_from_64_S (ctx384.h[3]);
    tmp->dgst32[ 8] = h32_from_64_S (ctx384.h[4]);
    tmp->dgst32[ 9] = l32_from_64_S (ctx384.h[4]);
    tmp->dgst32[10] = h32_from_64_S (ctx384.h[5]);
    tmp->dgst32[11] = l32_from_64_S (ctx384.h[5]);
    tmp->dgst32[12] = 0;
    tmp->dgst32[13] = 0;
    tmp->dgst32[14] = 0;
    tmp->dgst32[15] = 0;

    tmp->dgst_len = 48;
  }
  else if (sum3 == 2)
  {
    sha512_ctx_t ctx512;

    sha512_init (&ctx512);

    for (int i = 0; i < 64; i++)
    {
      sha512_update_aes (&ctx512, w, pw_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

      w0[0] = tmp->dgst32[ 0];
      w0[1] = tmp->dgst32[ 1];
      w0[2] = tmp->dgst32[ 2];
      w0[3] = tmp->dgst32[ 3];
      w1[0] = tmp->dgst32[ 4];
      w1[1] = tmp->dgst32[ 5];
      w1[2] = tmp->dgst32[ 6];
      w1[3] = tmp->dgst32[ 7];
      w2[0] = tmp->dgst32[ 8];
      w2[1] = tmp->dgst32[ 9];
      w2[2] = tmp->dgst32[10];
      w2[3] = tmp->dgst32[11];
      w3[0] = tmp->dgst32[12];
      w3[1] = tmp->dgst32[13];
      w3[2] = tmp->dgst32[14];
      w3[3] = tmp->dgst32[15];
      w4[0] = 0;
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
      w7[3] = 0;

      sha512_update_aes_128 (&ctx512, w0, w1, w2, w3, w4, w5, w6, w7, tmp->dgst_len, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    sha512_final_aes (&ctx512, aes_ks, aes_iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    ex = ctx512.w3[3] & 0xff;

    tmp->dgst32[ 0] = h32_from_64_S (ctx512.h[0]);
    tmp->dgst32[ 1] = l32_from_64_S (ctx512.h[0]);
    tmp->dgst32[ 2] = h32_from_64_S (ctx512.h[1]);
    tmp->dgst32[ 3] = l32_from_64_S (ctx512.h[1]);
    tmp->dgst32[ 4] = h32_from_64_S (ctx512.h[2]);
    tmp->dgst32[ 5] = l32_from_64_S (ctx512.h[2]);
    tmp->dgst32[ 6] = h32_from_64_S (ctx512.h[3]);
    tmp->dgst32[ 7] = l32_from_64_S (ctx512.h[3]);
    tmp->dgst32[ 8] = h32_from_64_S (ctx512.h[4]);
    tmp->dgst32[ 9] = l32_from_64_S (ctx512.h[4]);
    tmp->dgst32[10] = h32_from_64_S (ctx512.h[5]);
    tmp->dgst32[11] = l32_from_64_S (ctx512.h[5]);
    tmp->dgst32[12] = h32_from_64_S (ctx512.h[6]);
    tmp->dgst32[13] = l32_from_64_S (ctx512.h[6]);
    tmp->dgst32[14] = h32_from_64_S (ctx512.h[7]);
    tmp->dgst32[15] = l32_from_64_S (ctx512.h[7]);

    tmp->dgst_len = 64;
  }

  return ex;
}

__kernel void m10700_init (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha256_update_global_swap (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha256_final (&ctx);

  pdf17l8_tmp_t tmp;

  tmp.dgst32[ 0] = ctx.h[0];
  tmp.dgst32[ 1] = ctx.h[1];
  tmp.dgst32[ 2] = ctx.h[2];
  tmp.dgst32[ 3] = ctx.h[3];
  tmp.dgst32[ 4] = ctx.h[4];
  tmp.dgst32[ 5] = ctx.h[5];
  tmp.dgst32[ 6] = ctx.h[6];
  tmp.dgst32[ 7] = ctx.h[7];
  tmp.dgst32[ 8] = 0;
  tmp.dgst32[ 9] = 0;
  tmp.dgst32[10] = 0;
  tmp.dgst32[11] = 0;
  tmp.dgst32[12] = 0;
  tmp.dgst32[13] = 0;
  tmp.dgst32[14] = 0;
  tmp.dgst32[15] = 0;

  tmp.dgst_len = 32;

  tmps[gid] = tmp;
}

__kernel void m10700_loop (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);
  }

  /**
   * digest
   */

  pdf17l8_tmp_t tmp = tmps[gid];

  u32 ex = 0;

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    ex = do_round (w, pw_len, &tmp, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  if ((loop_pos + loop_cnt) == 64)
  {
    for (u32 i = 64; i < (ex & 0xff) + 32; i++)
    {
      ex = do_round (w, pw_len, &tmp, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
  }

  tmps[gid] = tmp;
}

__kernel void m10700_comp (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].dgst32[DGST_R0];
  const u32 r1 = tmps[gid].dgst32[DGST_R1];
  const u32 r2 = tmps[gid].dgst32[DGST_R2];
  const u32 r3 = tmps[gid].dgst32[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
