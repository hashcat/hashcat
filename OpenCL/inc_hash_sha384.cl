/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha384.h"

CONSTANT_VK u64a k_sha384[80] =
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

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha1 = BE, etc)
// input buf needs to be 128 byte aligned when using sha384_update()

DECLSPEC void sha384_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS const u32 *w4, PRIVATE_AS const u32 *w5, PRIVATE_AS const u32 *w6, PRIVATE_AS const u32 *w7, PRIVATE_AS u64 *digest)
{
  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  u64 w0_t = hl32_to_64_S (w0[0], w0[1]);
  u64 w1_t = hl32_to_64_S (w0[2], w0[3]);
  u64 w2_t = hl32_to_64_S (w1[0], w1[1]);
  u64 w3_t = hl32_to_64_S (w1[2], w1[3]);
  u64 w4_t = hl32_to_64_S (w2[0], w2[1]);
  u64 w5_t = hl32_to_64_S (w2[2], w2[3]);
  u64 w6_t = hl32_to_64_S (w3[0], w3[1]);
  u64 w7_t = hl32_to_64_S (w3[2], w3[3]);
  u64 w8_t = hl32_to_64_S (w4[0], w4[1]);
  u64 w9_t = hl32_to_64_S (w4[2], w4[3]);
  u64 wa_t = hl32_to_64_S (w5[0], w5[1]);
  u64 wb_t = hl32_to_64_S (w5[2], w5[3]);
  u64 wc_t = hl32_to_64_S (w6[0], w6[1]);
  u64 wd_t = hl32_to_64_S (w6[2], w6[3]);
  u64 we_t = hl32_to_64_S (w7[0], w7[1]);
  u64 wf_t = hl32_to_64_S (w7[2], w7[3]);

  #define ROUND_EXPAND_S()                            \
  {                                                   \
    w0_t = SHA384_EXPAND_S (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA384_EXPAND_S (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA384_EXPAND_S (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA384_EXPAND_S (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA384_EXPAND_S (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA384_EXPAND_S (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA384_EXPAND_S (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA384_EXPAND_S (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA384_EXPAND_S (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA384_EXPAND_S (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA384_EXPAND_S (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA384_EXPAND_S (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA384_EXPAND_S (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA384_EXPAND_S (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA384_EXPAND_S (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA384_EXPAND_S (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP_S(i)                                                                   \
  {                                                                                         \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha384[i +  0]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha384[i +  1]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha384[i +  2]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha384[i +  3]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha384[i +  4]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha384[i +  5]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha384[i +  6]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha384[i +  7]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha384[i +  8]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha384[i +  9]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha384[i + 10]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha384[i + 11]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha384[i + 12]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha384[i + 13]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, c, d, e, f, g, h, a, b, we_t, k_sha384[i + 14]); \
    SHA384_STEP_S (SHA384_F0o, SHA384_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha384[i + 15]); \
  }

  ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND_S (); ROUND_STEP_S (i);
  }

  #undef ROUND_EXPAND_S
  #undef ROUND_STEP_S

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha384_init (PRIVATE_AS sha384_ctx_t *ctx)
{
  ctx->h[0] = SHA384M_A;
  ctx->h[1] = SHA384M_B;
  ctx->h[2] = SHA384M_C;
  ctx->h[3] = SHA384M_D;
  ctx->h[4] = SHA384M_E;
  ctx->h[5] = SHA384M_F;
  ctx->h[6] = SHA384M_G;
  ctx->h[7] = SHA384M_H;

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

  ctx->len = 0;
}

DECLSPEC void sha384_update_128 (PRIVATE_AS sha384_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 127;

  ctx->len += len;

  if (pos == 0)
  {
    ctx->w0[0] = w0[0];
    ctx->w0[1] = w0[1];
    ctx->w0[2] = w0[2];
    ctx->w0[3] = w0[3];
    ctx->w1[0] = w1[0];
    ctx->w1[1] = w1[1];
    ctx->w1[2] = w1[2];
    ctx->w1[3] = w1[3];
    ctx->w2[0] = w2[0];
    ctx->w2[1] = w2[1];
    ctx->w2[2] = w2[2];
    ctx->w2[3] = w2[3];
    ctx->w3[0] = w3[0];
    ctx->w3[1] = w3[1];
    ctx->w3[2] = w3[2];
    ctx->w3[3] = w3[3];
    ctx->w4[0] = w4[0];
    ctx->w4[1] = w4[1];
    ctx->w4[2] = w4[2];
    ctx->w4[3] = w4[3];
    ctx->w5[0] = w5[0];
    ctx->w5[1] = w5[1];
    ctx->w5[2] = w5[2];
    ctx->w5[3] = w5[3];
    ctx->w6[0] = w6[0];
    ctx->w6[1] = w6[1];
    ctx->w6[2] = w6[2];
    ctx->w6[3] = w6[3];
    ctx->w7[0] = w7[0];
    ctx->w7[1] = w7[1];
    ctx->w7[2] = w7[2];
    ctx->w7[3] = w7[3];

    if (len == 128)
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
  }
  else
  {
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
}

DECLSPEC void sha384_update (PRIVATE_AS sha384_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_swap (PRIVATE_AS sha384_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);
    w4[0] = hc_swap32_S (w4[0]);
    w4[1] = hc_swap32_S (w4[1]);
    w4[2] = hc_swap32_S (w4[2]);
    w4[3] = hc_swap32_S (w4[3]);
    w5[0] = hc_swap32_S (w5[0]);
    w5[1] = hc_swap32_S (w5[1]);
    w5[2] = hc_swap32_S (w5[2]);
    w5[3] = hc_swap32_S (w5[3]);
    w6[0] = hc_swap32_S (w6[0]);
    w6[1] = hc_swap32_S (w6[1]);
    w6[2] = hc_swap32_S (w6[2]);
    w6[3] = hc_swap32_S (w6[3]);
    w7[0] = hc_swap32_S (w7[0]);
    w7[1] = hc_swap32_S (w7[1]);
    w7[2] = hc_swap32_S (w7[2]);
    w7[3] = hc_swap32_S (w7[3]);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_utf16le (PRIVATE_AS sha384_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[32] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      sha384_update_128 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_buf + 16, enc_buf + 20, enc_buf + 24, enc_buf + 28, enc_len);
    }

    return;
  }

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

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_update_utf16le_swap (PRIVATE_AS sha384_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[32] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      enc_buf[ 0] = hc_swap32_S (enc_buf[ 0]);
      enc_buf[ 1] = hc_swap32_S (enc_buf[ 1]);
      enc_buf[ 2] = hc_swap32_S (enc_buf[ 2]);
      enc_buf[ 3] = hc_swap32_S (enc_buf[ 3]);
      enc_buf[ 4] = hc_swap32_S (enc_buf[ 4]);
      enc_buf[ 5] = hc_swap32_S (enc_buf[ 5]);
      enc_buf[ 6] = hc_swap32_S (enc_buf[ 6]);
      enc_buf[ 7] = hc_swap32_S (enc_buf[ 7]);
      enc_buf[ 8] = hc_swap32_S (enc_buf[ 8]);
      enc_buf[ 9] = hc_swap32_S (enc_buf[ 9]);
      enc_buf[10] = hc_swap32_S (enc_buf[10]);
      enc_buf[11] = hc_swap32_S (enc_buf[11]);
      enc_buf[12] = hc_swap32_S (enc_buf[12]);
      enc_buf[13] = hc_swap32_S (enc_buf[13]);
      enc_buf[14] = hc_swap32_S (enc_buf[14]);
      enc_buf[15] = hc_swap32_S (enc_buf[15]);
      enc_buf[16] = hc_swap32_S (enc_buf[16]);
      enc_buf[17] = hc_swap32_S (enc_buf[17]);
      enc_buf[18] = hc_swap32_S (enc_buf[18]);
      enc_buf[19] = hc_swap32_S (enc_buf[19]);
      enc_buf[20] = hc_swap32_S (enc_buf[20]);
      enc_buf[21] = hc_swap32_S (enc_buf[21]);
      enc_buf[22] = hc_swap32_S (enc_buf[22]);
      enc_buf[23] = hc_swap32_S (enc_buf[23]);
      enc_buf[24] = hc_swap32_S (enc_buf[24]);
      enc_buf[25] = hc_swap32_S (enc_buf[25]);
      enc_buf[26] = hc_swap32_S (enc_buf[26]);
      enc_buf[27] = hc_swap32_S (enc_buf[27]);
      enc_buf[28] = hc_swap32_S (enc_buf[28]);
      enc_buf[29] = hc_swap32_S (enc_buf[29]);
      enc_buf[30] = hc_swap32_S (enc_buf[30]);
      enc_buf[31] = hc_swap32_S (enc_buf[31]);

      sha384_update_128 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_buf + 16, enc_buf + 20, enc_buf + 24, enc_buf + 28, enc_len);
    }

    return;
  }

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

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);
    w4[0] = hc_swap32_S (w4[0]);
    w4[1] = hc_swap32_S (w4[1]);
    w4[2] = hc_swap32_S (w4[2]);
    w4[3] = hc_swap32_S (w4[3]);
    w5[0] = hc_swap32_S (w5[0]);
    w5[1] = hc_swap32_S (w5[1]);
    w5[2] = hc_swap32_S (w5[2]);
    w5[3] = hc_swap32_S (w5[3]);
    w6[0] = hc_swap32_S (w6[0]);
    w6[1] = hc_swap32_S (w6[1]);
    w6[2] = hc_swap32_S (w6[2]);
    w6[3] = hc_swap32_S (w6[3]);
    w7[0] = hc_swap32_S (w7[0]);
    w7[1] = hc_swap32_S (w7[1]);
    w7[2] = hc_swap32_S (w7[2]);
    w7[3] = hc_swap32_S (w7[3]);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_update_global (PRIVATE_AS sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_global_swap (PRIVATE_AS sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);
    w4[0] = hc_swap32_S (w4[0]);
    w4[1] = hc_swap32_S (w4[1]);
    w4[2] = hc_swap32_S (w4[2]);
    w4[3] = hc_swap32_S (w4[3]);
    w5[0] = hc_swap32_S (w5[0]);
    w5[1] = hc_swap32_S (w5[1]);
    w5[2] = hc_swap32_S (w5[2]);
    w5[3] = hc_swap32_S (w5[3]);
    w6[0] = hc_swap32_S (w6[0]);
    w6[1] = hc_swap32_S (w6[1]);
    w6[2] = hc_swap32_S (w6[2]);
    w6[3] = hc_swap32_S (w6[3]);
    w7[0] = hc_swap32_S (w7[0]);
    w7[1] = hc_swap32_S (w7[1]);
    w7[2] = hc_swap32_S (w7[2]);
    w7[3] = hc_swap32_S (w7[3]);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_global_utf16le (PRIVATE_AS sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[32] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      sha384_update_128 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_buf + 16, enc_buf + 20, enc_buf + 24, enc_buf + 28, enc_len);
    }

    return;
  }

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

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_update_global_utf16le_swap (PRIVATE_AS sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[32] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      enc_buf[ 0] = hc_swap32_S (enc_buf[ 0]);
      enc_buf[ 1] = hc_swap32_S (enc_buf[ 1]);
      enc_buf[ 2] = hc_swap32_S (enc_buf[ 2]);
      enc_buf[ 3] = hc_swap32_S (enc_buf[ 3]);
      enc_buf[ 4] = hc_swap32_S (enc_buf[ 4]);
      enc_buf[ 5] = hc_swap32_S (enc_buf[ 5]);
      enc_buf[ 6] = hc_swap32_S (enc_buf[ 6]);
      enc_buf[ 7] = hc_swap32_S (enc_buf[ 7]);
      enc_buf[ 8] = hc_swap32_S (enc_buf[ 8]);
      enc_buf[ 9] = hc_swap32_S (enc_buf[ 9]);
      enc_buf[10] = hc_swap32_S (enc_buf[10]);
      enc_buf[11] = hc_swap32_S (enc_buf[11]);
      enc_buf[12] = hc_swap32_S (enc_buf[12]);
      enc_buf[13] = hc_swap32_S (enc_buf[13]);
      enc_buf[14] = hc_swap32_S (enc_buf[14]);
      enc_buf[15] = hc_swap32_S (enc_buf[15]);
      enc_buf[16] = hc_swap32_S (enc_buf[16]);
      enc_buf[17] = hc_swap32_S (enc_buf[17]);
      enc_buf[18] = hc_swap32_S (enc_buf[18]);
      enc_buf[19] = hc_swap32_S (enc_buf[19]);
      enc_buf[20] = hc_swap32_S (enc_buf[20]);
      enc_buf[21] = hc_swap32_S (enc_buf[21]);
      enc_buf[22] = hc_swap32_S (enc_buf[22]);
      enc_buf[23] = hc_swap32_S (enc_buf[23]);
      enc_buf[24] = hc_swap32_S (enc_buf[24]);
      enc_buf[25] = hc_swap32_S (enc_buf[25]);
      enc_buf[26] = hc_swap32_S (enc_buf[26]);
      enc_buf[27] = hc_swap32_S (enc_buf[27]);
      enc_buf[28] = hc_swap32_S (enc_buf[28]);
      enc_buf[29] = hc_swap32_S (enc_buf[29]);
      enc_buf[30] = hc_swap32_S (enc_buf[30]);
      enc_buf[31] = hc_swap32_S (enc_buf[31]);

      sha384_update_128 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_buf + 16, enc_buf + 20, enc_buf + 24, enc_buf + 28, enc_len);
    }

    return;
  }

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

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);
    w4[0] = hc_swap32_S (w4[0]);
    w4[1] = hc_swap32_S (w4[1]);
    w4[2] = hc_swap32_S (w4[2]);
    w4[3] = hc_swap32_S (w4[3]);
    w5[0] = hc_swap32_S (w5[0]);
    w5[1] = hc_swap32_S (w5[1]);
    w5[2] = hc_swap32_S (w5[2]);
    w5[3] = hc_swap32_S (w5[3]);
    w6[0] = hc_swap32_S (w6[0]);
    w6[1] = hc_swap32_S (w6[1]);
    w6[2] = hc_swap32_S (w6[2]);
    w6[3] = hc_swap32_S (w6[3]);
    w7[0] = hc_swap32_S (w7[0]);
    w7[1] = hc_swap32_S (w7[1]);
    w7[2] = hc_swap32_S (w7[2]);
    w7[3] = hc_swap32_S (w7[3]);

    sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sha384_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_final (PRIVATE_AS sha384_ctx_t *ctx)
{
  const int pos = ctx->len & 127;

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

// sha384_hmac

DECLSPEC void sha384_hmac_init_128 (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS const u32 *w4, PRIVATE_AS const u32 *w5, PRIVATE_AS const u32 *w6, PRIVATE_AS const u32 *w7)
{
  u32 a0[4];
  u32 a1[4];
  u32 a2[4];
  u32 a3[4];
  u32 a4[4];
  u32 a5[4];
  u32 a6[4];
  u32 a7[4];

  // ipad

  a0[0] = w0[0] ^ 0x36363636;
  a0[1] = w0[1] ^ 0x36363636;
  a0[2] = w0[2] ^ 0x36363636;
  a0[3] = w0[3] ^ 0x36363636;
  a1[0] = w1[0] ^ 0x36363636;
  a1[1] = w1[1] ^ 0x36363636;
  a1[2] = w1[2] ^ 0x36363636;
  a1[3] = w1[3] ^ 0x36363636;
  a2[0] = w2[0] ^ 0x36363636;
  a2[1] = w2[1] ^ 0x36363636;
  a2[2] = w2[2] ^ 0x36363636;
  a2[3] = w2[3] ^ 0x36363636;
  a3[0] = w3[0] ^ 0x36363636;
  a3[1] = w3[1] ^ 0x36363636;
  a3[2] = w3[2] ^ 0x36363636;
  a3[3] = w3[3] ^ 0x36363636;
  a4[0] = w4[0] ^ 0x36363636;
  a4[1] = w4[1] ^ 0x36363636;
  a4[2] = w4[2] ^ 0x36363636;
  a4[3] = w4[3] ^ 0x36363636;
  a5[0] = w5[0] ^ 0x36363636;
  a5[1] = w5[1] ^ 0x36363636;
  a5[2] = w5[2] ^ 0x36363636;
  a5[3] = w5[3] ^ 0x36363636;
  a6[0] = w6[0] ^ 0x36363636;
  a6[1] = w6[1] ^ 0x36363636;
  a6[2] = w6[2] ^ 0x36363636;
  a6[3] = w6[3] ^ 0x36363636;
  a7[0] = w7[0] ^ 0x36363636;
  a7[1] = w7[1] ^ 0x36363636;
  a7[2] = w7[2] ^ 0x36363636;
  a7[3] = w7[3] ^ 0x36363636;

  sha384_init (&ctx->ipad);

  sha384_update_128 (&ctx->ipad, a0, a1, a2, a3, a4, a5, a6, a7, 128);

  // opad

  u32 b0[4];
  u32 b1[4];
  u32 b2[4];
  u32 b3[4];
  u32 b4[4];
  u32 b5[4];
  u32 b6[4];
  u32 b7[4];

  b0[0] = w0[0] ^ 0x5c5c5c5c;
  b0[1] = w0[1] ^ 0x5c5c5c5c;
  b0[2] = w0[2] ^ 0x5c5c5c5c;
  b0[3] = w0[3] ^ 0x5c5c5c5c;
  b1[0] = w1[0] ^ 0x5c5c5c5c;
  b1[1] = w1[1] ^ 0x5c5c5c5c;
  b1[2] = w1[2] ^ 0x5c5c5c5c;
  b1[3] = w1[3] ^ 0x5c5c5c5c;
  b2[0] = w2[0] ^ 0x5c5c5c5c;
  b2[1] = w2[1] ^ 0x5c5c5c5c;
  b2[2] = w2[2] ^ 0x5c5c5c5c;
  b2[3] = w2[3] ^ 0x5c5c5c5c;
  b3[0] = w3[0] ^ 0x5c5c5c5c;
  b3[1] = w3[1] ^ 0x5c5c5c5c;
  b3[2] = w3[2] ^ 0x5c5c5c5c;
  b3[3] = w3[3] ^ 0x5c5c5c5c;
  b4[0] = w4[0] ^ 0x5c5c5c5c;
  b4[1] = w4[1] ^ 0x5c5c5c5c;
  b4[2] = w4[2] ^ 0x5c5c5c5c;
  b4[3] = w4[3] ^ 0x5c5c5c5c;
  b5[0] = w5[0] ^ 0x5c5c5c5c;
  b5[1] = w5[1] ^ 0x5c5c5c5c;
  b5[2] = w5[2] ^ 0x5c5c5c5c;
  b5[3] = w5[3] ^ 0x5c5c5c5c;
  b6[0] = w6[0] ^ 0x5c5c5c5c;
  b6[1] = w6[1] ^ 0x5c5c5c5c;
  b6[2] = w6[2] ^ 0x5c5c5c5c;
  b6[3] = w6[3] ^ 0x5c5c5c5c;
  b7[0] = w7[0] ^ 0x5c5c5c5c;
  b7[1] = w7[1] ^ 0x5c5c5c5c;
  b7[2] = w7[2] ^ 0x5c5c5c5c;
  b7[3] = w7[3] ^ 0x5c5c5c5c;

  sha384_init (&ctx->opad);

  sha384_update_128 (&ctx->opad, b0, b1, b2, b3, b4, b5, b6, b7, 128);
}

DECLSPEC void sha384_hmac_init (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha384_ctx_t tmp;

    sha384_init (&tmp);

    sha384_update (&tmp, w, len);

    sha384_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
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
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha384_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha384_hmac_init_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha384_ctx_t tmp;

    sha384_init (&tmp);

    sha384_update_swap (&tmp, w, len);

    sha384_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
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
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
    w4[0] = hc_swap32_S (w[16]);
    w4[1] = hc_swap32_S (w[17]);
    w4[2] = hc_swap32_S (w[18]);
    w4[3] = hc_swap32_S (w[19]);
    w5[0] = hc_swap32_S (w[20]);
    w5[1] = hc_swap32_S (w[21]);
    w5[2] = hc_swap32_S (w[22]);
    w5[3] = hc_swap32_S (w[23]);
    w6[0] = hc_swap32_S (w[24]);
    w6[1] = hc_swap32_S (w[25]);
    w6[2] = hc_swap32_S (w[26]);
    w6[3] = hc_swap32_S (w[27]);
    w7[0] = hc_swap32_S (w[28]);
    w7[1] = hc_swap32_S (w[29]);
    w7[2] = hc_swap32_S (w[30]);
    w7[3] = hc_swap32_S (w[31]);
  }

  sha384_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha384_hmac_init_global (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha384_ctx_t tmp;

    sha384_init (&tmp);

    sha384_update_global (&tmp, w, len);

    sha384_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
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
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha384_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha384_hmac_init_global_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha384_ctx_t tmp;

    sha384_init (&tmp);

    sha384_update_global_swap (&tmp, w, len);

    sha384_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
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
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
    w4[0] = hc_swap32_S (w[16]);
    w4[1] = hc_swap32_S (w[17]);
    w4[2] = hc_swap32_S (w[18]);
    w4[3] = hc_swap32_S (w[19]);
    w5[0] = hc_swap32_S (w[20]);
    w5[1] = hc_swap32_S (w[21]);
    w5[2] = hc_swap32_S (w[22]);
    w5[3] = hc_swap32_S (w[23]);
    w6[0] = hc_swap32_S (w[24]);
    w6[1] = hc_swap32_S (w[25]);
    w6[2] = hc_swap32_S (w[26]);
    w6[3] = hc_swap32_S (w[27]);
    w7[0] = hc_swap32_S (w[28]);
    w7[1] = hc_swap32_S (w[29]);
    w7[2] = hc_swap32_S (w[30]);
    w7[3] = hc_swap32_S (w[31]);
  }

  sha384_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha384_hmac_update_128 (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const int len)
{
  sha384_update_128 (&ctx->ipad, w0, w1, w2, w3, w4, w5, w6, w7, len);
}

DECLSPEC void sha384_hmac_update (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha384_update (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha384_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_utf16le (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha384_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_utf16le_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha384_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_global (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha384_update_global (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_global_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha384_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_global_utf16le (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha384_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_update_global_utf16le_swap (PRIVATE_AS sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha384_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_final (PRIVATE_AS sha384_hmac_ctx_t *ctx)
{
  sha384_final (&ctx->ipad);

  ctx->opad.w0[0] = h32_from_64_S (ctx->ipad.h[0]);
  ctx->opad.w0[1] = l32_from_64_S (ctx->ipad.h[0]);
  ctx->opad.w0[2] = h32_from_64_S (ctx->ipad.h[1]);
  ctx->opad.w0[3] = l32_from_64_S (ctx->ipad.h[1]);
  ctx->opad.w1[0] = h32_from_64_S (ctx->ipad.h[2]);
  ctx->opad.w1[1] = l32_from_64_S (ctx->ipad.h[2]);
  ctx->opad.w1[2] = h32_from_64_S (ctx->ipad.h[3]);
  ctx->opad.w1[3] = l32_from_64_S (ctx->ipad.h[3]);
  ctx->opad.w2[0] = h32_from_64_S (ctx->ipad.h[4]);
  ctx->opad.w2[1] = l32_from_64_S (ctx->ipad.h[4]);
  ctx->opad.w2[2] = h32_from_64_S (ctx->ipad.h[5]);
  ctx->opad.w2[3] = l32_from_64_S (ctx->ipad.h[5]);
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;
  ctx->opad.w4[0] = 0;
  ctx->opad.w4[1] = 0;
  ctx->opad.w4[2] = 0;
  ctx->opad.w4[3] = 0;
  ctx->opad.w5[0] = 0;
  ctx->opad.w5[1] = 0;
  ctx->opad.w5[2] = 0;
  ctx->opad.w5[3] = 0;
  ctx->opad.w6[0] = 0;
  ctx->opad.w6[1] = 0;
  ctx->opad.w6[2] = 0;
  ctx->opad.w6[3] = 0;
  ctx->opad.w7[0] = 0;
  ctx->opad.w7[1] = 0;
  ctx->opad.w7[2] = 0;
  ctx->opad.w7[3] = 0;

  ctx->opad.len += 48;

  sha384_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

DECLSPEC void sha384_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS const u32x *w4, PRIVATE_AS const u32x *w5, PRIVATE_AS const u32x *w6, PRIVATE_AS const u32x *w7, PRIVATE_AS u64x *digest)
{
  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = hl32_to_64 (w3[2], w3[3]);
  u64x w8_t = hl32_to_64 (w4[0], w4[1]);
  u64x w9_t = hl32_to_64 (w4[2], w4[3]);
  u64x wa_t = hl32_to_64 (w5[0], w5[1]);
  u64x wb_t = hl32_to_64 (w5[2], w5[3]);
  u64x wc_t = hl32_to_64 (w6[0], w6[1]);
  u64x wd_t = hl32_to_64 (w6[2], w6[3]);
  u64x we_t = hl32_to_64 (w7[0], w7[1]);
  u64x wf_t = hl32_to_64 (w7[2], w7[3]);

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA384_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA384_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA384_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA384_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA384_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA384_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA384_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA384_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA384_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA384_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA384_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA384_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA384_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA384_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA384_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA384_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha384[i +  0]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha384[i +  1]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha384[i +  2]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha384[i +  3]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha384[i +  4]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha384[i +  5]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha384[i +  6]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha384[i +  7]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha384[i +  8]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha384[i +  9]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha384[i + 10]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha384[i + 11]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha384[i + 12]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha384[i + 13]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, c, d, e, f, g, h, a, b, we_t, k_sha384[i + 14]); \
    SHA384_STEP (SHA384_F0o, SHA384_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha384[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  #undef ROUND_EXPAND
  #undef ROUND_STEP

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha384_init_vector (PRIVATE_AS sha384_ctx_vector_t *ctx)
{
  ctx->h[0] = SHA384M_A;
  ctx->h[1] = SHA384M_B;
  ctx->h[2] = SHA384M_C;
  ctx->h[3] = SHA384M_D;
  ctx->h[4] = SHA384M_E;
  ctx->h[5] = SHA384M_F;
  ctx->h[6] = SHA384M_G;
  ctx->h[7] = SHA384M_H;

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

  ctx->len = 0;
}

DECLSPEC void sha384_init_vector_from_scalar (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS sha384_ctx_t *ctx0)
{
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];
  ctx->h[5] = ctx0->h[5];
  ctx->h[6] = ctx0->h[6];
  ctx->h[7] = ctx0->h[7];

  ctx->w0[0] = ctx0->w0[0];
  ctx->w0[1] = ctx0->w0[1];
  ctx->w0[2] = ctx0->w0[2];
  ctx->w0[3] = ctx0->w0[3];
  ctx->w1[0] = ctx0->w1[0];
  ctx->w1[1] = ctx0->w1[1];
  ctx->w1[2] = ctx0->w1[2];
  ctx->w1[3] = ctx0->w1[3];
  ctx->w2[0] = ctx0->w2[0];
  ctx->w2[1] = ctx0->w2[1];
  ctx->w2[2] = ctx0->w2[2];
  ctx->w2[3] = ctx0->w2[3];
  ctx->w3[0] = ctx0->w3[0];
  ctx->w3[1] = ctx0->w3[1];
  ctx->w3[2] = ctx0->w3[2];
  ctx->w3[3] = ctx0->w3[3];
  ctx->w4[0] = ctx0->w4[0];
  ctx->w4[1] = ctx0->w4[1];
  ctx->w4[2] = ctx0->w4[2];
  ctx->w4[3] = ctx0->w4[3];
  ctx->w5[0] = ctx0->w5[0];
  ctx->w5[1] = ctx0->w5[1];
  ctx->w5[2] = ctx0->w5[2];
  ctx->w5[3] = ctx0->w5[3];
  ctx->w6[0] = ctx0->w6[0];
  ctx->w6[1] = ctx0->w6[1];
  ctx->w6[2] = ctx0->w6[2];
  ctx->w6[3] = ctx0->w6[3];
  ctx->w7[0] = ctx0->w7[0];
  ctx->w7[1] = ctx0->w7[1];
  ctx->w7[2] = ctx0->w7[2];
  ctx->w7[3] = ctx0->w7[3];

  ctx->len = ctx0->len;
}

DECLSPEC void sha384_update_vector_128 (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 127;

  ctx->len += len;

  if (pos == 0)
  {
    ctx->w0[0] = w0[0];
    ctx->w0[1] = w0[1];
    ctx->w0[2] = w0[2];
    ctx->w0[3] = w0[3];
    ctx->w1[0] = w1[0];
    ctx->w1[1] = w1[1];
    ctx->w1[2] = w1[2];
    ctx->w1[3] = w1[3];
    ctx->w2[0] = w2[0];
    ctx->w2[1] = w2[1];
    ctx->w2[2] = w2[2];
    ctx->w2[3] = w2[3];
    ctx->w3[0] = w3[0];
    ctx->w3[1] = w3[1];
    ctx->w3[2] = w3[2];
    ctx->w3[3] = w3[3];
    ctx->w4[0] = w4[0];
    ctx->w4[1] = w4[1];
    ctx->w4[2] = w4[2];
    ctx->w4[3] = w4[3];
    ctx->w5[0] = w5[0];
    ctx->w5[1] = w5[1];
    ctx->w5[2] = w5[2];
    ctx->w5[3] = w5[3];
    ctx->w6[0] = w6[0];
    ctx->w6[1] = w6[1];
    ctx->w6[2] = w6[2];
    ctx->w6[3] = w6[3];
    ctx->w7[0] = w7[0];
    ctx->w7[1] = w7[1];
    ctx->w7[2] = w7[2];
    ctx->w7[3] = w7[3];

    if (len == 128)
    {
      sha384_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

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
  }
  else
  {
    if ((pos + len) < 128)
    {
      switch_buffer_by_offset_8x4_be (w0, w1, w2, w3, w4, w5, w6, w7, pos);

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
      u32x c0[4] = { 0 };
      u32x c1[4] = { 0 };
      u32x c2[4] = { 0 };
      u32x c3[4] = { 0 };
      u32x c4[4] = { 0 };
      u32x c5[4] = { 0 };
      u32x c6[4] = { 0 };
      u32x c7[4] = { 0 };

      switch_buffer_by_offset_8x4_carry_be (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

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

      sha384_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

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
}

DECLSPEC void sha384_update_vector (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

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

    sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_vector_swap (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

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

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);
    w4[0] = hc_swap32 (w4[0]);
    w4[1] = hc_swap32 (w4[1]);
    w4[2] = hc_swap32 (w4[2]);
    w4[3] = hc_swap32 (w4[3]);
    w5[0] = hc_swap32 (w5[0]);
    w5[1] = hc_swap32 (w5[1]);
    w5[2] = hc_swap32 (w5[2]);
    w5[3] = hc_swap32 (w5[3]);
    w6[0] = hc_swap32 (w6[0]);
    w6[1] = hc_swap32 (w6[1]);
    w6[2] = hc_swap32 (w6[2]);
    w6[3] = hc_swap32 (w6[3]);
    w7[0] = hc_swap32 (w7[0]);
    w7[1] = hc_swap32 (w7[1]);
    w7[2] = hc_swap32 (w7[2]);
    w7[3] = hc_swap32 (w7[3]);

    sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
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

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);
  w4[0] = hc_swap32 (w4[0]);
  w4[1] = hc_swap32 (w4[1]);
  w4[2] = hc_swap32 (w4[2]);
  w4[3] = hc_swap32 (w4[3]);
  w5[0] = hc_swap32 (w5[0]);
  w5[1] = hc_swap32 (w5[1]);
  w5[2] = hc_swap32 (w5[2]);
  w5[3] = hc_swap32 (w5[3]);
  w6[0] = hc_swap32 (w6[0]);
  w6[1] = hc_swap32 (w6[1]);
  w6[2] = hc_swap32 (w6[2]);
  w6[3] = hc_swap32 (w6[3]);
  w7[0] = hc_swap32 (w7[0]);
  w7[1] = hc_swap32 (w7[1]);
  w7[2] = hc_swap32 (w7[2]);
  w7[3] = hc_swap32 (w7[3]);

  sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha384_update_vector_utf16le (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

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

    make_utf16le (w3, w6, w7);
    make_utf16le (w2, w4, w5);
    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le (w3, w6, w7);
  make_utf16le (w2, w4, w5);
  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_update_vector_utf16le_swap (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

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

    make_utf16le (w3, w6, w7);
    make_utf16le (w2, w4, w5);
    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);
    w4[0] = hc_swap32 (w4[0]);
    w4[1] = hc_swap32 (w4[1]);
    w4[2] = hc_swap32 (w4[2]);
    w4[3] = hc_swap32 (w4[3]);
    w5[0] = hc_swap32 (w5[0]);
    w5[1] = hc_swap32 (w5[1]);
    w5[2] = hc_swap32 (w5[2]);
    w5[3] = hc_swap32 (w5[3]);
    w6[0] = hc_swap32 (w6[0]);
    w6[1] = hc_swap32 (w6[1]);
    w6[2] = hc_swap32 (w6[2]);
    w6[3] = hc_swap32 (w6[3]);
    w7[0] = hc_swap32 (w7[0]);
    w7[1] = hc_swap32 (w7[1]);
    w7[2] = hc_swap32 (w7[2]);
    w7[3] = hc_swap32 (w7[3]);

    sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16le (w3, w6, w7);
  make_utf16le (w2, w4, w5);
  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);
  w4[0] = hc_swap32 (w4[0]);
  w4[1] = hc_swap32 (w4[1]);
  w4[2] = hc_swap32 (w4[2]);
  w4[3] = hc_swap32 (w4[3]);
  w5[0] = hc_swap32 (w5[0]);
  w5[1] = hc_swap32 (w5[1]);
  w5[2] = hc_swap32 (w5[2]);
  w5[3] = hc_swap32 (w5[3]);
  w6[0] = hc_swap32 (w6[0]);
  w6[1] = hc_swap32 (w6[1]);
  w6[2] = hc_swap32 (w6[2]);
  w6[3] = hc_swap32 (w6[3]);
  w7[0] = hc_swap32 (w7[0]);
  w7[1] = hc_swap32 (w7[1]);
  w7[2] = hc_swap32 (w7[2]);
  w7[3] = hc_swap32 (w7[3]);

  sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_update_vector_utf16beN (PRIVATE_AS sha384_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

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

    make_utf16beN (w3, w6, w7);
    make_utf16beN (w2, w4, w5);
    make_utf16beN (w1, w2, w3);
    make_utf16beN (w0, w0, w1);

    sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
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

  make_utf16beN (w3, w6, w7);
  make_utf16beN (w2, w4, w5);
  make_utf16beN (w1, w2, w3);
  make_utf16beN (w0, w0, w1);

  sha384_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha384_final_vector (PRIVATE_AS sha384_ctx_vector_t *ctx)
{
  const int pos = ctx->len & 127;

  append_0x80_8x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sha384_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

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

  sha384_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

// HMAC + Vector

DECLSPEC void sha384_hmac_init_vector_128 (PRIVATE_AS sha384_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS const u32x *w4, PRIVATE_AS const u32x *w5, PRIVATE_AS const u32x *w6, PRIVATE_AS const u32x *w7)
{
  u32x a0[4];
  u32x a1[4];
  u32x a2[4];
  u32x a3[4];
  u32x a4[4];
  u32x a5[4];
  u32x a6[4];
  u32x a7[4];

  // ipad

  a0[0] = w0[0] ^ 0x36363636;
  a0[1] = w0[1] ^ 0x36363636;
  a0[2] = w0[2] ^ 0x36363636;
  a0[3] = w0[3] ^ 0x36363636;
  a1[0] = w1[0] ^ 0x36363636;
  a1[1] = w1[1] ^ 0x36363636;
  a1[2] = w1[2] ^ 0x36363636;
  a1[3] = w1[3] ^ 0x36363636;
  a2[0] = w2[0] ^ 0x36363636;
  a2[1] = w2[1] ^ 0x36363636;
  a2[2] = w2[2] ^ 0x36363636;
  a2[3] = w2[3] ^ 0x36363636;
  a3[0] = w3[0] ^ 0x36363636;
  a3[1] = w3[1] ^ 0x36363636;
  a3[2] = w3[2] ^ 0x36363636;
  a3[3] = w3[3] ^ 0x36363636;
  a4[0] = w4[0] ^ 0x36363636;
  a4[1] = w4[1] ^ 0x36363636;
  a4[2] = w4[2] ^ 0x36363636;
  a4[3] = w4[3] ^ 0x36363636;
  a5[0] = w5[0] ^ 0x36363636;
  a5[1] = w5[1] ^ 0x36363636;
  a5[2] = w5[2] ^ 0x36363636;
  a5[3] = w5[3] ^ 0x36363636;
  a6[0] = w6[0] ^ 0x36363636;
  a6[1] = w6[1] ^ 0x36363636;
  a6[2] = w6[2] ^ 0x36363636;
  a6[3] = w6[3] ^ 0x36363636;
  a7[0] = w7[0] ^ 0x36363636;
  a7[1] = w7[1] ^ 0x36363636;
  a7[2] = w7[2] ^ 0x36363636;
  a7[3] = w7[3] ^ 0x36363636;

  sha384_init_vector (&ctx->ipad);

  sha384_update_vector_128 (&ctx->ipad, a0, a1, a2, a3, a4, a5, a6, a7, 128);

  // opad

  u32x b0[4];
  u32x b1[4];
  u32x b2[4];
  u32x b3[4];
  u32x b4[4];
  u32x b5[4];
  u32x b6[4];
  u32x b7[4];

  b0[0] = w0[0] ^ 0x5c5c5c5c;
  b0[1] = w0[1] ^ 0x5c5c5c5c;
  b0[2] = w0[2] ^ 0x5c5c5c5c;
  b0[3] = w0[3] ^ 0x5c5c5c5c;
  b1[0] = w1[0] ^ 0x5c5c5c5c;
  b1[1] = w1[1] ^ 0x5c5c5c5c;
  b1[2] = w1[2] ^ 0x5c5c5c5c;
  b1[3] = w1[3] ^ 0x5c5c5c5c;
  b2[0] = w2[0] ^ 0x5c5c5c5c;
  b2[1] = w2[1] ^ 0x5c5c5c5c;
  b2[2] = w2[2] ^ 0x5c5c5c5c;
  b2[3] = w2[3] ^ 0x5c5c5c5c;
  b3[0] = w3[0] ^ 0x5c5c5c5c;
  b3[1] = w3[1] ^ 0x5c5c5c5c;
  b3[2] = w3[2] ^ 0x5c5c5c5c;
  b3[3] = w3[3] ^ 0x5c5c5c5c;
  b4[0] = w4[0] ^ 0x5c5c5c5c;
  b4[1] = w4[1] ^ 0x5c5c5c5c;
  b4[2] = w4[2] ^ 0x5c5c5c5c;
  b4[3] = w4[3] ^ 0x5c5c5c5c;
  b5[0] = w5[0] ^ 0x5c5c5c5c;
  b5[1] = w5[1] ^ 0x5c5c5c5c;
  b5[2] = w5[2] ^ 0x5c5c5c5c;
  b5[3] = w5[3] ^ 0x5c5c5c5c;
  b6[0] = w6[0] ^ 0x5c5c5c5c;
  b6[1] = w6[1] ^ 0x5c5c5c5c;
  b6[2] = w6[2] ^ 0x5c5c5c5c;
  b6[3] = w6[3] ^ 0x5c5c5c5c;
  b7[0] = w7[0] ^ 0x5c5c5c5c;
  b7[1] = w7[1] ^ 0x5c5c5c5c;
  b7[2] = w7[2] ^ 0x5c5c5c5c;
  b7[3] = w7[3] ^ 0x5c5c5c5c;

  sha384_init_vector (&ctx->opad);

  sha384_update_vector_128 (&ctx->opad, b0, b1, b2, b3, b4, b5, b6, b7, 128);
}

DECLSPEC void sha384_hmac_init_vector (PRIVATE_AS sha384_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  if (len > 128)
  {
    sha384_ctx_vector_t tmp;

    sha384_init_vector (&tmp);

    sha384_update_vector (&tmp, w, len);

    sha384_final_vector (&tmp);

    w0[0] = h32_from_64 (tmp.h[0]);
    w0[1] = l32_from_64 (tmp.h[0]);
    w0[2] = h32_from_64 (tmp.h[1]);
    w0[3] = l32_from_64 (tmp.h[1]);
    w1[0] = h32_from_64 (tmp.h[2]);
    w1[1] = l32_from_64 (tmp.h[2]);
    w1[2] = h32_from_64 (tmp.h[3]);
    w1[3] = l32_from_64 (tmp.h[3]);
    w2[0] = h32_from_64 (tmp.h[4]);
    w2[1] = l32_from_64 (tmp.h[4]);
    w2[2] = h32_from_64 (tmp.h[5]);
    w2[3] = l32_from_64 (tmp.h[5]);
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
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha384_hmac_init_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha384_hmac_update_vector_128 (PRIVATE_AS sha384_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const int len)
{
  sha384_update_vector_128 (&ctx->ipad, w0, w1, w2, w3, w4, w5, w6, w7, len);
}

DECLSPEC void sha384_hmac_update_vector (PRIVATE_AS sha384_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  sha384_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void sha384_hmac_final_vector (PRIVATE_AS sha384_hmac_ctx_vector_t *ctx)
{
  sha384_final_vector (&ctx->ipad);

  ctx->opad.w0[0] = h32_from_64 (ctx->ipad.h[0]);
  ctx->opad.w0[1] = l32_from_64 (ctx->ipad.h[0]);
  ctx->opad.w0[2] = h32_from_64 (ctx->ipad.h[1]);
  ctx->opad.w0[3] = l32_from_64 (ctx->ipad.h[1]);
  ctx->opad.w1[0] = h32_from_64 (ctx->ipad.h[2]);
  ctx->opad.w1[1] = l32_from_64 (ctx->ipad.h[2]);
  ctx->opad.w1[2] = h32_from_64 (ctx->ipad.h[3]);
  ctx->opad.w1[3] = l32_from_64 (ctx->ipad.h[3]);
  ctx->opad.w2[0] = h32_from_64 (ctx->ipad.h[4]);
  ctx->opad.w2[1] = l32_from_64 (ctx->ipad.h[4]);
  ctx->opad.w2[2] = h32_from_64 (ctx->ipad.h[5]);
  ctx->opad.w2[3] = l32_from_64 (ctx->ipad.h[5]);
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;
  ctx->opad.w4[0] = 0;
  ctx->opad.w4[1] = 0;
  ctx->opad.w4[2] = 0;
  ctx->opad.w4[3] = 0;
  ctx->opad.w5[0] = 0;
  ctx->opad.w5[1] = 0;
  ctx->opad.w5[2] = 0;
  ctx->opad.w5[3] = 0;
  ctx->opad.w6[0] = 0;
  ctx->opad.w6[1] = 0;
  ctx->opad.w6[2] = 0;
  ctx->opad.w6[3] = 0;
  ctx->opad.w7[0] = 0;
  ctx->opad.w7[1] = 0;
  ctx->opad.w7[2] = 0;
  ctx->opad.w7[3] = 0;

  ctx->opad.len += 48;

  sha384_final_vector (&ctx->opad);
}
